#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按日期模板生成链接，并从当天开始逐日回退，直到取到有效节点。"""
import base64
import datetime
import gzip
import html
import re

import requests
from loguru import logger

from clash_parser import clash_yaml_to_links

_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept': '*/*',
}

_LABEL_BASE = '基础域名'
_LABEL_NODES = '节点列表'
_LABEL_FORMATS = '可选格式'
_LABELS = (_LABEL_BASE, _LABEL_NODES, _LABEL_FORMATS)

_FORMAT_TOKENS = {'base64', 'clash', 'quanx', 'urls', 'v2ray', 'sip002'}

_HTTP_URL_RE = re.compile(r'^https?://\S+$')
_REL_PATH_RE = re.compile(r'^[A-Za-z0-9._~@%+\-]+(?:/[A-Za-z0-9._~@%+\-]+)*/?$')


def _plain_lines(text):
    """把 HTML 粗略转成按行文本。"""
    cleaned = re.sub(r'<(script|style)[^>]*>.*?</\1>', ' ', text, flags=re.S | re.I)
    cleaned = re.sub(r'<br\s*/?>', '\n', cleaned, flags=re.I)
    cleaned = re.sub(r'<[^>]+>', '\n', cleaned)
    cleaned = html.unescape(cleaned)
    return [line.strip() for line in cleaned.splitlines() if line.strip()]


def _value_after(lines, start, predicate, limit=8):
    """取标签行之后第一个满足条件的值；标签同一行冒号后的内容优先。"""
    head = lines[start]
    for sep in ('：', ':'):
        if sep in head:
            tail = head.split(sep, 1)[1].strip()
            if predicate(tail):
                return tail
            break
    for candidate in lines[start + 1:start + 1 + limit]:
        if predicate(candidate):
            return candidate
        if any(label in candidate for label in _LABELS):
            break
    return None


def _is_relative_path(value):
    return '://' not in value and '/' in value and bool(_REL_PATH_RE.match(value))


def assemble_subscription_urls(text, preferred_format='base64'):
    """按「基础域名 / 节点列表 / 可选格式」三段式说明拼出订阅链接。

    典型电报消息：
        基础域名(直接点击复制):
        https://sub.example.com/
        节点列表(直接点击复制)：
        paste/abcdef-TG@Channel/
        可选格式(根据代理软件选择一个对应的点击复制):
        clash / base64 / quanx / urls
    """
    if not text:
        return []
    lines = _plain_lines(text)
    urls = []
    seen = set()

    for index, line in enumerate(lines):
        if _LABEL_BASE not in line:
            continue
        base = _value_after(lines, index, lambda value: bool(_HTTP_URL_RE.match(value)))
        if not base:
            continue

        path = None
        formats_at = None
        for cursor in range(index + 1, min(index + 12, len(lines))):
            if path is None and _LABEL_NODES in lines[cursor]:
                path = _value_after(lines, cursor, _is_relative_path)
            elif _LABEL_FORMATS in lines[cursor]:
                formats_at = cursor
                break
        if not path or formats_at is None:
            continue

        offered = {item.lower() for item in lines[formats_at + 1:formats_at + 11]} & _FORMAT_TOKENS
        if not offered:
            continue

        url = f"{base.rstrip('/')}/{path.strip('/')}/{preferred_format}"
        if url not in seen:
            seen.add(url)
            urls.append(url)

    return urls


def format_template(template, day):
    """把 {YYYY}/{YY}/{MM}/{M}/{DD}/{D} 替换成指定日期。"""
    return (template
            .replace('{YYYY}', f'{day.year:04d}')
            .replace('{YY}', f'{day.year % 100:02d}')
            .replace('{MM}', f'{day.month:02d}')
            .replace('{M}', str(day.month))
            .replace('{DD}', f'{day.day:02d}')
            .replace('{D}', str(day.day)))


def today_in(timezone_name=None):
    """返回运行环境的当天日期，可选指定时区。"""
    if not timezone_name:
        return datetime.date.today()
    try:
        from zoneinfo import ZoneInfo
        return datetime.datetime.now(ZoneInfo(timezone_name)).date()
    except Exception as e:
        logger.warning(f'时区 {timezone_name} 不可用({e})，改用本地时间')
        return datetime.date.today()


def _decode_base64(text):
    payload = text.strip()
    payload += '=' * (-len(payload) % 4)
    try:
        return base64.b64decode(payload).decode('utf-8', errors='ignore')
    except Exception:
        return ''


def _extract_nodes(text, node_pattern):
    nodes = set(re.findall(node_pattern, text))
    nodes.update(clash_yaml_to_links(text))
    if not nodes:
        decoded = _decode_base64(text)
        if decoded:
            nodes.update(re.findall(node_pattern, decoded))
            nodes.update(clash_yaml_to_links(decoded))
    return nodes


def _decode_body(response):
    """取原始字节解码，兼容 .gz 文件和常见中文编码。"""
    raw = response.content or b''
    if raw[:2] == b'\x1f\x8b':
        try:
            raw = gzip.decompress(raw)
        except OSError:
            return ''
    for encoding in ('utf-8', 'gbk'):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode('utf-8', errors='ignore')


def _fetch_nodes(url, node_pattern, timeout):
    try:
        response = requests.get(url, headers=_HEADERS, timeout=timeout)
    except requests.RequestException as e:
        logger.warning(f'动态链接请求失败: {url} ({type(e).__name__})')
        return set()
    if response.status_code != 200:
        logger.info(f'动态链接状态码 {response.status_code}: {url}')
        return set()
    text = _decode_body(response)
    if not text.strip():
        logger.info(f'动态链接内容为空: {url}')
        return set()
    return _extract_nodes(text, node_pattern)


def resolve(template, node_pattern, max_days_back=30, timeout=10, today=None):
    """从 today 开始逐日向前回溯，返回 (命中的URL, 节点集合)；全部失败返回 (None, set())。"""
    start = today or today_in()
    for offset in range(max(1, max_days_back + 1)):
        day = start - datetime.timedelta(days=offset)
        url = format_template(template, day)
        nodes = _fetch_nodes(url, node_pattern, timeout)
        if nodes:
            logger.info(f'动态链接命中({day.isoformat()}): {url}')
            return url, nodes
        logger.info(f'动态链接无有效内容，回退一天: {day.isoformat()}')
    return None, set()


def resolve_many(templates, node_pattern, max_days_back=30, timeout=10, today=None):
    """逐个模板独立回溯，返回 (命中的URL列表, 合并后的节点集合)。"""
    start = today or today_in()
    urls = []
    nodes = set()
    for template in templates:
        url, found = resolve(template, node_pattern, max_days_back, timeout, start)
        if url:
            urls.append(url)
            nodes.update(found)
    return urls, nodes
