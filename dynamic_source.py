#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按日期模板生成链接，并从当天开始逐日回退，直到取到有效节点。"""
import base64
import datetime
import gzip
import re

import requests
from loguru import logger

from clash_parser import clash_yaml_to_links

_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept': '*/*',
}


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
