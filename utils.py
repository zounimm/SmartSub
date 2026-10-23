#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""

通用工具函数模块

提取公共代码，减少重复

"""

import base64

import re

import socket

from loguru import logger

def decode_base64_safe(content):

    """

    安全地解码 Base64 内容

    Args:

        content: Base64 编码的字符串

    Returns:

        解码后的字符串，失败返回空字符串

    """

    try:

        # 添加 padding

        missing_padding = len(content) % 4

        if missing_padding:

            content += '=' * (4 - missing_padding)

        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')

        return decoded

    except Exception as e:

        logger.debug(f'Base64 解码失败: {e}')

        return ""

def encode_base64(content):

    """

    将内容编码为 Base64

    Args:

        content: 要编码的字符串

    Returns:

        Base64 编码后的字符串

    """

    try:

        return base64.b64encode(content.encode('utf-8')).decode('utf-8')

    except Exception as e:

        logger.error(f'Base64 编码失败: {e}')

        return ""

def is_valid_ip(ip_string):

    """

    检查是否为有效的 IPv4 地址

    Args:

        ip_string: IP 地址字符串

    Returns:

        bool: 是否为有效 IP

    """

    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'

    match = re.match(pattern, ip_string)

    if not match:

        return False

    # 检查每个数字是否在 0-255 范围内

    for num in match.groups():

        if int(num) > 255:

            return False

    return True

def resolve_hostname_to_ip(hostname):

    """

    解析主机名到 IP 地址

    Args:

        hostname: 主机名或域名

    Returns:

        str: IP 地址，失败返回 None

    """

    # 如果已经是 IP，直接返回

    if is_valid_ip(hostname):

        return hostname

    try:

        ip = socket.gethostbyname(hostname)

        return ip

    except socket.gaierror:

        logger.debug(f'DNS 解析失败: {hostname}')

        return None

    except Exception as e:

        logger.debug(f'主机名解析异常: {e}')

        return None

def mask_sensitive_data(data, keywords=None):

    """

    对敏感数据进行脱敏处理

    Args:

        data: 要处理的字符串

        keywords: 敏感关键词列表，默认为常见敏感参数

    Returns:

        str: 脱敏后的字符串

    """

    if not data:

        return ""

    if keywords is None:

        keywords = ['token', 'key', 'uuid', 'access_token', 'secret', 'auth', 'password']

    masked_data = data

    for keyword in keywords:

        # 匹配 ?key=value 或 &key=value

        pattern = f'([?&]{keyword}=)([^&]+)'

        masked_data = re.sub(pattern, r'\1******', masked_data, flags=re.IGNORECASE)

    return masked_data

def extract_protocol_from_url(url):

    """

    从代理节点 URL 中提取协议类型

    Args:

        url: 节点 URL

    Returns:

        str: 协议名称（小写），如果无法识别则返回 None

    """

    if not url or '://' not in url:

        return None

    protocol = url.split('://')[0].lower()

    # 支持的协议列表

    supported_protocols = ['vmess', 'ss', 'trojan', 'vless', 'hysteria2', 'hysteria', 'tuic', 'anytls']

    if protocol in supported_protocols:

        return protocol

    return None

def is_static_resource_url(url, extensions=None):

    """

    判断 URL 是否为静态资源

    Args:

        url: 要检查的 URL

        extensions: 静态资源扩展名列表（可选）

    Returns:

        bool: 是否为静态资源

    """

    if not url:

        return False

    if extensions is None:

        extensions = (

            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.ico', '.svg',

            '.css', '.js', '.woff', '.woff2', '.ttf', '.eot', '.otf',

            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv',

            '.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.dmg', '.exe', '.apk'

        )

    return url.lower().endswith(extensions)

def format_file_size(size_bytes):

    """

    格式化文件大小为人类可读格式

    Args:

        size_bytes: 文件大小（字节）

    Returns:

        str: 格式化后的大小（如 "1.23 MB"）

    """

    for unit in ['B', 'KB', 'MB', 'GB']:

        if size_bytes < 1024.0:

            return f"{size_bytes:.2f} {unit}"

        size_bytes /= 1024.0

    return f"{size_bytes:.2f} TB"

def is_safe_url(url, check_ssrf=True):

    """

    检查 URL 是否安全（SSRF防御 + 敏感信息检测）

    Args:

        url: 要检查的 URL

        check_ssrf: 是否检查 SSRF

    Returns:

        bool: URL 是否安全

    """

    if not url:

        return False

    url_lower = url.lower()

    # 1. SSRF 检测

    if check_ssrf:

        dangerous_hosts = [

            'localhost', '127.0.0.1', '0.0.0.0',

            '::1',  # IPv6 localhost

            '169.254',  # Link-local

            '10.',  # Private network

            '172.16.', '172.17.', '172.18.', '172.19.',  # Private network

            '172.20.', '172.21.', '172.22.', '172.23.',

            '172.24.', '172.25.', '172.26.', '172.27.',

            '172.28.', '172.29.', '172.30.', '172.31.',

            '192.168.',  # Private network

        ]

        for host in dangerous_hosts:

            if host in url_lower:

                logger.warning(f'检测到潜在的 SSRF 风险: {mask_sensitive_data(url)}')

                return False

    # 2. 敏感信息检测

    sensitive_patterns = [

        'glpat-', 'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_',  # GitHub tokens

        'private-token', 'access_token=', 'secret='

    ]

    for pattern in sensitive_patterns:

        if pattern in url_lower:

            logger.warning(f'检测到敏感信息: {mask_sensitive_data(url)[:50]}...')

            return False

    return True

def extract_country_emoji(country_code):

    """

    根据国家代码返回对应的国旗 Emoji

    Args:

        country_code: ISO 3166-1 alpha-2 国家代码（如 US, JP）

    Returns:

        str: 国旗 Emoji

    """

    country_map = {

        'US': '🇺🇸', 'JP': '🇯🇵', 'KR': '🇰🇷', 'HK': '🇭🇰', 'TW': '🇹🇼',

        'SG': '🇸🇬', 'GB': '🇬🇧', 'DE': '🇩🇪', 'CA': '🇨🇦', 'AU': '🇦🇺',

        'FR': '🇫🇷', 'NL': '🇳🇱', 'IN': '🇮🇳', 'TH': '🇹🇭', 'MY': '🇲🇾',

        'RU': '🇷🇺', 'CN': '🇨🇳', 'BR': '🇧🇷', 'AR': '🇦🇷', 'IT': '🇮🇹',

        'ES': '🇪🇸', 'SE': '🇸🇪', 'NO': '🇳🇴', 'FI': '🇫🇮', 'DK': '🇩🇰',

        'UNK': '🌐'

    }

    return country_map.get(country_code.upper(), '🌐')
