#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 Clash / Mihomo 订阅 YAML 里的 proxies 转换成标准分享链接。

只转换流水线当前支持的协议（见 DEFAULT_SCHEMES），其余类型跳过。
"""
import base64
import json
import urllib.parse

import yaml

DEFAULT_SCHEMES = {
    'ss', 'vmess', 'vless', 'trojan', 'hysteria2', 'hysteria', 'tuic', 'anytls',
    'ssr', 'snell', 'socks5', 'socks',
}


def _b64(data):
    return base64.b64encode(data).decode('ascii')


def _b64url(data):
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def _quote(value):
    return urllib.parse.quote(str(value), safe='')


def _join(value):
    if isinstance(value, (list, tuple)):
        return ','.join(str(v) for v in value if v)
    return str(value or '')


def _query(params):
    pairs = [(k, str(v)) for k, v in params if v not in (None, '')]
    if not pairs:
        return ''
    return urllib.parse.urlencode(pairs, quote_via=urllib.parse.quote, safe='')


def _host_port(proxy):
    server = str(proxy.get('server') or '').strip()
    try:
        port = int(proxy.get('port'))
    except (TypeError, ValueError):
        return None
    if not server or not 0 < port < 65536:
        return None
    if ':' in server and not server.startswith('['):
        server = f'[{server}]'
    return server, port


def _name(proxy, server, port):
    name = str(proxy.get('name') or '').strip()
    return name or f'{server}:{port}'


def _transport(proxy):
    """返回 (network, host, path, service_name)。"""
    network = str(proxy.get('network') or '').lower()
    host = path = service = ''

    ws = proxy.get('ws-opts')
    if isinstance(ws, dict):
        path = str(ws.get('path') or '')
        headers = ws.get('headers')
        if isinstance(headers, dict):
            host = str(headers.get('Host') or headers.get('host') or '')

    grpc = proxy.get('grpc-opts')
    if isinstance(grpc, dict):
        service = str(grpc.get('grpc-service-name') or '')

    h2 = proxy.get('h2-opts')
    if isinstance(h2, dict):
        if not path:
            path = str(h2.get('path') or '')
        if not host:
            h2_host = h2.get('host')
            if isinstance(h2_host, list):
                host = str(h2_host[0]) if h2_host else ''
            elif h2_host:
                host = str(h2_host)

    if not network:
        if isinstance(ws, dict):
            network = 'ws'
        elif isinstance(grpc, dict):
            network = 'grpc'
        elif isinstance(h2, dict):
            network = 'h2'
        else:
            network = 'tcp'
    return network, host, path, service


def _convert_ss(proxy, server, port, name):
    method = str(proxy.get('cipher') or '')
    password = str(proxy.get('password') or '')
    if not method:
        return None
    userinfo = _b64url(f'{method}:{password}'.encode('utf-8'))

    suffix = ''
    plugin = str(proxy.get('plugin') or '')
    if plugin:
        parts = [plugin]
        opts = proxy.get('plugin-opts')
        if isinstance(opts, dict):
            mode = opts.get('mode')
            host = opts.get('host')
            if plugin.startswith('obfs'):
                if mode:
                    parts.append(f'obfs={mode}')
                if host:
                    parts.append(f'obfs-host={host}')
            else:
                if mode:
                    parts.append(f'mode={mode}')
                if host:
                    parts.append(f'host={host}')
                if opts.get('path'):
                    parts.append(f'path={opts["path"]}')
                if opts.get('tls'):
                    parts.append('tls')
        suffix = '?plugin=' + _quote(';'.join(parts))

    return f'ss://{userinfo}@{server}:{port}{suffix}#{_quote(name)}'


def _convert_vmess(proxy, server, port, name):
    uuid = str(proxy.get('uuid') or '')
    if not uuid:
        return None
    network, host, path, service = _transport(proxy)
    tls_enabled = bool(proxy.get('tls')) or bool(proxy.get('reality-opts'))
    data = {
        'v': '2',
        'ps': name,
        'add': server.strip('[]'),
        'port': str(port),
        'id': uuid,
        'aid': str(proxy.get('alterId') or 0),
        'scy': str(proxy.get('cipher') or 'auto'),
        'net': network or 'tcp',
        'type': 'none',
        'host': host,
        'path': service or path,
        'tls': 'tls' if tls_enabled else '',
        'sni': str(proxy.get('servername') or ''),
        'alpn': _join(proxy.get('alpn')),
        'fp': str(proxy.get('client-fingerprint') or ''),
    }
    payload = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
    return 'vmess://' + _b64(payload.encode('utf-8'))


def _convert_vless(proxy, server, port, name):
    uuid = str(proxy.get('uuid') or '')
    if not uuid:
        return None
    network, host, path, service = _transport(proxy)
    params = [('encryption', 'none'), ('type', network or 'tcp')]

    reality = proxy.get('reality-opts')
    if isinstance(reality, dict) and reality:
        params.append(('security', 'reality'))
        if reality.get('public-key'):
            params.append(('pbk', reality['public-key']))
        if reality.get('short-id'):
            params.append(('sid', reality['short-id']))
    elif proxy.get('tls'):
        params.append(('security', 'tls'))

    sni = proxy.get('servername') or proxy.get('sni')
    if sni:
        params.append(('sni', sni))
    if proxy.get('client-fingerprint'):
        params.append(('fp', proxy['client-fingerprint']))
    alpn = _join(proxy.get('alpn'))
    if alpn:
        params.append(('alpn', alpn))
    if proxy.get('flow'):
        params.append(('flow', proxy['flow']))
    if host:
        params.append(('host', host))
    if path:
        params.append(('path', path))
    if service:
        params.append(('serviceName', service))
    if proxy.get('skip-cert-verify'):
        params.append(('allowInsecure', '1'))

    return f'vless://{_quote(uuid)}@{server}:{port}?{_query(params)}#{_quote(name)}'


def _convert_trojan(proxy, server, port, name):
    password = str(proxy.get('password') or '')
    if not password:
        return None
    network, host, path, service = _transport(proxy)
    params = []

    sni = proxy.get('sni') or proxy.get('servername')
    if sni:
        params.append(('sni', sni))
    if proxy.get('skip-cert-verify'):
        params.append(('allowInsecure', '1'))
    alpn = _join(proxy.get('alpn'))
    if alpn:
        params.append(('alpn', alpn))
    if network and network != 'tcp':
        params.append(('type', network))
    if host:
        params.append(('host', host))
    if path:
        params.append(('path', path))
    if service:
        params.append(('serviceName', service))

    query = _query(params)
    suffix = f'?{query}' if query else ''
    return f'trojan://{_quote(password)}@{server}:{port}{suffix}#{_quote(name)}'


def _convert_hysteria2(proxy, server, port, name):
    password = str(proxy.get('password') or proxy.get('auth') or '')
    if not password:
        return None
    params = []

    sni = proxy.get('sni') or proxy.get('servername')
    if sni:
        params.append(('sni', sni))
    if proxy.get('skip-cert-verify'):
        params.append(('insecure', '1'))
    alpn = _join(proxy.get('alpn'))
    if alpn:
        params.append(('alpn', alpn))
    if proxy.get('obfs'):
        params.append(('obfs', proxy['obfs']))
        if proxy.get('obfs-password'):
            params.append(('obfs-password', proxy['obfs-password']))

    query = _query(params)
    suffix = f'?{query}' if query else ''
    return f'hysteria2://{_quote(password)}@{server}:{port}/{suffix}#{_quote(name)}'


def _convert_hysteria(proxy, server, port, name):
    params = []

    auth = proxy.get('auth-str') or proxy.get('auth')
    if auth:
        params.append(('auth', auth))
    sni = proxy.get('sni') or proxy.get('servername')
    if sni:
        params.append(('peer', sni))
    if proxy.get('skip-cert-verify'):
        params.append(('insecure', '1'))
    if proxy.get('up'):
        params.append(('upmbps', proxy['up']))
    if proxy.get('down'):
        params.append(('downmbps', proxy['down']))
    alpn = _join(proxy.get('alpn'))
    if alpn:
        params.append(('alpn', alpn))
    if proxy.get('obfs'):
        params.append(('obfs', proxy['obfs']))
    if proxy.get('protocol'):
        params.append(('protocol', proxy['protocol']))

    query = _query(params)
    suffix = f'?{query}' if query else ''
    return f'hysteria://{server}:{port}{suffix}#{_quote(name)}'


def _convert_tuic(proxy, server, port, name):
    uuid = str(proxy.get('uuid') or '')
    if not uuid:
        return None
    password = str(proxy.get('password') or '')
    params = []

    sni = proxy.get('sni') or proxy.get('servername')
    if sni:
        params.append(('sni', sni))
    alpn = _join(proxy.get('alpn'))
    if alpn:
        params.append(('alpn', alpn))
    if proxy.get('congestion-controller'):
        params.append(('congestion_control', proxy['congestion-controller']))
    if proxy.get('udp-relay-mode'):
        params.append(('udp_relay_mode', proxy['udp-relay-mode']))
    if proxy.get('disable-sni'):
        params.append(('disable_sni', '1'))
    if proxy.get('skip-cert-verify'):
        params.append(('allow_insecure', '1'))

    query = _query(params)
    suffix = f'?{query}' if query else ''
    userinfo = f'{_quote(uuid)}:{_quote(password)}'
    return f'tuic://{userinfo}@{server}:{port}{suffix}#{_quote(name)}'


def _convert_anytls(proxy, server, port, name):
    password = str(proxy.get('password') or '')
    if not password:
        return None
    params = []

    sni = proxy.get('sni') or proxy.get('servername')
    if sni:
        params.append(('sni', sni))
    if proxy.get('skip-cert-verify'):
        params.append(('insecure', '1'))
    if proxy.get('client-fingerprint'):
        params.append(('fp', proxy['client-fingerprint']))

    query = _query(params)
    suffix = f'?{query}' if query else ''
    return f'anytls://{_quote(password)}@{server}:{port}{suffix}#{_quote(name)}'


def _convert_ssr(proxy, server, port, name):
    method = str(proxy.get('cipher') or '')
    if not method:
        return None
    password = str(proxy.get('password') or '')
    protocol = str(proxy.get('protocol') or 'origin')
    obfs = str(proxy.get('obfs') or 'plain')

    main = ':'.join([
        server.strip('[]'),
        str(port),
        protocol,
        method,
        obfs,
        _b64url(password.encode('utf-8')),
    ])
    params = [('remarks', _b64url(name.encode('utf-8')))]
    if proxy.get('obfs-param'):
        params.append(('obfsparam', _b64url(str(proxy['obfs-param']).encode('utf-8'))))
    if proxy.get('protocol-param'):
        params.append(('protoparam', _b64url(str(proxy['protocol-param']).encode('utf-8'))))
    query = '&'.join(f'{k}={v}' for k, v in params)

    return 'ssr://' + _b64url(f'{main}/?{query}'.encode('utf-8'))


def _convert_snell(proxy, server, port, name):
    psk = str(proxy.get('psk') or proxy.get('password') or '')
    if not psk:
        return None
    params = []
    if proxy.get('version'):
        params.append(('version', proxy['version']))
    obfs = proxy.get('obfs-opts')
    if isinstance(obfs, dict):
        if obfs.get('mode'):
            params.append(('obfs', obfs['mode']))
        if obfs.get('host'):
            params.append(('obfs-host', obfs['host']))

    query = _query(params)
    suffix = f'?{query}' if query else ''
    return f'snell://{_quote(psk)}@{server}:{port}{suffix}#{_quote(name)}'


def _convert_socks(proxy, server, port, name):
    username = str(proxy.get('username') or '')
    password = str(proxy.get('password') or '')
    userinfo = ''
    if username or password:
        userinfo = f'{_quote(username)}:{_quote(password)}@'
    return f'socks5://{userinfo}{server}:{port}#{_quote(name)}'


_CONVERTERS = {
    'ss': _convert_ss,
    'ssr': _convert_ssr,
    'vmess': _convert_vmess,
    'vless': _convert_vless,
    'trojan': _convert_trojan,
    'hysteria2': _convert_hysteria2,
    'hysteria': _convert_hysteria,
    'tuic': _convert_tuic,
    'anytls': _convert_anytls,
    'snell': _convert_snell,
    'socks5': _convert_socks,
    'socks': _convert_socks,
}


def _convert_proxy(proxy):
    scheme = str(proxy.get('type') or '').strip().lower()
    converter = _CONVERTERS.get(scheme)
    if converter is None:
        return None
    host_port = _host_port(proxy)
    if host_port is None:
        return None
    server, port = host_port
    try:
        return converter(proxy, server, port, _name(proxy, server, port))
    except Exception:
        return None


def clash_yaml_to_links(text, allowed_schemes=DEFAULT_SCHEMES):
    """把 Clash YAML 的 proxies 转成分享链接列表，失败返回 []。"""
    if not text or 'proxies:' not in text:
        return []
    try:
        data = yaml.safe_load(text)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    proxies = data.get('proxies')
    if not isinstance(proxies, list):
        return []

    allowed = {str(s).strip().lower() for s in (allowed_schemes or ())}
    links = []
    seen = set()
    for proxy in proxies:
        if not isinstance(proxy, dict):
            continue
        if str(proxy.get('type') or '').strip().lower() not in allowed:
            continue
        link = _convert_proxy(proxy)
        if link and link not in seen:
            seen.add(link)
            links.append(link)
    return links
