# -*- coding: utf-8 -*-
import re
import os
import yaml
import threading
import base64
import json
import requests
import concurrent.futures
import datetime
import time
import random
from loguru import logger
from tqdm import tqdm
from urllib.parse import quote, urlencode, urlparse
from pre_check import pre_check, get_sub_all
from utils import is_safe_url, mask_sensitive_data
from verify_subscription import verify_subscription_file
from clash_parser import clash_yaml_to_links
from dynamic_source import resolve_many as resolve_dynamic_sources, today_in, assemble_subscription_urls

class SubscriptionCollector:
    def __init__(self):
        # 1. 初始化路径 (使用绝对路径)
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        # 切换工作目录到脚本所在目录，确保 pre_check 等外部模块能正确创建目录
        os.chdir(self.base_dir)
        self.config_path = os.path.join(self.base_dir, 'config.yaml')
        self.blacklist_path = os.path.join(self.base_dir, 'blacklist.txt')
        self.collected_nodes_path = os.path.join(self.base_dir, 'collected_nodes.txt')
        self.failed_log_path = os.path.join(self.base_dir, 'failed_subscriptions.log')
        # 2. 初始化数据容器
        self.new_sub_list = []
        self.new_clash_list = []
        self.new_v2_list = []
        self.play_list = []
        self.airport_list = []
        self.collected_nodes_set = set()
        self.failed_sub_list = []
        self.failed_sub_reasons = {}
        self.low_quality_sub_reasons = {}
        # 3. 质量控制与统计
        self.quality_stats = {
            'total_checked': 0,
            'low_quality': 0,
            'empty_subscription': 0,
            'spam_content': 0
        }
        self.lock = threading.Lock()
        # 4. 正则表达式
        self.re_str = r"https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]"
        # 更全面的节点 URL 正则（兼容 RFC 3986，防止参数截断）
        # 抓取阶段不限制协议：项目不支持的协议也会进入 all_nodes.txt，供外部自行筛选
        self.node_str = r'(?:vmess|vless|trojan-go|trojan|ssr|ss|hysteria2|hy2|hysteria|tuic|anytls|snell|socks5|socks|wireguard|wg|ssh|juicity|mieru|brook)://[-a-zA-Z0-9+/=@#?&._%[\]:~!*();,]+'
        self.check_node_url_str = "https://{}/sub?target={}&url={}&insert=false&config=config%2FACL4SSR.ini"
        # 5. 配置参数 (默认值)
        self.max_workers = 32
        self.content_limit_mb = 3
        self.request_timeout = 15
        self.min_nodes = 3
        self.enable_quality_check = True
        self.check_url_list = []
        # 6. User-Agent 列表 (抗封锁 - 扩展池)
        self.user_agents = [
            # Chrome
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            # Edge
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Edg/124.0.0.0 Safari/537.36",
            # Firefox
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
            # Safari
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
            # Mobile
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
        ]
        # 7. 静态资源后缀 (用于过滤无效链接)
        self.static_extensions = (
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.ico', '.svg', 
            '.css', '.js', '.woff', '.woff2', '.ttf', '.eot', '.otf',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.dmg', '.exe', '.apk'
        )
        # 8. 代理配置 (支持 GitHub Actions 等环境)
        self.proxies = self._get_system_proxies()
        self.list_tg = []
        self.list_subscribe = []
        self.list_web_fuzz = []
        # 动态日期链接源 (由 config.yaml 的 dynamic_source 覆盖)
        self.dynamic_source_config = {}
        # 从电报/网页说明里拼装出的订阅链接
        self.assembled_sub_urls = set()
        # 加载配置
        self.load_config()
    def _extract_github_user(self, url):
        if not url:
            return None
        url_lower = url.lower()
        for marker in ['raw.githubusercontent.com/', 'gist.githubusercontent.com/', 'github.com/']:
            if marker in url_lower:
                tail = url_lower.split(marker, 1)[1]
                user = tail.split('/', 1)[0]
                return user if user else None
        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower()
            if host.endswith('github.com'):
                segments = [s for s in parsed.path.split('/') if s]
                if segments:
                    return segments[0].lower()
        except Exception:
            return None
        return None
    def _dedupe_github_users(self, url_list):
        if not url_list:
            return url_list
        seen_users = set()
        deduped = []
        removed = 0
        for url in url_list:
            user = self._extract_github_user(url)
            if user:
                if user in seen_users:
                    removed += 1
                    continue
                seen_users.add(user)
            deduped.append(url)
        if removed:
            logger.info(f'GitHub 用户去重: 移除 {removed} 条重复订阅链接')
        return deduped
    def _record_failed(self, url, reason):
        if not url:
            return
        if url not in self.failed_sub_reasons:
            self.failed_sub_reasons[url] = reason
            self.failed_sub_list.append(url)
    def _record_low_quality(self, url, reason):
        if not url:
            return
        if url not in self.low_quality_sub_reasons:
            self.low_quality_sub_reasons[url] = reason
    def get_abs_path(self, relative_path):
        """将相对路径转换为基于脚本目录的绝对路径"""
        if os.path.isabs(relative_path):
            return relative_path
        return os.path.join(self.base_dir, relative_path)
    @logger.catch
    def load_config(self):
        if not os.path.exists(self.config_path):
            logger.error(f"Config file not found: {self.config_path}")
            return
        with open(self.config_path, encoding="UTF-8") as f:
            data = yaml.safe_load(f)
        # 读取性能配置
        performance = data.get('performance', {})
        self.max_workers = performance.get('max_workers', 32)
        self.content_limit_mb = performance.get('content_limit_mb', 3)
        self.request_timeout = performance.get('request_timeout', 15)
        # 验证配置参数范围
        try:
            assert 1 <= self.max_workers <= 128, f"max_workers 必须在 1-128 之间，当前: {self.max_workers}"
            assert 1 <= self.content_limit_mb <= 50, f"content_limit_mb 必须在 1-50 之间，当前: {self.content_limit_mb}"
            assert 3 <= self.request_timeout <= 60, f"request_timeout 必须在 3-60 之间，当前: {self.request_timeout}"
        except AssertionError as e:
            logger.error(f"❌ 配置参数错误: {e}")
            raise
        # 读取质量控制配置
        quality = data.get('quality_control', {})
        self.min_nodes = quality.get('min_nodes', 3)
        self.enable_quality_check = quality.get('enable_quality_check', True)
        # 验证质量控制参数
        try:
            assert 1 <= self.min_nodes <= 100, f"min_nodes 必须在 1-100 之间，当前: {self.min_nodes}"
        except AssertionError as e:
            logger.error(f"❌ 配置参数错误: {e}")
            raise
        # 节点级去重池
        self.unique_nodes = set()
        logger.info(f'✅ 性能配置: 线程数={self.max_workers}, 限制={self.content_limit_mb}MB, 超时={self.request_timeout}s')
        logger.info(f'✅ 质量控制: 最少节点={self.min_nodes}, 质检={self.enable_quality_check}')
        # 获取 Telegram 频道
        list_tg_raw = data.get('tgchannel', [])
        self.list_tg = []
        for url in list_tg_raw:
            url = str(url).strip()
            if not url:
                continue
            # 使用正则智能提取频道 ID
            # 匹配: t.me/channel, t.me/s/channel, telegram.me/channel
            # 能够处理末尾斜杠、参数等情况
            match = re.search(r'(?:t\.me|telegram\.me)/(?:s/)?([a-zA-Z0-9_]+)', url, re.IGNORECASE)
            if match:
                channel_id = match.group(1)
                # 排除一些非频道的系统路径
                if channel_id.lower() not in ['s', 'share', 'joinchat', 'addstickers', 'iv']:
                    self.list_tg.append(f'https://t.me/s/{channel_id}')
            elif '/' not in url and '@' not in url:
                # 支持纯频道名: channel_name
                self.list_tg.append(f'https://t.me/s/{url}')
            elif url.startswith('@'):
                # 支持 @channel_name
                self.list_tg.append(f'https://t.me/s/{url[1:]}')
            else:
                logger.warning(f'忽略无法解析的 Telegram 链接: {url}')
        self.list_subscribe = data.get('subscribe', [])
        self.list_web_fuzz = data.get('web_pages', [])
        # 动态日期链接源
        self.dynamic_source_config = data.get('dynamic_source', {}) or {}
        if self.dynamic_source_config.get('enabled'):
            _templates = self.dynamic_source_config.get('templates') or self.dynamic_source_config.get('template') or []
            if isinstance(_templates, str):
                _templates = [_templates]
            logger.info(f'✅ 动态日期链接源已启用: {len(_templates)} 个模板')
        # 获取订阅转换 API
        # 优先读取 subconverter_backends，兼容旧配置 sub_convert_apis
        config_apis = data.get('subconverter_backends') or data.get('sub_convert_apis', [])
        if config_apis:
            self.check_url_list = config_apis
            logger.info(f'已加载 {len(self.check_url_list)} 个订阅转换 API')
        else:
            logger.warning('未配置 subconverter_backends，将使用默认 API')
            # 提供一组内置的默认 API 防止程序出错
            self.check_url_list = ['api.dler.io','sub.xeton.dev','sub.id9.cc','sub.maoxiongnet.com']
    @logger.catch
    def load_sub_yaml(self, path_yaml):
        abs_path = self.get_abs_path(path_yaml)
        if os.path.isfile(abs_path):
            with open(abs_path, encoding="UTF-8") as f:
                dict_url = yaml.safe_load(f)
        else:
            dict_url = {
                "机场订阅": [],
                "clash订阅": [],
                "v2订阅": [],
                "开心玩耍": []
            }
        logger.info(f'读取文件成功: {abs_path}')
        return dict_url
    def get_random_ua(self):
        """随机获取 User-Agent"""
        return random.choice(self.user_agents)
    def browser_headers(self):
        """模拟浏览器的完整请求头，降低被 WAF 拦截的概率"""
        return {
            'User-Agent': self.get_random_ua(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
    def check_ssrf(self, url):
        """简单的 SSRF 防御检测"""
        if not url: return False
        try:
            url_lower = url.lower()
            # 简单判断是否以 localhost 或 127.0.0.1 开头
            if url_lower.startswith(('http://localhost', 'https://localhost', 
                                   'http://127.0.0.1', 'https://127.0.0.1')):
                logger.warning(f'拦截潜在的 SSRF 请求: {mask_sensitive_data(url)}')
                return False
            return True
        except Exception:
            return False
    def _get_system_proxies(self):
        """从环境变量获取代理设置"""
        proxies = {}
        http_proxy = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
        https_proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')
        if http_proxy:
            proxies['http'] = http_proxy
        if https_proxy:
            proxies['https'] = https_proxy
        if proxies:
            logger.info(f'已检测到系统代理设置: {proxies}')
        return proxies if proxies else None
    @logger.catch
    def fetch_urls_from_page(self, url):
        """通用网页抓取函数 (增强抗封锁)"""
        if not self.check_ssrf(url):
            return []
        # 针对 Telegram 频道的优化：不重试，快速跳过
        is_tg_channel = 't.me/s/' in url
        url_list = []
        node_list = []
        data = None
        try:
            headers = self.browser_headers()
            # 发起请求 (启用 stream 模式防止内存溢出)
            resp = requests.get(url, headers=headers, timeout=self.request_timeout, proxies=self.proxies, stream=True)
            # 严格过滤：检测 400 以上的页面直接跳过 (用户指令)
            if resp.status_code >= 400:
                resp.close()
                logger.warning(f'{mask_sensitive_data(url)}\t状态码 {resp.status_code} >= 400，直接跳过')
                return []
            # 正常响应处理
            content_limit = self.content_limit_mb * 1024 * 1024
            content = b""
            try:
                for chunk in resp.iter_content(chunk_size=8192):
                    content += chunk
                    if len(content) > content_limit:
                        logger.warning(f'{mask_sensitive_data(url)}\t超过大小限制({self.content_limit_mb}MB)，截断下载')
                        # 不需要标记为失败，直接使用截断后的内容尝试提取
                        break
            except Exception as e:
                logger.warning(f'{mask_sensitive_data(url)}\t下载中断: {e}')
            resp.close()
            # 尝试解码
            data = content.decode('utf-8', errors='ignore')
        except requests.RequestException as e:
            if not is_tg_channel:
                logger.warning(f'{mask_sensitive_data(url)}\t网络请求失败: {type(e).__name__}')
            return []
        except Exception as e:
            logger.error(f'{mask_sensitive_data(url)}\t处理失败: {type(e).__name__} - {str(e)}')
            return []
        if not data:
            return []
        try:
            # 1. 提取订阅 URL
            all_url_list = re.findall(self.re_str, data)
            filter_string_list = ["//t.me/", "cdn-telegram.org", "w3.org", "google.com", "github.com/site", "github.com/features", "cdn5.telesco.pe"]
            url_list = [item for item in all_url_list if not any(filter_string in item for filter_string in filter_string_list)]
            # 过滤静态资源
            url_list = [item for item in url_list if not item.lower().endswith(self.static_extensions)]
            url_list = list(set(url_list))
            # 过滤敏感链接
            url_list = [u for u in url_list if is_safe_url(u)]
            # 拼装「基础域名 + 相对路径 + 格式」形式的订阅链接
            assembled = [u for u in assemble_subscription_urls(data) if is_safe_url(u)]
            if assembled:
                self.assembled_sub_urls.update(assembled)
                url_list = list(dict.fromkeys(url_list + assembled))
                logger.info(f'{mask_sensitive_data(url)}\t拼装出 {len(assembled)} 个订阅链接')
            # 2. 提取直接节点
            direct_nodes = re.findall(self.node_str, data)
            # Clash / Mihomo YAML 内容转成分享链接
            direct_nodes.extend(clash_yaml_to_links(data))
            if direct_nodes:
                node_list.extend(direct_nodes)
                logger.info(f'{mask_sensitive_data(url)}\t发现 {len(direct_nodes)} 个直接节点')
            if node_list:
                self.collected_nodes_set.update(node_list)
            # 3. 质量控制
            if len(url_list) == 0 and len(node_list) == 0:
                logger.warning(f'{mask_sensitive_data(url)}\t无有效内容')
                return []
            if len(url_list) + len(node_list) < 2:
                logger.warning(f'{mask_sensitive_data(url)}\t内容过少({len(url_list) + len(node_list)} < 2)，已跳过')
                return []
            logger.info(f'{mask_sensitive_data(url)}\t获取成功\t订阅链接:{len(url_list)} 节点链接:{len(node_list)}')
        except Exception as e:
            logger.error(f'{mask_sensitive_data(url)}\t数据解析失败: {type(e).__name__} - {str(e)}')
        return url_list
    def filter_base64(self, text):
        ss = ['ss://', 'ssr://', 'vmess://', 'vless://', 'trojan://', 'trojan-go://',
              'hysteria://', 'hysteria2://', 'hy2://', 'tuic://', 'anytls://',
              'snell://', 'socks://', 'socks5://', 'wireguard://', 'wg://',
              'ssh://', 'juicity://', 'mieru://', 'brook://']
        for i in ss:
            if i in text:
                return True
        return False
    def extract_nodes(self, content):
        """从内容中提取节点链接"""
        nodes = []
        try:
            # 尝试解析 Base64
            decoded_text = ""
            try:
                # 简单的 Base64 探测
                sample_length = min(256, len(content))
                head_text = content[:sample_length].strip()
                if not '://' in head_text and not 'proxies:' in head_text: # 只有不包含协议头才尝试解码
                    missing_padding = len(content) % 4
                    if missing_padding:
                        content += '=' * (4 - missing_padding)
                    decoded_text = base64.b64decode(content).decode('utf-8', errors='ignore')
            except Exception:
                pass
            # 从原始内容提取
            nodes.extend(re.findall(self.node_str, content))
            # 从解码内容提取
            if decoded_text:
                nodes.extend(re.findall(self.node_str, decoded_text))
        except Exception:
            pass
        return list(set(nodes)) # 局部去重
    def count_nodes_in_content(self, content, is_clash=False):
        try:
            if is_clash:
                data = yaml.safe_load(content)
                proxies = data.get('proxies', [])
                return len(proxies)
            else:
                try:
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                    nodes = [line for line in decoded.split('\n') if line.strip() and '://' in line]
                    return len(nodes)
                except Exception:
                    return 0
        except Exception:
            return 0
    def validate_subscription_quality(self, url, content, is_clash=False):
        if not self.enable_quality_check:
            return True
        node_count = self.count_nodes_in_content(content, is_clash)
        if node_count == 0:
            logger.warning(f'{mask_sensitive_data(url)}\t空订阅（0个节点）- 已跳过')
            with self.lock:
                self.quality_stats['empty_subscription'] += 1
            self._record_low_quality(url, 'empty_subscription')
            return False
        if node_count < self.min_nodes:
            logger.warning(f'{mask_sensitive_data(url)}\t节点过少（{node_count} < {self.min_nodes}）- 已跳过')
            with self.lock:
                self.quality_stats['low_quality'] += 1
            self._record_low_quality(url, 'low_nodes')
            return False
        spam_keywords = ['已过期', '请购买', '试用结束', '联系客服', '已到期']
        content_lower = content.lower()
        if any(keyword in content_lower for keyword in spam_keywords):
            logger.warning(f'{mask_sensitive_data(url)}\t检测到垃圾内容 - 已跳过')
            with self.lock:
                self.quality_stats['spam_content'] += 1
            self._record_low_quality(url, 'spam_content')
            return False
        logger.info(f'{mask_sensitive_data(url)}\t质量验证通过（{node_count} 个节点）')
        return True
    @logger.catch
    def sub_check(self, url, bar):
        if not self.check_ssrf(url):
            bar.update(1)
            return
        # 快速过滤静态资源后缀 (二次保险)
        if url.lower().endswith(self.static_extensions):
            bar.update(1)
            return
        # 单次请求，不重试
        try:
            headers = self.browser_headers()
            res = requests.get(url, headers=headers, timeout=self.request_timeout, stream=True, proxies=self.proxies)
            # 严格过滤：检测 400 以上的页面直接跳过 (用户指令)
            if res.status_code >= 400:
                res.close()
                self._record_failed(url, f'http_{res.status_code}')
                logger.warning(f'{mask_sensitive_data(url)}\t状态码 {res.status_code} >= 400，直接跳过')
                bar.update(1)
                return
            if res.status_code == 200:
                header_info_valid = False
                header_play_info = ""
                # Header Check
                # 注意：获取到流量信息后不应直接返回，必须继续执行 Body 下载和节点提取，
                # 这样才能确保该订阅中的节点被解析并加入去重池。
                try:
                    info = res.headers.get('subscription-userinfo')
                    if info:
                        info_num = re.findall(r'\d+', info)
                        if info_num:
                            upload = int(info_num[0])
                            download = int(info_num[1])
                            total = int(info_num[2])
                            unused = (total - upload - download) / 1024 / 1024 / 1024
                            unused_rounded = round(unused, 2)
                            if unused_rounded > 0:
                                header_info_valid = True
                                header_play_info = '可用流量:' + str(unused_rounded) + ' GB                    ' + url
                except Exception:
                    pass
                # Body Check
                content_limit = self.content_limit_mb * 1024 * 1024
                content = b""
                try:
                    for chunk in res.iter_content(chunk_size=8192):
                        content += chunk
                        if len(content) > content_limit:
                            logger.debug(f'{mask_sensitive_data(url)} 超过大小限制，截断下载')
                            break
                    text = content.decode('utf-8', errors='ignore')
                except Exception:
                    res.close()
                    self._record_failed(url, 'download_failed')
                    logger.warning(f'{mask_sensitive_data(url)}\t下载中断 - 已标记为失效')
                    bar.update(1)
                    return
                finally:
                    res.close()
                # 质量控制：内容去重检查 (已废弃文件级 MD5 去重)
                with self.lock:
                    self.quality_stats['total_checked'] += 1
                # 解析节点并加入全局去重池
                nodes = self.extract_nodes(text)
                clash_links = clash_yaml_to_links(text)
                if clash_links:
                    nodes.extend(clash_links)
                if nodes:
                    with self.lock:
                        self.unique_nodes.update(nodes)
                # Clash 判断
                try:
                    if 'proxies:' in text:
                        if clash_links:
                            logger.info(f'{mask_sensitive_data(url)}\tClash 订阅解析出 {len(clash_links)} 个节点')
                        if not self.validate_subscription_quality(url, text, is_clash=True):
                            bar.update(1)
                            return
                        with self.lock:
                            self.new_clash_list.append(url)
                            if header_info_valid:
                                self.new_sub_list.append(url)
                                self.play_list.append(header_play_info)
                        bar.update(1)
                        return
                except Exception:
                    pass
                # V2Ray/Base64 判断
                try:
                    sample_length = min(256, len(text))
                    head_text = text[:sample_length].strip()
                    missing_padding = len(head_text) % 4
                    if missing_padding:
                        head_text += '=' * (4 - missing_padding)
                    decoded_text = base64.b64decode(head_text).decode('utf-8', errors='ignore')
                    if self.filter_base64(decoded_text):
                        if not self.validate_subscription_quality(url, text, is_clash=False):
                            bar.update(1)
                            return
                        with self.lock:
                            self.new_v2_list.append(url)
                            if header_info_valid:
                                self.new_sub_list.append(url)
                                self.play_list.append(header_play_info)
                except Exception:
                    pass
                bar.update(1)
                return
            # 非 200 也非 >= 400 的其他状态 (如 3xx 未跳转)
            res.close()
            self._record_failed(url, f'http_{res.status_code}')
            logger.warning(f'{mask_sensitive_data(url)}\t状态码异常: {res.status_code}')
            bar.update(1)
            return
        except Exception:
            self._record_failed(url, 'request_failed')
            logger.warning(f'{mask_sensitive_data(url)}\t请求失败 - 已标记为失效')
            bar.update(1)
            return
    def start_check_urls(self, url_list):
        logger.info('开始筛选---')
        # 加载自动黑名单
        blacklist_set = set()
        if os.path.exists(self.blacklist_path):
            try:
                with open(self.blacklist_path, 'r', encoding='utf-8') as f:
                    lines = f.read().splitlines()
                # 限制黑名单大小，防止无限膨胀
                blacklist_limit = 50000
                if len(lines) > blacklist_limit:
                    logger.warning(f'黑名单行数 ({len(lines)}) 超过限制 ({blacklist_limit})，执行自动清理...')
                    # 保留最新的 50000 条 (假设是追加写入，末尾为最新)
                    lines = lines[-blacklist_limit:]
                    try:
                        with open(self.blacklist_path, 'w', encoding='utf-8') as f:
                            f.write('\n'.join(lines))
                        logger.info('黑名单清理完成')
                    except Exception as e:
                        logger.error(f'黑名单清理写入失败: {e}')
                blacklist_set = set(line.strip() for line in lines if line.strip())
                logger.info(f'已加载自动黑名单，包含 {len(blacklist_set)} 个失效链接')
            except MemoryError:
                logger.error('加载黑名单时发生 MemoryError，正在重置文件...')
                try:
                    if os.path.exists(self.blacklist_path):
                        backup_path = self.blacklist_path + '.bak'
                        os.rename(self.blacklist_path, backup_path)
                        logger.warning(f'原黑名单已备份至: {backup_path}')
                except Exception as e:
                    logger.error(f'备份黑名单失败: {e}')
                blacklist_set = set()
            except Exception as e:
                logger.warning(f'加载黑名单失败: {e}')
        # 黑名单过滤
        if blacklist_set:
            original_count = len(url_list)
            url_list = [str(url) for url in url_list if str(url) not in blacklist_set]
            filtered_count = original_count - len(url_list)
            if filtered_count > 0:
                logger.info(f'已根据黑名单跳过 {filtered_count} 个 URL')
        bar = tqdm(total=len(url_list), desc='订阅筛选：')
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.sub_check, url, bar) for url in url_list]
            concurrent.futures.wait(futures)
        bar.close()
        logger.info('筛选完成')
    def save_collected_nodes(self):
        if not self.collected_nodes_set:
            return
        # 每轮覆盖：只保留本轮网页抓取到的节点
        all_nodes = {node for node in self.collected_nodes_set if '://' in node and len(node) > 15}
        try:
            with open(self.collected_nodes_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(all_nodes)))
            logger.info(f'已保存 {len(all_nodes)} 个节点到 {self.collected_nodes_path} (覆盖写入)')
        except Exception as e:
            logger.error(f'保存节点文件失败: {e}')
    def sub_update(self, url_list, path_yaml):
        logger.info('开始更新订阅---')
        if len(url_list) == 0:
            logger.info('没有需要更新的数据')
            return 
        # 重置列表
        self.new_sub_list = []
        self.new_clash_list = []
        self.new_v2_list = []
        self.play_list = []
        self.failed_sub_list = []
        self.failed_sub_reasons = {}
        self.low_quality_sub_reasons = {}
        check_url_list = list(dict.fromkeys(url_list))
        check_url_list = self._dedupe_github_users(check_url_list)
        # 写入 _url_check.txt
        abs_path_yaml = self.get_abs_path(path_yaml)
        # url_file = abs_path_yaml.replace('.yaml','_url_check.txt')
        # with open(url_file, 'w', encoding='utf-8') as f:
        #     f.write('\n'.join(str(item) for item in check_url_list))
        self.start_check_urls(check_url_list)
        # 处理失效链接
        if self.failed_sub_list:
            failed_count = len(self.failed_sub_list)
            logger.warning(f'发现 {failed_count} 个失效订阅链接，已自动清理')
            # 日志大小限制和轮转（防止无限增长）
            max_log_size = 1024 * 1024  # 1MB
            if os.path.exists(self.failed_log_path):
                log_size = os.path.getsize(self.failed_log_path)
                if log_size > max_log_size:
                    backup_path = self.failed_log_path + '.old'
                    try:
                        os.rename(self.failed_log_path, backup_path)
                        logger.info(f'日志文件过大 ({log_size/1024/1024:.2f}MB)，已备份到 {backup_path}')
                    except Exception as e:
                        logger.warning(f'日志备份失败: {e}')
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open(self.failed_log_path, 'a', encoding='utf-8') as f:
                f.write(f'\n=== {timestamp} - 失效订阅 ({failed_count} 个) ===\n')
                for failed_url in self.failed_sub_list:
                    reason = self.failed_sub_reasons.get(failed_url, 'unknown')
                    f.write(f'{failed_url}\t{reason}\n')
            try:
                with open(self.blacklist_path, 'a', encoding='utf-8') as f:
                    for failed_url in self.failed_sub_list:
                        f.write(f'{failed_url}\n')
                logger.info(f'已将 {failed_count} 个失效链接加入自动黑名单')
            except Exception as e:
                logger.warning(f'写入黑名单失败: {e}')
        # 更新 YAML
        dict_url = self.load_sub_yaml(path_yaml)
        self.new_sub_list = sorted(list(set(self.new_sub_list)))
        self.new_clash_list = sorted(list(set(self.new_clash_list)))
        self.new_v2_list = sorted(list(set(self.new_v2_list)))
        self.play_list = sorted(list(set(self.play_list)))
        dict_url.update({'机场订阅': self.new_sub_list})
        dict_url.update({'clash订阅': self.new_clash_list})
        dict_url.update({'v2订阅': self.new_v2_list})
        dict_url.update({'开心玩耍': self.play_list})
        with open(abs_path_yaml, 'w', encoding="utf-8") as f:
            yaml.dump(dict_url, f, allow_unicode=True)
        self.save_source_health(path_yaml, check_url_list)
        self.print_quality_report()
    def save_source_health(self, path_yaml, check_url_list):
        if not self.failed_sub_reasons and not self.low_quality_sub_reasons:
            return
        try:
            runtime_dir = os.path.join(self.base_dir, 'runtime')
            os.makedirs(runtime_dir, exist_ok=True)
            output_path = os.path.join(runtime_dir, 'source_health.json')
            payload = {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'target': path_yaml,
                'total_checked': len(check_url_list),
                'failed': [
                    {'url': url, 'reason': reason}
                    for url, reason in self.failed_sub_reasons.items()
                ],
                'low_quality': [
                    {'url': url, 'reason': reason}
                    for url, reason in self.low_quality_sub_reasons.items()
                ]
            }
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f'写入 source_health.json 失败: {e}')
    def print_quality_report(self):
        total = self.quality_stats['total_checked']
        if total == 0: return
        valid_count = len(self.new_sub_list) + len(self.new_clash_list) + len(self.new_v2_list)
        failed_count = len(self.failed_sub_list)
        logger.info('='*60)
        logger.info('📊 订阅抓取统计报告')
        logger.info('='*60)
        logger.info(f'✅ 有效订阅: {valid_count} 个')
        logger.info(f'   - Clash 订阅: {len(self.new_clash_list)} 个')
        logger.info(f'   - V2Ray 订阅: {len(self.new_v2_list)} 个')
        logger.info(f'   - 机场订阅: {len(self.new_sub_list)} 个')
        if self.enable_quality_check:
            logger.info(f'\n🔍 质量控制统计:')
            logger.info(f'   - 检查总数: {total} 个')
            low_quality_total = (self.quality_stats['empty_subscription'] + 
                                self.quality_stats['low_quality'] + 
                                self.quality_stats['spam_content'])
            if low_quality_total > 0:
                logger.info(f'   - 低质量订阅: {low_quality_total} 个')
        if failed_count > 0:
            logger.info(f'\n❌ 失效订阅: {failed_count} 个')
        logger.info('='*60)
    @logger.catch
    def url_check_valid(self, target, url, bar):
        # 注意：这里使用单次请求，不进行重试
        # 这样可以确保遍历所有后端，而不是只重试某一个
        success = False
        url_encode = quote(url, safe='')
        # 遍历所有配置的后端 API
        for api_url in self.check_url_list:
            try:
                check_url_string = self.check_node_url_str.format(api_url, target, url_encode)
                headers = {'User-Agent': self.get_random_ua()}
                # 设置较短的超时时间，加快轮询速度
                res = requests.get(check_url_string, headers=headers, timeout=self.request_timeout, proxies=self.proxies)
                if res.status_code == 200:
                    with self.lock:
                        self.airport_list.append(url)
                    success = True
                    break # 成功则停止轮询
            except requests.RequestException:
                continue # 当前 API 失败，尝试下一个
            except Exception as e:
                logger.debug(f'解析失败: {api_url} - {type(e).__name__}')
                continue
        if not success:
            logger.warning(f'所有节点转换 API 均不可用或检测失败: {mask_sensitive_data(url)[:30]}...')
            # 如果是列表为空导致没有循环，也属于失败
            if not self.check_url_list:
                logger.warning('所有节点转换 API 均不可用，请检查配置文件')
        bar.update(1)
    def write_url_config(self, url_file, url_list, target):
        logger.info('检测订阅节点有效性')
        self.airport_list = []
        bar = tqdm(total=len(url_list), desc='节点检测：')
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.url_check_valid, target, url, bar) for url in url_list]
            concurrent.futures.wait(futures)
        bar.close()
        logger.info('检测订阅节点有效性完成')
        # 读取直接采集的节点
        direct_nodes = []
        if os.path.exists(self.collected_nodes_path):
            with open(self.collected_nodes_path, 'r', encoding='utf-8') as f:
                direct_nodes = f.read().splitlines()
        # 合并所有来源
        final_list = self.airport_list + direct_nodes
        # 过滤：只保留节点URL，移除订阅链接
        nodes_only = []
        for item in final_list:
            item_str = str(item).strip()
            # 保留协议节点，排除http订阅链接
            if '://' in item_str and not item_str.startswith(('http://', 'https://')):
                nodes_only.append(item_str)
        # Base64编码节点列表
        nodes_text = '\n'.join(nodes_only)
        base64_content = base64.b64encode(nodes_text.encode('utf-8')).decode('utf-8')
        # 写入Base64编码的订阅文件（添加文件大小限制）
        output_file = url_file.replace('sub_store', target)
        # 文件大小限制：5MB
        max_file_size = 5 * 1024 * 1024  # 5MB
        content_size = len(base64_content.encode('utf-8'))
        if content_size > max_file_size:
            logger.warning(f'⚠️ {target} 文件过大 ({content_size/1024/1024:.2f}MB > 5MB)，将进行智能裁剪...')
            # 计算需要保留的节点数量
            keep_ratio = max_file_size / content_size
            keep_count = int(len(nodes_only) * keep_ratio * 0.95)  # 保留95%以确保不超限
            # 随机采样保留节点（更公平）
            import random
            nodes_only = random.sample(nodes_only, keep_count)
            nodes_text = '\n'.join(nodes_only)
            base64_content = base64.b64encode(nodes_text.encode('utf-8')).decode('utf-8')
            logger.info(f'📊 已裁剪至 {keep_count} 个节点 ({len(base64_content.encode("utf-8"))/1024/1024:.2f}MB)')
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(base64_content)
        logger.info(f'✅ 已生成 {target} 订阅文件: {len(nodes_only)} 个节点 (Base64编码, {len(base64_content.encode("utf-8"))/1024/1024:.2f}MB)')
    def write_sub_store(self, yaml_file):
        logger.info('写入 sub_store 文件--')
        dict_url = self.load_sub_yaml(yaml_file)
        abs_yaml_file = self.get_abs_path(yaml_file)
        play_list = dict_url['开心玩耍']
        play_url_list = re.findall(self.re_str, str(play_list))
        sub_list = dict_url['机场订阅']
        sub_url_list = re.findall(self.re_str, str(sub_list))
        write_str = "-- play_list --\n\n\n" + '\n'.join(str(item) for item in play_url_list)
        write_str += "\n\n\n-- sub_list --\n\n\n" + '\n'.join(str(item) for item in sub_url_list)
        url_file = abs_yaml_file.replace('.yaml','_sub_store.txt')
        with open(url_file, 'w', encoding='utf-8') as f:
            f.write(write_str)
        self.write_url_config(url_file, play_url_list, 'loon')
        self.write_url_config(url_file, sub_url_list, 'clash')
    def write_merge_files(self):
        """生成合并后的文件"""
        # 1. 汇总所有节点
        final_nodes = list(self.unique_nodes) # 包含从订阅中解析的所有节点
        # 2. 合并直接采集的节点 (虽然 sub_check 已经把订阅里的节点加进去了，但 collected_nodes_set 来自网页爬取)
        final_nodes.extend(list(self.collected_nodes_set))
        # 3. 再次去重并排序
        final_nodes = sorted(list(set(final_nodes)))
        # 4. 写入 sub_merge.txt (节点列表)
        content_merge = '\n'.join(final_nodes)
        path_merge = os.path.join(self.base_dir, 'sub_merge.txt')
        with open(path_merge, 'w', encoding='utf-8') as f:
            f.write(content_merge)
        # 5. 写入 sub/all_nodes.txt (本轮全量节点快照，未筛选，供外部自行测试/筛选)
        all_nodes_path = os.path.join(self.base_dir, 'sub', 'all_nodes.txt')
        os.makedirs(os.path.dirname(all_nodes_path), exist_ok=True)
        with open(all_nodes_path, 'w', encoding='utf-8') as f:
            f.write(content_merge)
        logger.info(f'全量节点已写入 sub/all_nodes.txt ({len(final_nodes)} 个)')
        # 6. 写入 base64 版本
        path_base64 = os.path.join(self.base_dir, 'sub_merge_base64.txt')
        with open(path_base64, 'w', encoding='utf-8') as f:
            f.write(base64.b64encode(content_merge.encode('utf-8')).decode('utf-8'))
        logger.info(f'合并完成: {len(final_nodes)} 个唯一节点已写入 sub_merge.txt')
        # 6. 更新 sub_all.yaml (仍然保留有效的订阅链接作为历史记录)
        # 注意：这里的 new_sub_list 等是在 run() 流程中 populated 的
        # 如果是 merge_sub 调用 sub_update，这些 list 包含了当前有效的所有订阅
        # 我们需要读取 yaml_file, 然后更新它
        pass # write_sub_store 已经负责写入 yaml，这里不需要重复写入 yaml
    def verify_subscription_outputs(self):
        """验证生成的订阅文件格式（Base64 与协议）"""
        files_to_check = [
            os.path.join(self.base_dir, 'sub', 'sub_all_clash.txt'),
            os.path.join(self.base_dir, 'sub', 'sub_all_loon.txt')
        ]
        results = {}
        for filepath in files_to_check:
            results[filepath] = verify_subscription_file(filepath)
        self._append_summary(self._format_verify_summary(results))
        failed = [os.path.basename(path) for path, ok in results.items() if not ok]
        if failed:
            raise RuntimeError(f'订阅文件验证失败: {", ".join(failed)}')
        logger.info('订阅文件验证通过: sub_all_clash.txt, sub_all_loon.txt')
    def _format_verify_summary(self, results):
        lines = [
            "## Subscription Verify",
            "",
            "| File | Status |",
            "| --- | --- |"
        ]
        for path, ok in results.items():
            name = os.path.basename(path)
            status = "✅ Passed" if ok else "❌ Failed"
            lines.append(f"| `{name}` | {status} |")
        lines.append("")
        return "\n".join(lines)
    def _append_summary(self, content):
        summary_path = os.getenv('GITHUB_STEP_SUMMARY')
        if not summary_path:
            return
        try:
            with open(summary_path, 'a', encoding='utf-8') as f:
                f.write(content)
                if not content.endswith("\n"):
                    f.write("\n")
        except Exception as e:
            logger.warning(f'写入 Actions Summary 失败: {e}')
    def get_url_form_yaml(self, yaml_file):
        dict_url = self.load_sub_yaml(yaml_file)
        url_list = []
        for key in ['机场订阅', 'clash订阅', 'v2订阅', '开心玩耍']:
            url_list.extend(dict_url.get(key, []))
        url_list = re.findall(self.re_str, str(url_list))
        return [url for url in url_list if is_safe_url(url)]
    def get_url_form_channel(self):
        logger.info('读取config成功')
        url_list = []
        if self.list_tg:
            logger.info(f'开始抓取 {len(self.list_tg)} 个 Telegram 频道...')
            for channel_url in self.list_tg:
                temp_list = self.fetch_urls_from_page(channel_url)
                if temp_list: url_list.extend(temp_list)
        if self.list_web_fuzz:
            logger.info(f'开始模糊抓取 {len(self.list_web_fuzz)} 个网页...')
            for web_url in self.list_web_fuzz:
                temp_list = self.fetch_urls_from_page(web_url)
                if temp_list: url_list.extend(temp_list)
        if self.list_subscribe:
            logger.info(f'加载 {len(self.list_subscribe)} 个直连订阅源...')
            url_list.extend(self.list_subscribe)
        self.save_collected_nodes()
        return url_list
    def fetch_dynamic_source(self):
        """解析动态日期链接，并把拼装出的订阅链接一起写入 sub/dynamic_url.txt。"""
        cfg = self.dynamic_source_config
        urls = []
        nodes = set()

        if cfg.get('enabled'):
            templates = cfg.get('templates')
            if isinstance(templates, str):
                templates = [templates]
            if not isinstance(templates, list) or not templates:
                # 兼容旧的单个 template 字段
                templates = [cfg['template']] if cfg.get('template') else []
            templates = list(dict.fromkeys(str(t).strip() for t in templates if str(t).strip()))
            if templates:
                max_days_back = int(cfg.get('max_days_back', 30))
                timeout = int(cfg.get('timeout', 10))
                logger.info(f'🔎 解析动态日期链接: {len(templates)} 个模板')
                urls, nodes = resolve_dynamic_sources(
                    templates, self.node_str, max_days_back, timeout, today_in(cfg.get('timezone'))
                )
                if urls:
                    logger.info(f'✅ 动态链接命中 {len(urls)}/{len(templates)} 个 (节点 {len(nodes)} 个)')
                else:
                    logger.warning(f'⚠️ 动态链接连续回退 {max_days_back} 天均无有效节点')

        assembled = sorted(self.assembled_sub_urls)
        if assembled:
            logger.info(f'🔗 拼装出 {len(assembled)} 个订阅链接')
        urls = list(dict.fromkeys(urls + assembled))
        if not urls:
            return

        output_path = self.get_abs_path(cfg.get('output_file', 'sub/dynamic_url.txt'))
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(urls))
        except Exception as e:
            logger.warning(f'写入动态链接文件失败: {e}')

        if nodes:
            with self.lock:
                self.unique_nodes.update(nodes)
    def run(self):
        start_time = time.time()
        try:
            # 1. Update Today's Sub
            url_list = self.get_url_form_channel()
            self.fetch_dynamic_source()
            path_yaml = pre_check() # pre_check returns relative path
            self.sub_update(url_list, path_yaml)
            # 2. Merge Sub
            all_yaml = get_sub_all() # returns relative path
            # pre_check was called above, so path_yaml is valid
            merge_url_list = []
            merge_url_list.extend(self.get_url_form_yaml(all_yaml))
            merge_url_list.extend(self.get_url_form_yaml(path_yaml))
            self.sub_update(merge_url_list, all_yaml)
            self.write_sub_store(all_yaml)
            self.verify_subscription_outputs()
            self.write_merge_files()
            # 3. Notification
            runtime = time.time() - start_time
            runtime_str = f"{int(runtime // 60)}分{int(runtime % 60)}秒"
            try:
                from notification import send_notification, format_notification_message
                stats_data = {
                    'valid_count': len(self.new_sub_list) + len(self.new_clash_list) + len(self.new_v2_list),
                    'clash_count': len(self.new_clash_list),
                    'v2ray_count': len(self.new_v2_list),
                    'airport_count': len(self.new_sub_list),
                    'total_checked': self.quality_stats.get('total_checked', 0),
                    'low_quality_count': (self.quality_stats.get('low_quality', 0) + 
                                         self.quality_stats.get('empty_subscription', 0) + 
                                         self.quality_stats.get('spam_content', 0)),
                    'failed_count': len(self.failed_sub_list),
                    'runtime': runtime_str
                }
                message = format_notification_message(stats_data)
                send_notification(message, "SmartSub 运行成功")
            except Exception as e:
                logger.warning(f'发送通知失败: {e}')
            logger.info('✅ 所有任务执行完成')
        except Exception as e:
            logger.error(f'❌ 运行失败: {e}')
            try:
                from notification import send_notification, format_error_notification
                error_msg = format_error_notification(str(e))
                send_notification(error_msg, "SmartSub 运行失败")
            except:
                pass
            raise
if __name__ == '__main__':
    collector = SubscriptionCollector()
    collector.run()
