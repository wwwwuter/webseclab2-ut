"""
扫描安全护栏模块
在创建扫描任务前统一执行三类防护校验:

1. 速率限制 (Rate Limit): 限制用户单位时间内的任务创建数, 防止刷任务
2. 并发上限 (Concurrency): 限制用户/全局同时运行的任务数, 防止资源耗尽
3. 目标白名单/黑名单 (Target ACL): 限制可扫描的目标范围

所有阈值均可通过环境变量/配置覆盖, 默认值面向实验平台场景 (宽松但防滥用)。
"""

import ipaddress
import re
import socket
from datetime import datetime, timedelta

from app.models.scan import ScanTask


def _normalize_target(raw):
    """
    从用户输入解析出 host, 去除协议头/scheme、路径与查询参数。
    支持 IPv4 / IPv6(含 [::1]:port 形式) / 主机名:port。
    """
    t = (raw or '').strip()
    t = re.sub(r'^(https?|ftp)://', '', t, flags=re.IGNORECASE)
    t = t.split('/')[0].split('?')[0]
    if not t:
        return ''
    # IPv6 形式 [::1]:port
    if t.startswith('['):
        m = re.match(r'^\[(.+?)\](?::\d+)?$', t)
        return m.group(1) if m else t
    # 含冒号: 可能是 host:port 或 IPv6 字面量
    if ':' in t:
        try:
            ipaddress.ip_address(t)  # 纯 IPv6 字面量 (无端口)
            return t
        except ValueError:
            host, _, p = t.rpartition(':')
            if host and p.isdigit():
                return host
    return t


def _resolve_target_ips(host):
    """
    将目标解析为 IP 集合。
    IP 字面量直接返回; 主机名解析全部 A/AAAA 记录。
    """
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    ips = []
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return ips
    for info in infos:
        try:
            ips.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    return ips


def _parse_networks(csv):
    """
    解析逗号分隔的 CIDR / 主机 / IP 列表为网络对象集合。
    非法条目静默跳过, 不影响其余条目。
    """
    networks = []
    for item in (csv or '').split(','):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            try:
                networks.append(ipaddress.ip_network(ipaddress.ip_address(item)))
            except ValueError:
                continue
    return networks


class ScanGuardrails:
    """扫描安全护栏: 在创建任务前校验速率、并发、目标合法性。"""

    def __init__(self, config):
        """
        :param config: Flask 配置对象 (提供 SCAN_* 阈值)
        """
        self.config = config

    # ==================== 速率限制 ====================

    def check_rate_limit(self, user_id):
        """
        检查用户是否超过速率限制。
        统计窗口内 (默认 1 小时) 该用户创建的任务总数。
        :return: (是否通过, 错误信息)
        """
        max_tasks = int(self.config.get('SCAN_RATE_LIMIT_MAX', 10))
        window = int(self.config.get('SCAN_RATE_LIMIT_WINDOW', 3600))
        if max_tasks <= 0:
            return True, None  # 0 表示禁用速率限制

        since = datetime.now() - timedelta(seconds=window)
        count = ScanTask.query.filter(
            ScanTask.user_id == user_id,
            ScanTask.created_time >= since
        ).count()

        if count >= max_tasks:
            return False, f'扫描频率超限: {window // 60} 分钟内最多创建 {max_tasks} 个任务'
        return True, None

    # ==================== 并发上限 ====================

    def check_concurrency(self, user_id):
        """
        检查用户/全局并发运行任务数是否超限。
        仅统计 running 状态 (created 为排队态, 不占用扫描资源)。
        :return: (是否通过, 错误信息)
        """
        max_per_user = int(self.config.get('SCAN_MAX_CONCURRENT_PER_USER', 2))
        if max_per_user > 0:
            running = ScanTask.query.filter(
                ScanTask.user_id == user_id,
                ScanTask.status == ScanTask.STATUS_RUNNING
            ).count()
            if running >= max_per_user:
                return False, f'并发扫描超限: 同时最多运行 {max_per_user} 个任务'

        max_global = int(self.config.get('SCAN_MAX_CONCURRENT_GLOBAL', 5))
        if max_global > 0:
            global_running = ScanTask.query.filter(
                ScanTask.status == ScanTask.STATUS_RUNNING
            ).count()
            if global_running >= max_global:
                return False, '系统并发扫描已满，请稍后再试'
        return True, None

    # ==================== 目标白名单/黑名单 ====================

    def check_target(self, raw_target):
        """
        检查目标是否命中黑名单 / 是否在白名单内。
        黑名单优先; 白名单为空时表示不启用白名单限制。
        :return: (是否通过, 错误信息)
        """
        host = _normalize_target(raw_target)
        if not host:
            return True, None
        ips = _resolve_target_ips(host)
        if not ips:
            # 无法解析: 不在此拦截, 交由扫描阶段正常报错
            return True, None

        # 黑名单: 任一解析 IP 命中即拦截
        blacklist = _parse_networks(self.config.get('SCAN_TARGET_BLACKLIST', ''))
        for ip in ips:
            for net in blacklist:
                if ip in net:
                    return False, f'目标 {host} 命中黑名单 {net}，已被拦截'

        # 白名单: 启用时, 所有解析 IP 均需命中白名单
        whitelist = _parse_networks(self.config.get('SCAN_TARGET_WHITELIST', ''))
        if whitelist:
            if not any(ip in net for ip in ips for net in whitelist):
                return False, f'目标 {host} 不在允许扫描的白名单内'
        return True, None

    # ==================== 统一入口 ====================

    def check_all(self, user_id, raw_target):
        """
        依次执行全部护栏校验 (速率 → 并发 → 目标)。
        :return: (是否通过, 错误信息)
        """
        ok, error = self.check_rate_limit(user_id)
        if not ok:
            return False, error
        ok, error = self.check_concurrency(user_id)
        if not ok:
            return False, error
        ok, error = self.check_target(raw_target)
        if not ok:
            return False, error
        return True, None
