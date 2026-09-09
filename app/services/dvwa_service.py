"""
DVWA关联服务模块
生成DVWA实验访问地址，实现实验平台与DVWA环境逻辑关联
注意: 当前阶段不实现自动登录DVWA，仅生成关联URL

连通性探测说明:
- 仅探测服务端已保存的实验目标地址 (不接受任意用户输入的探测请求)
- 探测结果按目标地址缓存，与首页系统状态卡的探测互相独立
- 探测结果只表示"该地址是否有 HTTP 服务响应"，不代表 DVWA 已登录、
  已安装 Hook 或安全等级已切换；这些仍需在靶场内手动确认
"""

import hashlib
import hmac
import json
import time
from urllib.parse import urlencode, urlparse

import requests
from flask import current_app

# 连通性探测状态常量
STATE_UNCONFIGURED = 'unconfigured'   # 未设置目标地址
STATE_UNREACHABLE = 'unreachable'     # 无法建立连接 (超时/拒绝/DNS失败等)
STATE_HTTP_ERROR = 'http_error'       # 能连接但返回 5xx
STATE_REACHABLE = 'reachable'         # 能连接且返回非 5xx 响应

_PROBE_TIMEOUT = 3
# 按目标地址缓存探测结果: {target: {'time': 时间戳, 'state': ..., 'detail': ...}}
_target_cache = {}

# 漏洞分类 -> 关键事件类型 映射 (用于自动判定实验成功)
# 当 Hook 上报的事件类型与实验关联漏洞所属分类的关键事件一致时, 自动判定成功
# 同时支持英文分类名 (init_vulnerability.py 种子) 与中文分类名 (测试/手动录入)
CATEGORY_EVENT_MAP = {
    'SQL Injection': 'sqli_success',
    'SQL注入': 'sqli_success',
    'XSS': 'xss_success',
    'Command Injection': 'command_injection_success',
    '命令注入': 'command_injection_success',
    'File Upload': 'file_upload_success',
    '文件上传': 'file_upload_success',
    'CSRF': 'csrf_success',
    'Broken Access Control': 'access_control_success',
    '越权访问': 'access_control_success',
    'Insecure Deserialization': 'deserialization_success',
    '不安全反序列化': 'deserialization_success',
    'Security Misconfiguration': 'misconfig_success',
    '安全配置错误': 'misconfig_success',
}


class DVWAService:
    """DVWA关联服务类"""

    @staticmethod
    def generate_dvwa_url(target, token, level='low'):
        """
        生成DVWA实验访问地址
        :param target: DVWA目标基础地址 (如 http://192.168.56.101/dvwa)
        :param token: 实验Token
        :param level: DVWA安全等级
        :return: 完整的DVWA访问URL
        """
        if not target:
            return ''

        # 去除末尾斜杠
        base_url = target.rstrip('/')

        # 构建带实验参数的URL
        params = {
            'experiment_token': token,
            'dvwa_level': level
        }
        return f'{base_url}?{urlencode(params)}'

    @staticmethod
    def get_dvwa_security_url(target, level='low'):
        """
        生成DVWA安全等级设置页面URL
        :param target: DVWA目标地址
        :param level: 安全等级
        :return: DVWA安全设置页面URL
        """
        if not target:
            return ''
        base_url = target.rstrip('/')
        # DVWA安全设置页面路径
        return f'{base_url}/security.php'

    # ==================== Hook 签名与事件映射 ====================

    @staticmethod
    def get_hook_secret():
        """获取 Hook 共享密钥 (从配置读取)"""
        return current_app.config.get('DVWA_HOOK_SECRET', '') if current_app else ''

    @staticmethod
    def sign_payload(payload, secret=None):
        """
        对上报 payload 生成 HMAC-SHA256 签名
        :param payload: 待签名的规范化字符串 (如 experiment_token.event_type.timestamp)
        :param secret: 共享密钥 (缺省从配置读取)
        :return: 十六进制签名
        """
        secret = secret or DVWAService.get_hook_secret()
        if not secret:
            return ''
        return hmac.new(secret.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()

    @staticmethod
    def verify_signature(payload, signature, secret=None):
        """
        校验上报 payload 的 HMAC-SHA256 签名 (恒定时间比较, 防时序攻击)
        :param payload: 待校验的规范化字符串
        :param signature: 上报的签名 (十六进制)
        :param secret: 共享密钥 (缺省从配置读取)
        :return: True/False
        """
        secret = secret or DVWAService.get_hook_secret()
        if not secret or not signature:
            return False
        expected = DVWAService.sign_payload(payload, secret)
        return hmac.compare_digest(expected, signature)

    @staticmethod
    def canonical_payload(experiment_token, event_type, timestamp):
        """
        生成用于签名的规范化字符串
        顺序固定, 防止字段重排导致签名不一致
        """
        return f'{experiment_token}.{event_type}.{timestamp}'

    @staticmethod
    def get_key_event_for_category(category_name):
        """
        根据漏洞分类名获取对应的关键事件类型
        :param category_name: 漏洞分类名 (如 'SQL Injection')
        :return: 事件类型字符串, 无映射返回 None
        """
        if not category_name:
            return None
        return CATEGORY_EVENT_MAP.get(category_name)

    @staticmethod
    def generate_hook_url(target, token, level='low'):
        """
        生成带 Hook 参数的 DVWA 实验访问地址
        与 generate_dvwa_url 一致, 但额外携带 hook 标识, 供 DVWA 端识别并注入上报逻辑
        :param target: DVWA目标基础地址
        :param token: 实验Token
        :param level: DVWA安全等级
        :return: 完整的DVWA访问URL
        """
        if not target:
            return ''
        base_url = target.rstrip('/')
        params = {
            'experiment_token': token,
            'dvwa_level': level,
            'hook': '1',
        }
        return f'{base_url}?{urlencode(params)}'

    @staticmethod
    def validate_target_url(target):
        """
        验证目标地址格式
        :param target: 目标URL
        :return: (True/False, 错误信息)
        """
        if not target:
            return False, '目标地址不能为空'
        if not target.startswith(('http://', 'https://')):
            return False, '目标地址必须以http://或https://开头'
        parsed = urlparse(target)
        if not parsed.hostname:
            return False, '目标地址缺少有效的主机名'
        return True, None

    @staticmethod
    def check_target_connectivity(target, use_cache=True):
        """
        探测实验目标地址的连通性 (仅探测服务端已保存的地址, 按目标缓存)
        :param target: 实验记录中保存的目标地址
        :param use_cache: 是否使用缓存 (测试环境可传 False 强制实时探测)
        :return: {'state': STATE_*, 'detail': 可读文案}
        """
        if not target:
            return {'state': STATE_UNCONFIGURED, 'detail': '未设置目标地址'}

        ttl = current_app.config.get('SYSTEM_STATUS_TTL', 30) if current_app else 30
        now = time.time()
        cached = _target_cache.get(target)
        if use_cache and ttl > 0 and cached and (now - cached['time']) < ttl:
            return {'state': cached['state'], 'detail': cached['detail']}

        result = DVWAService._probe(target)
        if use_cache and ttl > 0:
            _target_cache[target] = {'time': now, **result}
        return result

    @staticmethod
    def _probe(target):
        try:
            # 不跟随跨域重定向, 避免探测结果被重定向到无关地址
            resp = requests.get(target, timeout=_PROBE_TIMEOUT, allow_redirects=False)
        except requests.Timeout:
            return {'state': STATE_UNREACHABLE, 'detail': '连接超时，请检查虚拟机是否开机、网络是否可达'}
        except requests.RequestException:
            return {'state': STATE_UNREACHABLE, 'detail': '无法连接，请检查虚拟机是否开机、地址是否正确'}

        if resp.status_code >= 500:
            return {'state': STATE_HTTP_ERROR, 'detail': f'目标服务返回异常 (HTTP {resp.status_code})'}
        return {'state': STATE_REACHABLE, 'detail': f'目标地址可访问 (HTTP {resp.status_code})'}
