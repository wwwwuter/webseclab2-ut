"""
系统状态探测服务
为首页「系统状态」卡片提供各组件的真实连通性探测结果。

探测的组件 (按设计文档顺序):
- DVWA:        HTTP 探活 (可配置 DVWA_BASE_URL)
- Metasploit:  TCP 探活 (可配置 METASPLOIT_RPC_HOST/PORT, 平台未直接集成, 仅测连通性)
- AI 引擎:     AI 分析能力就绪判定 —— 本地 Ollama 可达 (LLM_MODE=ollama) 或
              云端 API 已配置密钥 (LLM_MODE=api 且 LLM_API_KEY 非空) 任一满足即在线
- Nmap:        NmapScanner.is_available() (扫描器二进制是否可用)
- 数据库:      SQLAlchemy 探活 (SELECT 1)

结果带 TTL 缓存, 避免高频页面加载反复发起探测拖慢首页。
"""

import socket
import time

import requests
from flask import current_app
from sqlalchemy import text

from app.extensions import db
from app.services.nmap_service import NmapScanner
from app.services.ollama_service import OllamaService

# 模块级缓存: {time: 时间戳, data: 上次探测结果}
_cache = {'time': 0.0, 'data': None}

# 探测超时 (秒) — 控制首页不卡顿; 配合 30s 缓存, 仅首次加载触发探测
_PROBE_TIMEOUT = 2


def _probe_http(url):
    """HTTP 连通性探测: 能建立连接并拿到任意 HTTP 响应即视为在线"""
    try:
        resp = requests.get(url, timeout=_PROBE_TIMEOUT)
        # 任意 2xx/3xx/4xx 都表示服务在响应 (5xx 也说明服务活着只是异常)
        return resp.status_code < 600
    except (requests.RequestException, ValueError):
        return False


def _probe_tcp(host, port):
    """TCP 连通性探测: 能建立 socket 连接即视为在线"""
    try:
        with socket.create_connection((host, port), timeout=_PROBE_TIMEOUT):
            return True
    except (OSError, socket.timeout):
        return False


class SystemStatusService:
    """系统状态探测服务"""

    def get_status(self, use_cache=None):
        """
        返回各组件状态列表。

        :param use_cache: 是否使用缓存; 默认读取 SYSTEM_STATUS_TTL 配置
                          (TTL>0 用缓存, TTL=0 强制实时探测, 测试环境即如此)
        :return: [{'key','name','status','detail'}, ...]
                 status ∈ {'online','offline'}
                 detail 随状态切换为对应的可读文案
        """
        ttl = current_app.config.get('SYSTEM_STATUS_TTL', 30) if current_app else 30
        now = time.time()
        if use_cache is None:
            use_cache = ttl > 0

        if use_cache and _cache['data'] and (now - _cache['time']) < ttl:
            return _cache['data']

        data = self._build()

        if use_cache:
            _cache['time'] = now
            _cache['data'] = data
        return data

    def get_status_safe(self):
        """
        供首页同步渲染: 仅用缓存, **绝不触发实时探测**, 保证首页瞬时返回。

        - 缓存命中 (TTL 内) -> 返回上次的真实状态 (瞬时)
        - 缓存为空/过期且未触发过 -> 返回占位列表 (status='unknown', detail='探测中…')
          真实状态由前端 JS 异步调用 /api/system-status 补齐

        与 get_status() 的区别: 本方法在缓存未命中时**不发起网络探测**,
        因此不会阻塞首页请求处理。
        """
        ttl = current_app.config.get('SYSTEM_STATUS_TTL', 30) if current_app else 30
        if ttl > 0 and _cache['data'] and (time.time() - _cache['time']) < ttl:
            return _cache['data']
        # 无可用缓存: 返回占位, 不探测
        placeholder = [
            ('dvwa', 'DVWA'), ('metasploit', 'Metasploit'), ('ai', 'AI 引擎'),
            ('nmap', 'Nmap'), ('database', '数据库'),
        ]
        return [self._mk(key, name, 'unknown', '探测中…', '探测中…')
                for key, name in placeholder]

    def _cfg(self, key, default):
        """安全读取配置, 无 app context 时回退默认"""
        if current_app:
            return current_app.config.get(key, default)
        return default

    def _build(self):
        return [
            self._dvwa(),
            self._metasploit(),
            self._ai(),
            self._nmap(),
            self._database(),
        ]

    # ==================== 各组件探测 ====================

    def _database(self):
        try:
            db.session.execute(text('SELECT 1'))
            return self._mk('database', '数据库', 'online', 'Connected', 'Error')
        except Exception:
            return self._mk('database', '数据库', 'offline', 'Connected', 'Error')

    def _ai(self):
        """
        AI 分析能力就绪判定。

        平台 AI 分两种后端:
        - LLM_MODE=ollama: 依赖本地 Ollama 服务
        - LLM_MODE=api:    依赖云端 API (DeepSeek/DashScope/OpenAI), 需配置密钥

        只要其一连通即视为可用 (绿灯):
        - 本地 Ollama 可达  -> 'Ollama Running'
        - API 模式且已配置密钥 -> 'API Connected'
        - 两者皆可用        -> 'Ready'
        都不通 -> 'Unavailable' (红)
        """
        mode = self._cfg('LLM_MODE', 'ollama')
        ollama_ok = False
        try:
            ollama_ok = OllamaService().is_available()
        except Exception:
            ollama_ok = False
        # 云端 API 模式: 配了密钥即认为可用 (真实连通性由调用时保证)
        api_ok = bool(mode == 'api' and self._cfg('LLM_API_KEY', ''))

        available = ollama_ok or api_ok
        if available:
            if ollama_ok and api_ok:
                detail = 'Ready'
            elif ollama_ok:
                detail = 'Ollama Running'
            else:
                detail = 'API Connected'
        else:
            detail = 'Unavailable'
        return self._mk('ai', 'AI 引擎', 'online' if available else 'offline',
                        detail, detail)

    def _nmap(self):
        ok = False
        try:
            ok = NmapScanner().is_available()
        except Exception:
            ok = False
        return self._mk('nmap', 'Nmap', 'online' if ok else 'offline',
                        'Available', 'Missing')

    def _dvwa(self):
        url = self._cfg('DVWA_BASE_URL', 'http://localhost/dvwa')
        ok = _probe_http(url)
        return self._mk('dvwa', 'DVWA', 'online' if ok else 'offline',
                        'Online', 'Offline')

    def _metasploit(self):
        host = self._cfg('METASPLOIT_RPC_HOST', '127.0.0.1')
        port = self._cfg('METASPLOIT_RPC_PORT', 55553)
        ok = _probe_tcp(host, int(port))
        return self._mk('metasploit', 'Metasploit', 'online' if ok else 'offline',
                        'Connected', 'Disconnected')

    @staticmethod
    def _mk(key, name, status, online_text, offline_text):
        return {
            'key': key,
            'name': name,
            'status': status,
            'detail': online_text if status == 'online' else offline_text,
        }


def clear_status_cache():
    """清空系统状态缓存 (测试/调试用)"""
    _cache['time'] = 0.0
    _cache['data'] = None
