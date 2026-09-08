"""
首页「系统状态」卡测试

覆盖:
- SystemStatusService.get_status() 返回 5 个组件且字段合法
- 单组件 online/offline 切换时 detail 文案正确
- 首页匿名访问能渲染「系统状态」卡及组件名
- 测试环境缓存关闭 (SYSTEM_STATUS_TTL=0)
"""

import pytest

from app.services import system_status_service as svc_mod
from app.services.system_status_service import SystemStatusService, clear_status_cache


def _login(client, username, password):
    return client.post('/login', data={'username': username, 'password': password},
                       follow_redirects=True)


EXPECTED_ORDER = ['dvwa', 'metasploit', 'ai', 'nmap', 'database']
EXPECTED_NAMES = {'dvwa': 'DVWA', 'metasploit': 'Metasploit', 'ai': 'AI 引擎',
                  'nmap': 'Nmap', 'database': '数据库'}


@pytest.fixture(autouse=True)
def _clear_cache():
    clear_status_cache()
    yield
    clear_status_cache()


def test_get_status_returns_five_components(app, db):
    """get_status 必须返回 5 个组件, 顺序与名称符合设计文档"""
    with app.app_context():
        data = SystemStatusService().get_status()
    assert len(data) == 5
    assert [d['key'] for d in data] == EXPECTED_ORDER
    for d in data:
        assert d['name'] == EXPECTED_NAMES[d['key']]
        assert 'detail' in d and d['detail']


def test_status_values_valid(app, db):
    """每个组件 status 只能 online/offline, detail 非空"""
    with app.app_context():
        data = SystemStatusService().get_status()
    for d in data:
        assert d['status'] in ('online', 'offline')
        assert isinstance(d['detail'], str) and d['detail']


def test_component_detail_switches_with_status(app, db, monkeypatch):
    """强制某组件 online/offline, 验证 detail 文案切换正确"""
    with app.app_context():
        monkeypatch.setattr(
            SystemStatusService, '_ai',
            lambda self: self._mk('ai', 'AI 引擎', 'online', 'Ollama Running', 'Unavailable')
        )
        monkeypatch.setattr(
            SystemStatusService, '_nmap',
            lambda self: self._mk('nmap', 'Nmap', 'offline', 'Available', 'Missing')
        )
        data = SystemStatusService().get_status()
        by_key = {d['key']: d for d in data}
        assert by_key['ai']['status'] == 'online'
        assert by_key['ai']['detail'] == 'Ollama Running'
        assert by_key['nmap']['status'] == 'offline'
        assert by_key['nmap']['detail'] == 'Missing'


def test_ai_online_via_api_mode_with_key(app, db, monkeypatch):
    """云端 API 模式且配置了密钥: 即使本地 Ollama 未运行, AI 状态也应在线"""
    with app.app_context():
        # 模拟本地 Ollama 不可用
        monkeypatch.setattr(
            'app.services.system_status_service.OllamaService.is_available',
            staticmethod(lambda: False)
        )
        monkeypatch.setitem(app.config, 'LLM_MODE', 'api')
        monkeypatch.setitem(app.config, 'LLM_API_KEY', 'sk-test-xxxx')
        data = SystemStatusService().get_status()
        ai = next(d for d in data if d['key'] == 'ai')
        assert ai['status'] == 'online'
        assert ai['detail'] == 'API Connected'


def test_ai_offline_when_ollama_down_and_no_key(app, db, monkeypatch):
    """本地 Ollama 不可用 且 (ollama 模式或 api 模式无密钥): AI 状态离线"""
    with app.app_context():
        monkeypatch.setattr(
            'app.services.system_status_service.OllamaService.is_available',
            staticmethod(lambda: False)
        )
        # api 模式但缺密钥
        monkeypatch.setitem(app.config, 'LLM_MODE', 'api')
        monkeypatch.setitem(app.config, 'LLM_API_KEY', '')
        data = SystemStatusService().get_status()
        ai = next(d for d in data if d['key'] == 'ai')
        assert ai['status'] == 'offline'
        assert ai['detail'] == 'Unavailable'


def test_cache_disabled_in_testing(app, db):
    """测试环境 SYSTEM_STATUS_TTL=0, 不命中缓存 (实时探测)"""
    with app.app_context():
        ttl = __import__('flask', fromlist=['current_app']).current_app.config['SYSTEM_STATUS_TTL']
        assert ttl == 0


def test_index_page_renders_status_card(client):
    """首页匿名访问渲染「系统状态」卡与全部组件名; 且同步渲染用占位(不阻塞探测)"""
    resp = client.get('/')
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert '系统运行状态' in body
    for name in EXPECTED_NAMES.values():
        assert name in body
    # 缓存已清空 (autouse fixture), 首页应渲染占位 '探测中…', 而非实时探测结果
    assert '探测中' in body


def test_system_status_api_returns_json(client):
    """/api/system-status 返回 200 + 5 个组件 JSON (供前端异步填充)"""
    resp = client.get('/api/system-status')
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list) and len(data) == 5
    assert {d['key'] for d in data} == set(EXPECTED_ORDER)
    for d in data:
        assert d['status'] in ('online', 'offline', 'unknown')


def test_dvwa_probe_respects_config(app, db, monkeypatch):
    """DVWA 探测读取 DVWA_BASE_URL 配置 (可覆盖)"""
    captured = {}

    def fake_probe(url):
        captured['url'] = url
        return False

    monkeypatch.setattr(svc_mod, '_probe_http', fake_probe)
    with app.app_context():
        app.config['DVWA_BASE_URL'] = 'http://dvwa.example.com'
        SystemStatusService().get_status()
    assert captured.get('url') == 'http://dvwa.example.com'
