"""
平台安全债回归测试:
1. 扫描目标 SSRF 防护 (scanner_service)
2. AI 分析结果页 XSS 防护 (ai/result.html 移除 |safe)
3. Cookie 安全标记 (config.py)
4. debug 开关由配置驱动 (run.py 不再硬编码 debug=True)
"""
import os
from pathlib import Path

from app.config import BaseConfig, DevelopmentConfig, ProductionConfig
from app.services.scanner_service import (
    ScannerService,
    _normalize_scan_target,
    _target_is_ssrf_blocked,
)


# ==================== 1. SSRF 防护 ====================

class TestSSRFProtection:
    """扫描目标 SSRF 防护: 实验室默认允许内网扫描, 云元数据地址(169.254.0.0/16)始终拦截。
    可通过 SCAN_ALLOW_PRIVATE_TARGETS=false 恢复严格拦截模式。"""

    def _with_env(self, key, value):
        saved = os.environ.get(key)
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
        return saved

    def test_normalize_strips_scheme_path_port(self):
        assert _normalize_scan_target('http://192.168.1.1:8080/foo?x=1') == ('192.168.1.1', 8080)
        assert _normalize_scan_target('https://example.com') == ('example.com', None)
        assert _normalize_scan_target('[::1]:9000') == ('::1', 9000)
        assert _normalize_scan_target('10.0.0.5') == ('10.0.0.5', None)
        assert _normalize_scan_target('') == ('', None)

    def test_block_private_by_default(self):
        # 默认 (allow_private=False) 拦截所有内网/回环/链路本地地址
        assert _target_is_ssrf_blocked('127.0.0.1', allow_private=False) is True
        assert _target_is_ssrf_blocked('::1', allow_private=False) is True
        assert _target_is_ssrf_blocked('10.0.0.5', allow_private=False) is True
        assert _target_is_ssrf_blocked('192.168.1.1', allow_private=False) is True
        assert _target_is_ssrf_blocked('172.16.5.5', allow_private=False) is True
        assert _target_is_ssrf_blocked('169.254.169.254', allow_private=False) is True
        # 公网地址放行
        assert _target_is_ssrf_blocked('8.8.8.8', allow_private=False) is False
        assert _target_is_ssrf_blocked('1.1.1.1', allow_private=False) is False

    def test_metadata_always_blocked(self):
        # 即使显式允许内网扫描, 云元数据地址也必须始终拦截
        assert _target_is_ssrf_blocked('169.254.169.254', allow_private=True) is True
        assert _target_is_ssrf_blocked('169.254.169.254:80', allow_private=True) is True
        # 允许内网时, 普通内网地址放行
        assert _target_is_ssrf_blocked('127.0.0.1', allow_private=True) is False
        assert _target_is_ssrf_blocked('192.168.1.1', allow_private=True) is False

    def test_create_task_default_allows_private(self, app, db, test_user):
        """实验室默认模式 (allow_private=True): 内网/VM 目标可正常创建扫描任务。"""
        # 不设置环境变量, 使用默认值 (=true)
        saved = self._with_env('SCAN_ALLOW_PRIVATE_TARGETS', None)
        try:
            with app.app_context():
                svc = ScannerService()
                # 私有地址应放行
                task, error = svc.create_task(test_user.id, '192.168.56.101')
            assert task is not None
            assert error is None
        finally:
            self._with_env('SCAN_ALLOW_PRIVATE_TARGETS', saved)

    def test_create_task_blocks_metadata(self, app, db, test_user):
        """云元数据地址 (169.254.0.0/16) 始终被拦截, 即使在实验室默认模式下。"""
        saved = self._with_env('SCAN_ALLOW_PRIVATE_TARGETS', None)
        try:
            with app.app_context():
                svc = ScannerService()
                task, error = svc.create_task(test_user.id, '169.254.169.254')
            assert task is None
            assert error is not None
            assert '元数据' in error or '拦截' in error
        finally:
            self._with_env('SCAN_ALLOW_PRIVATE_TARGETS', saved)

    def test_create_task_strict_mode_blocks_private(self, app, db, test_user):
        """严格模式 (SCAN_ALLOW_PRIVATE_TARGETS=false): 恢复拦截内网目标。"""
        saved = self._with_env('SCAN_ALLOW_PRIVATE_TARGETS', 'false')
        try:
            with app.app_context():
                svc = ScannerService()
                task, error = svc.create_task(test_user.id, '192.168.1.1')
            assert task is None
            assert error is not None
        finally:
            self._with_env('SCAN_ALLOW_PRIVATE_TARGETS', saved)

    def test_create_task_allows_public(self, app, db, test_user):
        """公网目标在默认模式下应放行 (不触发 SSRF 拦截)。"""
        saved = self._with_env('SCAN_ALLOW_PRIVATE_TARGETS', None)
        try:
            with app.app_context():
                svc = ScannerService()
                task, error = svc.create_task(test_user.id, '8.8.8.8')
            assert task is not None
            assert error is None
        finally:
            self._with_env('SCAN_ALLOW_PRIVATE_TARGETS', saved)


# ==================== 2. AI 结果页 XSS 防护 ====================

class TestAIResultXSS:
    """ai/result.html 不得再使用 |safe 渲染 LLM 输出, 防止存储型 XSS。"""

    def test_template_has_no_safe_filter(self):
        tpl = Path(__file__).resolve().parents[1] / 'app' / 'templates' / 'ai' / 'result.html'
        content = tpl.read_text(encoding='utf-8')
        assert '|safe' not in content, '模板不应再出现 |safe (XSS 风险)'
        assert 'white-space:pre-wrap;' in content or 'white-space:pre-wrap' in content

    def test_rendered_analysis_is_escaped(self, app, db, client, test_user):
        """注入 <script> 的分析内容在页面中应被转义, 不会原样执行。"""
        from app.models.ai_analysis import AIAnalysis
        with app.app_context():
            a = AIAnalysis(
                user_id=test_user.id,
                model='test-model',
                status='completed',
                risk_level='High',
                vulnerability_analysis='<script>alert(1)</script>\n第二行文本',
                possible_attack='<img src=x onerror=alert(2)>',
            )
            db.session.add(a)
            db.session.commit()
            aid = a.id

        # 登录后访问结果页
        client.post('/login', data={'username': 'testuser', 'password': 'test123456'},
                    follow_redirects=True)
        resp = client.get(f'/ai/result/{aid}')
        assert resp.status_code == 200
        body = resp.data
        # 原始脚本标签不应出现
        assert b'<script>alert(1)</script>' not in body
        assert b'<img src=x onerror=alert(2)>' not in body
        # 应被转义为实体
        assert b'&lt;script&gt;alert(1)&lt;/script&gt;' in body
        # 换行在新方案下由 white-space:pre-wrap 处理 (文本原样保留)
        assert '第二行文本'.encode('utf-8') in body


# ==================== 3. Cookie 安全标记 ====================

class TestCookieFlags:
    """会话 Cookie 应配置 HttpOnly / SameSite, Secure 由环境变量控制。"""

    def test_production_cookie_flags(self):
        assert ProductionConfig.SESSION_COOKIE_HTTPONLY is True
        assert ProductionConfig.SESSION_COOKIE_SAMESITE == 'Lax'
        # 生产默认不开 Secure (避免本地 http 无法登录), 由部署方设置环境变量开启
        assert ProductionConfig.SESSION_COOKIE_SECURE is False

    def test_base_config_flags(self):
        assert BaseConfig.SESSION_COOKIE_HTTPONLY is True
        assert BaseConfig.SESSION_COOKIE_SAMESITE == 'Lax'

    def test_secure_env_gated(self):
        # SESSION_COOKIE_SECURE 应受环境变量控制 (模拟生产 https 部署)
        saved = os.environ.get('SESSION_COOKIE_SECURE')
        os.environ['SESSION_COOKIE_SECURE'] = 'true'
        try:
            # 重新加载模块以读取最新环境变量值
            import importlib
            import app.config as cfg
            importlib.reload(cfg)
            assert cfg.BaseConfig.SESSION_COOKIE_SECURE is True
        finally:
            if saved is None:
                os.environ.pop('SESSION_COOKIE_SECURE', None)
            else:
                os.environ['SESSION_COOKIE_SECURE'] = saved
            import importlib
            import app.config as cfg
            importlib.reload(cfg)


# ==================== 4. debug 由配置驱动 ====================

class TestDebugConfig:
    """run.py 不得硬编码 debug=True, debug 应由配置决定。"""

    def test_run_py_not_hardcoded(self):
        run_py = Path(__file__).resolve().parents[1] / 'run.py'
        content = run_py.read_text(encoding='utf-8')
        assert 'debug=True' not in content, 'run.py 不应硬编码 debug=True'
        assert 'app.config.get(' in content

    def test_production_debug_off(self):
        assert ProductionConfig.DEBUG is False

    def test_development_debug_on(self):
        # 开发环境仍可开启 debug, 方便本地排错
        assert DevelopmentConfig.DEBUG is True
