"""
认证模块测试
覆盖: 注册、登录、退出、输入验证、密码验证
"""

from tests.conftest import login_user, logout_user


class TestRegister:
    """注册功能测试"""

    def test_register_page_loads(self, client):
        """GET /register 返回注册页面"""
        resp = client.get('/register')
        assert resp.status_code == 200
        assert '注册'.encode() in resp.data

    def test_register_success(self, client, db):
        """正常注册后跳转到登录页"""
        resp = client.post('/register', data={
            'username': 'newuser',
            'password': 'pass123456',
            'confirm_password': 'pass123456',
            'email': ''
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert '登录'.encode() in resp.data

    def test_register_duplicate_username(self, client, test_user):
        """重复用户名注册失败"""
        resp = client.post('/register', data={
            'username': 'testuser',  # 与 test_user 重复
            'password': 'pass123456',
            'confirm_password': 'pass123456',
            'email': ''
        }, follow_redirects=True)
        assert '已存在'.encode() in resp.data

    def test_register_short_username(self, client, db):
        """用户名太短 (< 3 字符) 被拒绝"""
        resp = client.post('/register', data={
            'username': 'ab',
            'password': 'pass123456',
            'confirm_password': 'pass123456',
            'email': ''
        }, follow_redirects=True)
        assert '3-64'.encode() in resp.data

    def test_register_short_password(self, client, db):
        """密码太短 (< 6 字符) 被拒绝"""
        resp = client.post('/register', data={
            'username': 'newuser2',
            'password': '123',
            'confirm_password': '123',
            'email': ''
        }, follow_redirects=True)
        assert '6'.encode() in resp.data

    def test_register_password_mismatch(self, client, db):
        """两次密码不一致被拒绝"""
        resp = client.post('/register', data={
            'username': 'newuser3',
            'password': 'pass123456',
            'confirm_password': 'differentpass',
            'email': ''
        }, follow_redirects=True)
        assert '不一致'.encode() in resp.data

    def test_register_empty_fields(self, client, db):
        """空用户名/密码被拒绝"""
        resp = client.post('/register', data={
            'username': '',
            'password': '',
            'confirm_password': '',
            'email': ''
        }, follow_redirects=True)
        assert '不能为空'.encode() in resp.data


class TestLogin:
    """登录功能测试"""

    def test_login_page_loads(self, client):
        """GET /login 返回登录页面"""
        resp = client.get('/login')
        assert resp.status_code == 200
        assert '登录'.encode() in resp.data

    def test_login_success(self, client, test_user):
        """正确密码登录后跳转到首页"""
        resp = login_user(client, 'testuser', 'test123456')
        assert resp.status_code == 200
        assert 'testuser'.encode() in resp.data

    def test_login_wrong_password(self, client, test_user):
        """错误密码登录失败"""
        resp = login_user(client, 'testuser', 'wrongpassword')
        assert '错误'.encode() in resp.data

    def test_login_nonexistent_user(self, client, db):
        """不存在的用户名登录失败"""
        resp = login_user(client, 'ghost', 'pass123456')
        assert '错误'.encode() in resp.data

    def test_login_empty_fields(self, client, test_user):
        """空用户名/密码被拒绝"""
        resp = client.post('/login', data={
            'username': '',
            'password': ''
        }, follow_redirects=True)
        assert '请输入'.encode() in resp.data


class TestLogout:
    """退出登录测试"""

    def test_logout(self, client, test_user):
        """登录后退出, 回到首页"""
        login_user(client, 'testuser', 'test123456')
        resp = logout_user(client)
        assert resp.status_code == 200
        assert '退出登录'.encode() in resp.data


class TestAuthProtection:
    """登录保护测试"""

    def test_scan_requires_login(self, client, db):
        """未登录访问扫描页面被重定向到登录"""
        resp = client.get('/scan')
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

    def test_dashboard_requires_login(self, client, db):
        """未登录访问 Dashboard 被重定向"""
        resp = client.get('/security-dashboard')
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']
