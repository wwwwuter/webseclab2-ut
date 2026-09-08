"""
个人中心 (Profile) 测试
覆盖：访问权限 / 资料页渲染 / 编辑页渲染 / 修改资料API / 改密码API / 头像上传API
"""
import base64

import pytest


def _login(client, username, password):
    return client.post('/login', data={'username': username, 'password': password},
                       follow_redirects=True)


def _make_png():
    # 1x1 透明 PNG
    return base64.b64decode(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=='
    )


def test_profile_requires_login(client):
    """未登录访问 /profile 应重定向到登录页"""
    resp = client.get('/profile')
    assert resp.status_code == 302
    assert '/login' in resp.headers['Location']


def test_profile_page_renders(client, test_user):
    """登录后 /profile 渲染：含模块标题与统计卡"""
    _login(client, 'testuser', 'test123456')
    resp = client.get('/profile')
    assert resp.status_code == 200
    text = resp.get_data(as_text=True)
    assert '个人中心' in text
    assert '我的数据' in text
    assert '最近登录' in text
    assert '账号管理' in text


def test_profile_edit_page_renders(client, test_user):
    """登录后 /profile/edit 渲染：含保存按钮与头像上传"""
    _login(client, 'testuser', 'test123456')
    resp = client.get('/profile/edit')
    assert resp.status_code == 200
    text = resp.get_data(as_text=True)
    assert '保存修改' in text
    assert '修改密码' in text


def test_update_api(client, test_user, app):
    """修改昵称 + 邮箱：返回成功并落库"""
    _login(client, 'testuser', 'test123456')
    resp = client.post('/profile/api/update',
                       json={'nickname': '安全小白', 'email': 'new@example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    with app.app_context():
        from app.models.user import User
        u = User.query.filter_by(username='testuser').first()
        assert u.nickname == '安全小白'
        assert u.email == 'new@example.com'


def test_update_api_rejects_bad_email(client, test_user):
    """邮箱格式非法时应拒绝"""
    _login(client, 'testuser', 'test123456')
    resp = client.post('/profile/api/update',
                       json={'nickname': 'x', 'email': 'not-an-email'})
    data = resp.get_json()
    assert data['ok'] is False


def test_change_password_api(client, test_user, app):
    """改密码：当前密码错误应拒绝；正确则应成功且新密码生效"""
    _login(client, 'testuser', 'test123456')
    # 错误当前密码
    r1 = client.post('/profile/api/change-password',
                     json={'current': 'wrong', 'new': 'abc12345', 'confirm': 'abc12345'})
    assert r1.get_json()['ok'] is False
    # 二次不一致
    r2 = client.post('/profile/api/change-password',
                     json={'current': 'test123456', 'new': 'abc12345', 'confirm': 'diff1234'})
    assert r2.get_json()['ok'] is False
    # 正确
    r3 = client.post('/profile/api/change-password',
                     json={'current': 'test123456', 'new': 'abc12345', 'confirm': 'abc12345'})
    assert r3.get_json()['ok'] is True
    with app.app_context():
        from app.models.user import User
        u = User.query.filter_by(username='testuser').first()
        assert u.check_password('abc12345')


def test_avatar_api(client, test_user):
    """头像上传：PNG ≤2MB 应成功；非法类型应拒绝"""
    import io
    _login(client, 'testuser', 'test123456')
    png = _make_png()
    resp = client.post('/profile/api/avatar', data={
        'avatar': (io.BytesIO(png), 'avatar.png')
    }, content_type='multipart/form-data')
    assert resp.status_code == 200
    assert resp.get_json()['ok'] is True
    # 非法类型
    bad = client.post('/profile/api/avatar', data={
        'avatar': (io.BytesIO(b'notimage'), 'avatar.gif')
    }, content_type='multipart/form-data')
    assert bad.get_json()['ok'] is False
