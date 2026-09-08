"""
pytest 测试夹具 (fixtures)
提供 app / client / db / 测试用户 等公共夹具, 所有测试文件自动共享

使用方法:
    在测试函数参数中直接声明夹具名即可, 如:
    def test_login(client, test_user):
        resp = client.post('/login', data={...})
"""

import os

import pytest
from app import create_app
from app.extensions import db as _db
from app.models.user import User
from app.models.vulnerability import Vulnerability, VulnerabilityCategory

# 测试环境视为受控实验环境, 允许扫描内网目标 (127.0.0.1 / 192.168.x 等)。
# 注意: 云元数据地址 (169.254.169.254) 在 scanner_service 中始终拦截, 不受此开关影响。
os.environ.setdefault('SCAN_ALLOW_PRIVATE_TARGETS', 'true')


@pytest.fixture(scope='session')
def app():
    """
    创建测试用 Flask 应用 (session 级别, 整个测试会话只创建一次)
    使用 testing 配置: 内存 SQLite + 关闭 CSRF
    """
    app = create_app('testing')
    yield app


@pytest.fixture(scope='function')
def db(app):
    """
    每个测试函数独立的数据库 (function 级别)
    测试前创建所有表, 测试后清空
    """
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.rollback()
        _db.drop_all()


@pytest.fixture(scope='function')
def client(app, db):
    """Flask 测试客户端 (模拟 HTTP 请求, 无需启动服务器)"""
    return app.test_client()


@pytest.fixture(scope='function')
def test_user(app, db):
    """创建普通测试用户"""
    with app.app_context():
        user = User(username='testuser', role='user')
        user.set_password('test123456')
        db.session.add(user)
        db.session.commit()
        yield user


@pytest.fixture(scope='function')
def admin_user(app, db):
    """创建管理员测试用户"""
    with app.app_context():
        user = User(username='adminuser', role='admin')
        user.set_password('admin123456')
        db.session.add(user)
        db.session.commit()
        yield user


@pytest.fixture(scope='function')
def sample_vulns(app, db):
    """创建示例漏洞数据 (分类 + 漏洞记录)"""
    with app.app_context():
        # 创建分类
        cat_sql = VulnerabilityCategory(name='SQL注入')
        cat_xss = VulnerabilityCategory(name='XSS')
        db.session.add_all([cat_sql, cat_xss])
        db.session.flush()

        # 创建漏洞记录
        vulns = [
            Vulnerability(
                name='SQL注入基础', category_id=cat_sql.id,
                severity='High', cve='CVE-2024-0001',
                description='通过用户输入拼接SQL语句进行攻击',
                attack_method="输入 ' OR 1=1 --", solution='使用参数化查询'
            ),
            Vulnerability(
                name='存储型XSS', category_id=cat_xss.id,
                severity='Medium', cve='CVE-2024-0002',
                description='恶意脚本被存储在服务器端，其他用户访问时执行',
                attack_method='在评论区插入 <script> 标签',
                solution='输出编码和CSP策略'
            ),
            Vulnerability(
                name='反射型XSS', category_id=cat_xss.id,
                severity='Medium',
                description='恶意脚本通过URL参数反射到页面上',
                attack_method='构造含恶意参数的URL', solution='输入验证和输出编码'
            ),
        ]
        db.session.add_all(vulns)
        db.session.commit()
        yield vulns


@pytest.fixture(scope='function')
def seed_data(app, db):
    """
    重新填充种子数据 (RBAC角色/权限 + Prompt场景模板)
    由于 db fixture 每个测试函数都会重建数据库, 而 create_app 中的种子函数只在会话级运行一次,
    因此需要此 fixture 在函数级 DB 创建后重新填充
    """
    with app.app_context():
        from app import _seed_rbac, _seed_prompt_templates
        _seed_rbac()
        _seed_prompt_templates()
    yield


def login_user(client, username, password):
    """辅助函数: 通过测试客户端登录用户"""
    return client.post('/login', data={
        'username': username,
        'password': password
    }, follow_redirects=True)


def logout_user(client):
    """辅助函数: 退出登录"""
    return client.get('/logout', follow_redirects=True)
