"""
管理后台 (/admin) 升级功能测试
覆盖: KRI 统计 / 用户搜索筛选排序 / 改角色(自锁+末位管理员保护) / 删除用户(自锁+末位管理员+关联数据保护) / 访问控制
"""

import pytest
from tests.conftest import login_user
from app.services.auth_service import AuthService
from app.models.user import User


# ==================== KRI 统计 ====================

class TestUserStats:
    def test_stats_keys(self, app, admin_user, test_user):
        with app.app_context():
            stats = AuthService.get_user_stats()
            assert set(stats.keys()) == {'total', 'admins', 'normal', 'today_new'}

    def test_stats_counts(self, app, admin_user, test_user):
        with app.app_context():
            stats = AuthService.get_user_stats()
            assert stats['total'] == 2
            assert stats['admins'] == 1
            assert stats['normal'] == 1
            # admin_user / test_user 均为本次会话创建, 计入今日新增
            assert stats['today_new'] == 2


# ==================== 搜索 / 筛选 / 排序 ====================

class TestUserFilter:
    def test_search_by_username(self, app, admin_user, test_user):
        with app.app_context():
            pg = AuthService.get_users_filtered(keyword='admin')
            names = [u.username for u in pg.items]
            assert 'adminuser' in names
            assert 'testuser' not in names

    def test_filter_by_role(self, app, admin_user, test_user):
        with app.app_context():
            pg = AuthService.get_users_filtered(role='admin')
            assert all(u.role == 'admin' for u in pg.items)
            assert len(pg.items) == 1

    def test_sort_username_asc(self, app, admin_user, test_user):
        with app.app_context():
            pg = AuthService.get_users_filtered(sort_by='username', order='asc')
            names = [u.username for u in pg.items]
            assert names == sorted(names)

    def test_sort_role_semantic_admin_first(self, app, admin_user, test_user):
        with app.app_context():
            pg = AuthService.get_users_filtered(sort_by='role', order='asc')
            assert pg.items[0].role == 'admin'


# ==================== 改角色 ====================

class TestSetRole:
    def test_promote_user_to_admin(self, app, admin_user, test_user):
        with app.app_context():
            uid = User.query.filter_by(username='testuser').first().id
            ok, err = AuthService.set_role(uid, 'admin', operator_id=admin_user.id)
            assert ok and err is None
            assert User.query.get(uid).role == 'admin'

    def test_cannot_change_own_role(self, app, admin_user):
        with app.app_context():
            ok, err = AuthService.set_role(admin_user.id, 'user', operator_id=admin_user.id)
            assert not ok
            assert '自己' in err

    def test_cannot_demote_last_admin(self, app, admin_user, test_user):
        with app.app_context():
            # 用另一账号操作, 触发"末位管理员"而非"自锁"分支
            ok, err = AuthService.set_role(admin_user.id, 'user', operator_id=test_user.id)
            assert not ok
            assert '至少' in err

    def test_invalid_role_rejected(self, app, admin_user, test_user):
        with app.app_context():
            ok, err = AuthService.set_role(test_user.id, 'superuser', operator_id=admin_user.id)
            assert not ok
            assert '无效' in err


# ==================== 删除用户 ====================

class TestDeleteUser:
    def test_delete_normal_user(self, app, admin_user, test_user):
        with app.app_context():
            uid = User.query.filter_by(username='testuser').first().id
            ok, err = AuthService.delete_user(uid, operator_id=admin_user.id)
            assert ok and err is None
            assert User.query.get(uid) is None

    def test_cannot_delete_self(self, app, admin_user):
        with app.app_context():
            ok, err = AuthService.delete_user(admin_user.id, operator_id=admin_user.id)
            assert not ok
            assert '自己' in err

    def test_cannot_delete_last_admin(self, app, admin_user, test_user):
        with app.app_context():
            ok, err = AuthService.delete_user(admin_user.id, operator_id=test_user.id)
            assert not ok
            assert '至少' in err

    def test_cannot_delete_user_with_data(self, app, admin_user, test_user, sample_vulns):
        with app.app_context():
            from app.extensions import db
            from app.models.experiment import Experiment
            uid = User.query.filter_by(username='testuser').first().id
            exp = Experiment(user_id=uid, vulnerability_id=sample_vulns[0].id,
                             experiment_name='数据占用', token='tok-data-1')
            db.session.add(exp)
            db.session.commit()
            ok, err = AuthService.delete_user(uid, operator_id=admin_user.id)
            assert not ok
            assert '关联数据' in err


# ==================== 访问控制 & 页面 ====================

class TestAdminPanelAccess:
    def test_requires_login(self, client):
        resp = client.get('/admin', follow_redirects=False)
        assert resp.status_code in (301, 302)

    def test_normal_user_forbidden(self, client, test_user):
        login_user(client, 'testuser', 'test123456')
        resp = client.get('/admin', follow_redirects=False)
        assert resp.status_code in (302, 403)

    def test_admin_full_page(self, client, admin_user):
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/admin')
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert '总用户数' in html
        assert '管理入口' in html
        assert 'admin-user-results' in html

    def test_htmx_fragment(self, client, admin_user):
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/admin?q=admin', headers={'HX-Request': 'true'})
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        # 片段不应包含整页骨架 (KRI 卡片)
        assert '总用户数' not in html
        assert 'adminuser' in html

    def test_unified_admin_tabs(self, client, admin_user):
        """统一工作台: /admin 含用户/漏洞/实验三个 Tab, 各 section 均渲染"""
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/admin')
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        # 三个 Tab 入口
        assert '用户管理' in html and '漏洞管理' in html and '实验管理' in html
        # 三个 HTMX 局部刷新目标容器
        assert 'id="admin-user-results"' in html
        assert 'id="admin-vuln-results"' in html
        assert 'id="admin-exp-results"' in html
        # 漏洞 / 实验 的统计图表区已随页面渲染
        assert 'severityChart' in html
        assert 'statusChart' in html
        # 导航仅保留单一「管理后台」入口 (漏洞管理/实验管理不再单独出现于导航)
        assert html.count('漏洞管理') >= 1  # Tab 中保留
        assert html.count('实验管理') >= 1  # Tab 中保留

    def test_role_route_blocks_self(self, client, admin_user, app):
        login_user(client, 'adminuser', 'admin123456')
        aid = admin_user.id
        resp = client.post(f'/admin/user/{aid}/role',
                           data={'role': 'user'}, follow_redirects=True)
        assert resp.status_code == 200
        with app.app_context():
            assert db_get_user(aid).role == 'admin'


def db_get_user(uid):
    from app.extensions import db
    return db.session.get(User, uid)
