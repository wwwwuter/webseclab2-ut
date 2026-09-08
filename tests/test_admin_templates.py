"""
管理后台: Prompt模板管理 (/ai/admin/templates) P0 改进测试
覆盖: 搜索/场景筛选 + HTMX 片段 / 删除模板(自定义可删, 默认禁删) / reset 版本自增 / 访问控制
"""

import pytest
from tests.conftest import login_user
from app.extensions import db
from app.models.prompt_template import PromptTemplate


def make_tpl(app, **kw):
    """在 app 上下文内创建模板并返回 id"""
    with app.app_context():
        t = PromptTemplate(
            template_key=kw.get('template_key', 'custom_k'),
            name=kw.get('name', '自定义模板'),
            scene=kw.get('scene', 'general'),
            description=kw.get('description', 'desc'),
            content=kw.get('content', '分析 {vulnerability_name}'),
            is_default=kw.get('is_default', False),
            is_active=True,
            version=kw.get('version', 1),
        )
        db.session.add(t)
        db.session.commit()
        return t.id


# ==================== 列表 + 搜索/筛选 ====================

class TestAdminTemplatesList:
    def test_full_page(self, client, admin_user, seed_data):
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/ai/admin/templates')
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert 'admin-templates-results' in html
        assert '新增模板' in html

    def test_htmx_fragment_excludes_search_form(self, client, admin_user, seed_data):
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/ai/admin/templates?q=SQL',
                         headers={'HX-Request': 'true'})
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert 'admin-templates-results' not in html  # 片段不含整页骨架
        assert 'SQL' in html

    def test_search_by_keyword(self, client, admin_user, seed_data, app):
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/ai/admin/templates?q=%E5%91%BD%E4%BB%A4%E6%B3%A8%E5%85%A5',
                         headers={'HX-Request': 'true'})
        html = resp.get_data(as_text=True)
        assert '命令注入' in html
        assert 'SQL' not in html

    def test_filter_by_scene(self, client, admin_user, seed_data):
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/ai/admin/templates?scene=sql_injection',
                         headers={'HX-Request': 'true'})
        html = resp.get_data(as_text=True)
        assert 'SQL' in html
        assert '命令注入' not in html


# ==================== 删除模板 ====================

class TestDeleteTemplate:
    def test_delete_custom_template(self, client, admin_user, seed_data, app):
        tid = make_tpl(app, template_key='custom_del_1', name='待删模板')
        login_user(client, 'adminuser', 'admin123456')
        resp = client.post(f'/ai/admin/templates/delete/{tid}',
                          data={'csrf_token': 'x'}, follow_redirects=False)
        assert resp.status_code in (302, 303)
        with app.app_context():
            assert db.session.get(PromptTemplate, tid) is None

    def test_delete_default_blocked(self, client, admin_user, seed_data, app):
        # 取一个系统默认模板尝试删除
        with app.app_context():
            dt = PromptTemplate.query.filter_by(is_default=True).first()
            assert dt is not None
            did = dt.id
        login_user(client, 'adminuser', 'admin123456')
        resp = client.post(f'/ai/admin/templates/delete/{did}',
                          data={'csrf_token': 'x'}, follow_redirects=True)
        assert resp.status_code == 200
        with app.app_context():
            assert db.session.get(PromptTemplate, did) is not None


# ==================== reset 版本自增 ====================

class TestResetVersion:
    def test_reset_bumps_version(self, client, admin_user, seed_data, app):
        with app.app_context():
            dt = PromptTemplate.query.filter_by(is_default=True).first()
            before = dt.version or 1
            did = dt.id
        login_user(client, 'adminuser', 'admin123456')
        client.post(f'/ai/admin/templates/reset/{did}',
                   data={'csrf_token': 'x'}, follow_redirects=True)
        with app.app_context():
            after = db.session.get(PromptTemplate, did).version
        assert after == before + 1


# ==================== 访问控制 ====================

class TestAccess:
    def test_requires_login(self, client):
        resp = client.get('/ai/admin/templates', follow_redirects=False)
        assert resp.status_code in (301, 302)

    def test_normal_user_forbidden(self, client, test_user):
        login_user(client, 'testuser', 'test123456')
        resp = client.get('/ai/admin/templates', follow_redirects=False)
        assert resp.status_code in (302, 403)
