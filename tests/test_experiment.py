"""实验管理 (admin) 功能测试 - P0+P1 筛选/删除口径/统计/详情"""
import pytest
from app.models.user import User
from app.models.experiment import Experiment
from app.services.experiment_service import ExperimentService


@pytest.fixture
def sample_exps(app, db, admin_user, test_user):
    """创建跨用户的示例实验数据 (供筛选/删除测试)"""
    with app.app_context():
        exps = []
        # test_user 的两个实验
        e1, _ = ExperimentService.create_experiment(
            user_id=test_user.id, vulnerability_id=None,
            experiment_name='SQL注入练习', target='http://dvwa', dvwa_level='low')
        e2, _ = ExperimentService.create_experiment(
            user_id=test_user.id, vulnerability_id=None,
            experiment_name='XSS实战', target='http://dvwa', dvwa_level='high')
        # 直接改状态便于筛选
        e2.status = 'failed'
        db.session.commit()
        # admin 自己的一个实验
        e3, _ = ExperimentService.create_experiment(
            user_id=admin_user.id, vulnerability_id=None,
            experiment_name='CSRF研究', target='http://dvwa', dvwa_level='medium')
        e3.status = 'running'
        db.session.commit()
        exps = [e1, e2, e3]
        yield exps


class TestAdminExpList:
    def test_requires_login(self, client):
        resp = client.get('/admin/experiment')
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

    def test_normal_user_forbidden(self, client, test_user):
        from tests.conftest import login_user
        login_user(client, 'testuser', 'test123456')
        resp = client.get('/admin/experiment')
        assert resp.status_code == 403

    def test_admin_full_page(self, client, admin_user):
        from tests.conftest import login_user
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/admin/experiment')
        assert resp.status_code == 200
        assert '实验管理' in resp.text
        # KRI 卡与图表容器
        assert '实验总数' in resp.text
        assert '成功率' in resp.text
        assert 'statusChart' in resp.text

    def test_admin_filter_by_status(self, client, admin_user, sample_exps):
        from tests.conftest import login_user
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/admin/experiment?status=running')
        assert resp.status_code == 200
        assert 'CSRF研究' in resp.text
        assert 'SQL注入练习' not in resp.text

    def test_admin_filter_by_keyword(self, client, admin_user, sample_exps):
        from tests.conftest import login_user
        login_user(client, 'adminuser', 'admin123456')
        # 按用户名(owner)筛选
        resp = client.get('/admin/experiment?q=testuser')
        assert resp.status_code == 200
        assert 'SQL注入练习' in resp.text
        assert 'CSRF研究' not in resp.text

    def test_admin_htmx_fragment(self, client, admin_user, sample_exps):
        from tests.conftest import login_user
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/admin/experiment', headers={'HX-Request': 'true'})
        assert resp.status_code == 200
        # 片段不应含整页外壳
        assert '<!DOCTYPE' not in resp.text and '<html' not in resp.text
        assert 'SQL注入练习' in resp.text

    def test_admin_delete_any_user_exp(self, client, admin_user, sample_exps, app, db):
        """验证 is_owner 口径修复: admin 能删别人的实验"""
        from tests.conftest import login_user
        login_user(client, 'adminuser', 'admin123456')
        target = sample_exps[0]  # test_user 的实验
        resp = client.post(f'/admin/experiment/{target.id}/delete', follow_redirects=True)
        assert resp.status_code == 200
        with app.app_context():
            assert db.session.get(Experiment, target.id) is None

    def test_stats_keys_present(self, client, admin_user, sample_exps):
        from tests.conftest import login_user
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/admin/experiment')
        # 后端统计键在图表数据中体现
        assert 'success_rate' in resp.text or '成功率' in resp.text
        assert 'DVWA' in resp.text  # 等级占比区

    def test_admin_detail_bypass_owner(self, client, admin_user, sample_exps):
        """admin 能查看别人的实验详情 (绕过 owner 校验)"""
        from tests.conftest import login_user
        login_user(client, 'adminuser', 'admin123456')
        target = sample_exps[0]  # test_user 的实验
        resp = client.get(f'/admin/experiment/{target.id}')
        assert resp.status_code == 200
        assert 'SQL注入练习' in resp.text
        # admin 视图下不应出现用户端写操作按钮 (启动/提交结果)
        assert '启动实验' not in resp.text


class TestExpSort:
    """P2: 表头排序 (语义排序, 非字母序)"""

    def _make_levels(self, app, admin_user, levels):
        created = []
        with app.app_context():
            for lv in levels:
                e, _ = ExperimentService.create_experiment(
                    user_id=admin_user.id, vulnerability_id=None,
                    experiment_name=f'exp-{lv}', target='http://dvwa', dvwa_level=lv)
                created.append(e)
        return created

    def test_sort_dvwa_level_asc(self, app, admin_user):
        self._make_levels(app, admin_user, ['impossible', 'low', 'high', 'medium'])
        with app.app_context():
            items = ExperimentService.get_experiments_filtered(
                sort_by='dvwa_level', order='asc').items
            assert [e.dvwa_level for e in items] == ['low', 'medium', 'high', 'impossible']

    def test_sort_dvwa_level_desc(self, app, admin_user):
        self._make_levels(app, admin_user, ['low', 'high', 'medium', 'impossible'])
        with app.app_context():
            items = ExperimentService.get_experiments_filtered(
                sort_by='dvwa_level', order='desc').items
            assert [e.dvwa_level for e in items] == ['impossible', 'high', 'medium', 'low']

    def test_sort_status_semantic(self, app, admin_user, db):
        with app.app_context():
            order_map = ['created', 'running', 'success', 'failed', 'closed']
            for st in ['closed', 'created', 'failed', 'running', 'success']:
                e, _ = ExperimentService.create_experiment(
                    user_id=admin_user.id, vulnerability_id=None,
                    experiment_name=f's-{st}', target='http://dvwa', dvwa_level='low')
                e.status = st
                db.session.commit()
            items = ExperimentService.get_experiments_filtered(
                sort_by='status', order='asc').items
            assert [e.status for e in items] == order_map

    def test_sort_default_by_created_desc(self, app, admin_user):
        self._make_levels(app, admin_user, ['low', 'medium'])
        with app.app_context():
            items = ExperimentService.get_experiments_filtered().items
            # 默认按 created_time 倒序
            assert items[0].created_time >= items[-1].created_time

    def test_sort_param_flows_to_fragment(self, client, admin_user, sample_exps):
        from tests.conftest import login_user
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/admin/experiment?sort=dvwa_level&order=asc',
                          headers={'HX-Request': 'true'})
        assert resp.status_code == 200
        # 排序表头链接存在 (含 sort 参数)
        assert 'sort=dvwa_level' in resp.text

    def test_full_page_has_sortable_headers(self, client, admin_user, sample_exps):
        from tests.conftest import login_user
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/admin/experiment')
        assert resp.status_code == 200
        assert 'sort=dvwa_level' in resp.text
        assert 'sort=status' in resp.text
        assert 'sort=created_time' in resp.text


class TestExpRowClick:
    """P2-7: 列表行点击进入详情 (data-detail-url 注入)"""

    def test_row_has_detail_url(self, client, admin_user, sample_exps):
        from tests.conftest import login_user
        login_user(client, 'adminuser', 'admin123456')
        target = sample_exps[0]
        resp = client.get('/admin/experiment', headers={'HX-Request': 'true'})
        # 每行带 exp-row 与指向详情的 data-detail-url
        assert 'exp-row' in resp.text
        assert f'/admin/experiment/{target.id}"' in resp.text or f"/admin/experiment/{target.id}" in resp.text
        assert f'data-detail-url="/admin/experiment/{target.id}"' in resp.text

    def test_row_click_target_resolves(self, client, admin_user, sample_exps):
        from tests.conftest import login_user
        login_user(client, 'adminuser', 'admin123456')
        target = sample_exps[0]
        # data-detail-url 指向的详情页应可访问 (验证链接有效)
        resp = client.get(f'/admin/experiment/{target.id}')
        assert resp.status_code == 200
        assert 'SQL注入练习' in resp.text


class TestUserExpList:
    """用户端列表: 搜索/筛选/排序 (HTMX) + 创建页分组预填"""

    @pytest.fixture
    def user_exps(self, app, db, test_user):
        with app.app_context():
            e1, _ = ExperimentService.create_experiment(
                user_id=test_user.id, vulnerability_id=None,
                experiment_name='SQL注入练习', target='http://dvwa', dvwa_level='low')
            e2, _ = ExperimentService.create_experiment(
                user_id=test_user.id, vulnerability_id=None,
                experiment_name='XSS实战', target='http://dvwa', dvwa_level='high')
            e2.status = 'failed'
            db.session.commit()
            yield [e1, e2]

    def _login(self, client):
        from tests.conftest import login_user
        login_user(client, 'testuser', 'test123456')

    def test_filter_by_dvwa_level(self, client, test_user, user_exps):
        self._login(client)
        resp = client.get('/experiment?dvwa_level=low')
        assert resp.status_code == 200
        assert 'SQL注入练习' in resp.text
        assert 'XSS实战' not in resp.text

    def test_filter_by_status(self, client, test_user, user_exps):
        self._login(client)
        resp = client.get('/experiment?status=failed')
        assert resp.status_code == 200
        assert 'XSS实战' in resp.text
        assert 'SQL注入练习' not in resp.text

    def test_htmx_partial_returns_only_results(self, client, test_user, user_exps):
        self._login(client)
        resp = client.get('/experiment?q=SQL', headers={'HX-Request': 'true'})
        assert resp.status_code == 200
        # 片段不含整页外壳 (统计标题), 但含卡片
        assert '我的实验' not in resp.text
        assert 'SQL注入练习' in resp.text

    def test_create_page_grouped_and_prefill(self, client, test_user, sample_vulns):
        self._login(client)
        target = sample_vulns[0]  # SQL注入基础, 属于 SQL注入 分类
        resp = client.get(f'/experiment/create?vulnerability_id={target.id}')
        assert resp.status_code == 200
        assert 'SQL注入' in resp.text          # optgroup 分类名
        assert f'value="{target.id}" selected' in resp.text  # 预选


class TestExpDetailEnhancements:
    """详情页: result 轻量渲染 / Token 复制 / 耗时 / 关联报告 / 智能返回"""

    def _login(self, client):
        from tests.conftest import login_user
        login_user(client, 'testuser', 'test123456')

    def test_detail_enhancements(self, client, app, db, test_user):
        from app.services.experiment_service import ExperimentService
        from app.models.report import Report
        from datetime import datetime, timedelta
        self._login(client)
        exp, _ = ExperimentService.create_experiment(
            user_id=test_user.id, vulnerability_id=None,
            experiment_name='耗时实验', target='http://dvwa', dvwa_level='low')
        exp.status = 'success'
        exp.result = '步骤1\n步骤2 含 `code`\n```\nSELECT 1;\n```'
        exp.created_time = datetime.now() - timedelta(hours=2)
        exp.completed_time = datetime.now()
        db.session.commit()
        # 关联一份报告
        rep = Report(user_id=test_user.id, experiment_id=exp.id,
                     title='实验报告A', report_type='experiment', status='generated')
        db.session.add(rep)
        db.session.commit()

        resp = client.get(f'/experiment/{exp.id}?status=success')
        assert resp.status_code == 200
        # 1) result 轻量渲染 (换行/代码块)
        assert '<br>' in resp.text
        assert '<code>' in resp.text
        assert '<pre' in resp.text
        # 2) Token 复制按钮
        assert 'copyToken' in resp.text
        assert 'data-token=' in resp.text
        # 3) 实验耗时
        assert '实验耗时' in resp.text
        assert '小时' in resp.text
        # 4) 关联报告
        assert '关联 AI 报告' in resp.text
        assert '实验报告A' in resp.text
        # 5) 智能返回保留筛选参数
        assert 'status=success' in resp.text



