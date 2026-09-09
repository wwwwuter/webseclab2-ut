"""
实验状态机 + DVWA 连通性探测回归测试
覆盖第一阶段改动: 状态转换合法性、原子事务、结果校验、并发防覆盖、连通性探测分支
"""
import pytest
from unittest.mock import patch

from app.models.experiment import Experiment, ExperimentLog
from app.services.experiment_service import ExperimentService
from app.services import dvwa_service as dvwa_module
from app.services.dvwa_service import DVWAService
from tests.conftest import login_user


@pytest.fixture
def created_exp(app, db, test_user):
    """created 状态的实验"""
    with app.app_context():
        exp, err = ExperimentService.create_experiment(
            user_id=test_user.id, vulnerability_id=None,
            experiment_name='状态机测试', target='http://dvwa.local', dvwa_level='low')
        assert err is None
        yield exp


@pytest.fixture
def running_exp(app, db, test_user, created_exp):
    with app.app_context():
        exp, err = ExperimentService.start_experiment(created_exp.id, test_user.id)
        assert err is None
        yield exp


class TestStateTransitions:
    """状态转换合法性: 只允许 created->running->success/failed, created/running->closed"""

    def test_start_from_created_succeeds(self, app, created_exp, test_user):
        with app.app_context():
            exp, err = ExperimentService.start_experiment(created_exp.id, test_user.id)
            assert err is None
            assert exp.status == Experiment.STATUS_RUNNING

    def test_start_twice_rejected(self, app, running_exp, test_user):
        with app.app_context():
            exp, err = ExperimentService.start_experiment(running_exp.id, test_user.id)
            assert exp is None
            assert err is not None

    def test_complete_without_start_rejected(self, app, created_exp, test_user):
        """未 start 直接提交结果应被拒绝, 不产生结果和完成时间"""
        with app.app_context():
            exp, err = ExperimentService.complete_experiment(
                created_exp.id, test_user.id, '直接提交的结果描述文本', status='success')
            assert exp is None
            assert err is not None
            fresh = ExperimentService.get_experiment_by_id(created_exp.id, test_user.id)[0]
            assert fresh.status == Experiment.STATUS_CREATED
            assert fresh.result is None or fresh.result == ''

    def test_complete_from_running_succeeds(self, app, running_exp, test_user):
        with app.app_context():
            exp, err = ExperimentService.complete_experiment(
                running_exp.id, test_user.id, '成功复现漏洞的详细步骤描述', status='success')
            assert err is None
            assert exp.status == 'success'
            assert exp.completed_time is not None

    def test_complete_on_terminal_state_rejected(self, app, running_exp, test_user):
        """终态不可被覆盖 (success/failed/closed 均为终态)"""
        with app.app_context():
            ExperimentService.complete_experiment(
                running_exp.id, test_user.id, '第一次提交的结果描述文本', status='success')
            exp2, err2 = ExperimentService.complete_experiment(
                running_exp.id, test_user.id, '试图覆盖的第二次结果描述', status='failed')
            assert exp2 is None
            assert err2 is not None
            fresh = ExperimentService.get_experiment_by_id(running_exp.id, test_user.id)[0]
            assert fresh.status == 'success'
            assert '第一次提交' in fresh.result

    def test_close_from_created_succeeds(self, app, created_exp, test_user):
        with app.app_context():
            exp, err = ExperimentService.close_experiment(created_exp.id, test_user.id)
            assert err is None
            assert exp.status == Experiment.STATUS_CLOSED

    def test_close_from_running_succeeds(self, app, running_exp, test_user):
        with app.app_context():
            exp, err = ExperimentService.close_experiment(running_exp.id, test_user.id)
            assert err is None
            assert exp.status == Experiment.STATUS_CLOSED

    def test_close_on_success_rejected(self, app, running_exp, test_user):
        """关闭不能覆盖已完成结果 (success 是终态)"""
        with app.app_context():
            ExperimentService.complete_experiment(
                running_exp.id, test_user.id, '已经成功完成的实验结果描述', status='success')
            exp2, err2 = ExperimentService.close_experiment(running_exp.id, test_user.id)
            assert exp2 is None
            assert err2 is not None
            fresh = ExperimentService.get_experiment_by_id(running_exp.id, test_user.id)[0]
            assert fresh.status == 'success'

    def test_cross_user_operation_rejected(self, app, running_exp, admin_user):
        """跨用户操作被拒绝, 不产生任何状态变更"""
        with app.app_context():
            exp, err = ExperimentService.complete_experiment(
                running_exp.id, admin_user.id, '别人试图提交的结果描述', status='success')
            assert exp is None
            assert err is not None


class TestResultValidation:
    """结果描述校验: 非空、最短长度、最长长度"""

    def test_empty_result_rejected(self, app, running_exp, test_user):
        with app.app_context():
            exp, err = ExperimentService.complete_experiment(
                running_exp.id, test_user.id, '   ', status='success')
            assert exp is None
            assert err is not None

    def test_too_short_result_rejected(self, app, running_exp, test_user):
        with app.app_context():
            exp, err = ExperimentService.complete_experiment(
                running_exp.id, test_user.id, '太短', status='success')
            assert exp is None
            assert err is not None

    def test_invalid_status_rejected(self, app, running_exp, test_user):
        with app.app_context():
            exp, err = ExperimentService.complete_experiment(
                running_exp.id, test_user.id, '一段合法长度的结果描述文本', status='deleted')
            assert exp is None
            assert err is not None


class TestAtomicLogging:
    """业务变更与日志同事务提交, 失败时一起回滚"""

    def test_create_writes_log_atomically(self, app, db, test_user):
        with app.app_context():
            exp, err = ExperimentService.create_experiment(
                user_id=test_user.id, vulnerability_id=None,
                experiment_name='日志一致性测试', target='http://dvwa.local', dvwa_level='low')
            assert err is None
            logs = ExperimentLog.query.filter_by(experiment_id=exp.id).all()
            assert len(logs) == 1
            assert logs[0].action == 'create'

    def test_transition_failure_rolls_back_log(self, app, db, running_exp, test_user):
        """模拟提交事务时抛异常, 状态和日志都不应落地"""
        with app.app_context():
            with patch.object(db.session, 'commit', side_effect=Exception('boom')):
                exp, err = ExperimentService.complete_experiment(
                    running_exp.id, test_user.id, '因异常应被回滚的结果描述', status='success')
            assert exp is None
            assert err is not None
            fresh = ExperimentService.get_experiment_by_id(running_exp.id, test_user.id)[0]
            assert fresh.status == Experiment.STATUS_RUNNING
            logs = ExperimentLog.query.filter_by(
                experiment_id=running_exp.id, action='complete').all()
            assert len(logs) == 0


class TestDvwaConnectivity:
    """连通性探测: 未配置/超时/异常状态码/正常响应/缓存隔离"""

    def setup_method(self):
        dvwa_module._target_cache.clear()

    def test_unconfigured_target(self, app):
        with app.app_context():
            result = DVWAService.check_target_connectivity('')
            assert result['state'] == dvwa_module.STATE_UNCONFIGURED

    def test_timeout_marked_unreachable(self, app):
        import requests
        with app.app_context():
            with patch('app.services.dvwa_service.requests.get', side_effect=requests.Timeout()):
                result = DVWAService.check_target_connectivity('http://10.0.0.1', use_cache=False)
            assert result['state'] == dvwa_module.STATE_UNREACHABLE

    def test_connection_error_marked_unreachable(self, app):
        import requests
        with app.app_context():
            with patch('app.services.dvwa_service.requests.get',
                       side_effect=requests.ConnectionError()):
                result = DVWAService.check_target_connectivity('http://10.0.0.1', use_cache=False)
            assert result['state'] == dvwa_module.STATE_UNREACHABLE

    def test_5xx_marked_http_error_not_ready(self, app):
        class FakeResp:
            status_code = 502
        with app.app_context():
            with patch('app.services.dvwa_service.requests.get', return_value=FakeResp()):
                result = DVWAService.check_target_connectivity('http://10.0.0.1', use_cache=False)
            assert result['state'] == dvwa_module.STATE_HTTP_ERROR

    def test_200_marked_reachable(self, app):
        class FakeResp:
            status_code = 200
        with app.app_context():
            with patch('app.services.dvwa_service.requests.get', return_value=FakeResp()):
                result = DVWAService.check_target_connectivity('http://10.0.0.1', use_cache=False)
            assert result['state'] == dvwa_module.STATE_REACHABLE

    def test_404_still_marked_reachable_not_ready_semantics(self, app):
        """404/403 只代表有 HTTP 服务响应, 不代表已登录或已装 Hook; 仍归为 reachable"""
        class FakeResp:
            status_code = 404
        with app.app_context():
            with patch('app.services.dvwa_service.requests.get', return_value=FakeResp()):
                result = DVWAService.check_target_connectivity('http://10.0.0.1', use_cache=False)
            assert result['state'] == dvwa_module.STATE_REACHABLE

    def test_cache_isolated_by_target(self, app):
        class OkResp:
            status_code = 200

        class ErrResp:
            status_code = 502
        with app.app_context():
            with patch('app.services.dvwa_service.requests.get', return_value=OkResp()):
                r1 = DVWAService.check_target_connectivity('http://a.local')
            with patch('app.services.dvwa_service.requests.get', return_value=ErrResp()):
                r2 = DVWAService.check_target_connectivity('http://b.local')
            assert r1['state'] == dvwa_module.STATE_REACHABLE
            assert r2['state'] == dvwa_module.STATE_HTTP_ERROR

    def test_no_redirect_followed(self, app):
        """探测不应跟随跨域重定向"""
        class OkResp:
            status_code = 200
        with app.app_context():
            with patch('app.services.dvwa_service.requests.get', return_value=OkResp()) as mock_get:
                DVWAService.check_target_connectivity('http://a.local', use_cache=False)
                _, kwargs = mock_get.call_args
                assert kwargs.get('allow_redirects') is False


class TestDvwaStatusRoute:
    """详情页异步探测接口: 用户隔离 + 未配置目标 404"""

    def test_route_requires_login(self, client, running_exp):
        resp = client.get(f'/experiment/{running_exp.id}/dvwa-status')
        assert resp.status_code == 302

    def test_route_returns_json_state(self, client, running_exp, test_user):
        login_user(client, 'testuser', 'test123456')
        class OkResp:
            status_code = 200
        with patch('app.services.dvwa_service.requests.get', return_value=OkResp()):
            resp = client.get(f'/experiment/{running_exp.id}/dvwa-status')
        assert resp.status_code == 200
        assert resp.get_json()['state'] == 'reachable'

    def test_route_blocks_cross_user_access(self, client, running_exp, admin_user):
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get(f'/experiment/{running_exp.id}/dvwa-status')
        assert resp.status_code == 404
