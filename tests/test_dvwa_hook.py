"""
DVWA Hook 自动验证功能测试
覆盖: 签名校验 / 事件记录 / 自动判定成功 / 去重 / 防重放 / 非关键事件
"""
import time

import pytest

from app.services.dvwa_service import DVWAService
from app.services.experiment_service import ExperimentService
from app.models.experiment import Experiment
from app.models.experiment_event import ExperimentEvent


@pytest.fixture
def hook_secret(app):
    """为测试应用设置 Hook 共享密钥"""
    app.config['DVWA_HOOK_SECRET'] = 'test-hook-secret-123'
    return 'test-hook-secret-123'


@pytest.fixture
def running_exp(app, db, test_user, sample_vulns):
    """创建并启动一个关联 SQL注入漏洞的实验 (running 状态)"""
    with app.app_context():
        vuln = sample_vulns[0]  # SQL注入基础, 分类为 SQL注入
        exp, _ = ExperimentService.create_experiment(
            user_id=test_user.id, vulnerability_id=vuln.id,
            experiment_name='SQL注入Hook实验', target='http://dvwa', dvwa_level='low')
        exp.status = Experiment.STATUS_RUNNING
        db.session.commit()
        yield exp


def _sign(secret, token, event_type, ts):
    """生成合法签名"""
    canonical = DVWAService.canonical_payload(token, event_type, ts)
    return DVWAService.sign_payload(canonical, secret)


class TestSignature:
    def test_sign_and_verify(self, hook_secret):
        """签名可被正确校验"""
        canonical = DVWAService.canonical_payload('EXP-ABC', 'sqli_success', 1234567890)
        sig = DVWAService.sign_payload(canonical, hook_secret)
        assert DVWAService.verify_signature(canonical, sig, hook_secret) is True

    def test_verify_rejects_tampered(self, hook_secret):
        """篡改 payload 后签名校验失败"""
        canonical = DVWAService.canonical_payload('EXP-ABC', 'sqli_success', 1234567890)
        sig = DVWAService.sign_payload(canonical, hook_secret)
        tampered = DVWAService.canonical_payload('EXP-ABC', 'xss_success', 1234567890)
        assert DVWAService.verify_signature(tampered, sig, hook_secret) is False

    def test_verify_rejects_wrong_secret(self, hook_secret):
        """错误密钥签名校验失败"""
        canonical = DVWAService.canonical_payload('EXP-ABC', 'sqli_success', 1234567890)
        sig = DVWAService.sign_payload(canonical, 'wrong-secret')
        assert DVWAService.verify_signature(canonical, sig, hook_secret) is False

    def test_verify_empty_secret(self, app):
        """未配置密钥时校验失败"""
        app.config['DVWA_HOOK_SECRET'] = ''
        canonical = DVWAService.canonical_payload('EXP-ABC', 'sqli_success', 1234567890)
        assert DVWAService.verify_signature(canonical, 'abc') is False


class TestCategoryEventMap:
    def test_sql_injection_maps_to_sqli(self):
        assert DVWAService.get_key_event_for_category('SQL Injection') == 'sqli_success'

    def test_xss_maps_to_xss(self):
        assert DVWAService.get_key_event_for_category('XSS') == 'xss_success'

    def test_unknown_category_returns_none(self):
        assert DVWAService.get_key_event_for_category('Unknown') is None

    def test_empty_category_returns_none(self):
        assert DVWAService.get_key_event_for_category('') is None


class TestHookEndpoint:
    def _post(self, client, token, event_type, ts, secret, payload=None):
        """构造并发送带签名的 Hook 上报"""
        sig = _sign(secret, token, event_type, ts)
        return client.post('/api/dvwa/hook', json={
            'experiment_token': token,
            'event_type': event_type,
            'payload': payload,
            'timestamp': ts,
            'signature': sig,
        })

    def test_requires_json(self, client):
        resp = client.post('/api/dvwa/hook', data='not-json', content_type='text/plain')
        assert resp.status_code == 400

    def test_missing_fields(self, client):
        resp = client.post('/api/dvwa/hook', json={'event_type': 'sqli_success'})
        assert resp.status_code == 400

    def test_invalid_signature(self, client, hook_secret, running_exp):
        """错误签名返回 401"""
        ts = int(time.time())
        resp = client.post('/api/dvwa/hook', json={
            'experiment_token': running_exp.token,
            'event_type': 'sqli_success',
            'timestamp': ts,
            'signature': 'deadbeef',
        })
        assert resp.status_code == 401

    def test_stale_timestamp_rejected(self, client, hook_secret, running_exp):
        """过期时间戳被拒绝 (防重放)"""
        ts = int(time.time()) - 10000
        resp = self._post(client, running_exp.token, 'sqli_success', ts, hook_secret)
        assert resp.status_code == 400

    def test_key_event_triggers_success(self, client, app, db, hook_secret, running_exp):
        """命中关键事件且实验 running -> 自动判定成功"""
        ts = int(time.time())
        resp = self._post(client, running_exp.token, 'sqli_success', ts, hook_secret)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert data['triggered_success'] is True

        with app.app_context():
            exp = db.session.get(Experiment, running_exp.id)
            assert exp.status == Experiment.STATUS_SUCCESS
            assert '自动验证' in exp.result
            # 事件已记录
            ev = db.session.get(ExperimentEvent, data['event_id'])
            assert ev.triggered_success is True

    def test_non_key_event_no_success(self, client, app, db, hook_secret, running_exp):
        """非关键事件不触发成功, 实验保持 running"""
        ts = int(time.time())
        resp = self._post(client, running_exp.token, 'xss_success', ts, hook_secret)
        assert resp.status_code == 200
        assert resp.get_json()['triggered_success'] is False

        with app.app_context():
            exp = db.session.get(Experiment, running_exp.id)
            assert exp.status == Experiment.STATUS_RUNNING

    def test_unknown_experiment_404(self, client, hook_secret):
        """不存在的实验返回 404"""
        ts = int(time.time())
        resp = self._post(client, 'EXP-NOTEXIST', 'sqli_success', ts, hook_secret)
        assert resp.status_code == 404

    def test_deduplication(self, client, app, db, hook_secret, running_exp):
        """相同事件重复上报只记录一次 (幂等)"""
        ts = int(time.time())
        self._post(client, running_exp.token, 'sqli_success', ts, hook_secret)
        self._post(client, running_exp.token, 'sqli_success', ts, hook_secret)

        with app.app_context():
            count = ExperimentEvent.query.filter_by(
                experiment_id=running_exp.id, event_type='sqli_success').count()
            assert count == 1


class TestRecordHookEvent:
    def test_created_experiment_not_auto_success(self, app, db, test_user, sample_vulns):
        """created 状态实验收到关键事件不自动判定 (需先启动)"""
        with app.app_context():
            vuln = sample_vulns[0]
            exp, _ = ExperimentService.create_experiment(
                user_id=test_user.id, vulnerability_id=vuln.id,
                experiment_name='未启动实验', target='http://dvwa', dvwa_level='low')
            # 保持 created 状态
            event, error = ExperimentService.record_hook_event(
                exp.token, 'sqli_success', {'a': 1}, int(time.time()))
            assert error is None
            assert event.triggered_success is True  # 命中关键事件标记
            # 但实验状态不变 (created 不自动判定)
            assert db.session.get(Experiment, exp.id).status == Experiment.STATUS_CREATED

    def test_missing_token(self, app, db):
        event, error = ExperimentService.record_hook_event('', 'sqli_success')
        assert error is not None
        assert event is None

    def test_get_events_ordered(self, app, db, test_user, sample_vulns):
        """事件列表按时间倒序"""
        with app.app_context():
            vuln = sample_vulns[0]
            exp, _ = ExperimentService.create_experiment(
                user_id=test_user.id, vulnerability_id=vuln.id,
                experiment_name='事件排序', target='http://dvwa', dvwa_level='low')
            exp.status = Experiment.STATUS_RUNNING
            db.session.commit()
            ExperimentService.record_hook_event(exp.token, 'sqli_success', None, int(time.time()))
            ExperimentService.record_hook_event(exp.token, 'xss_success', None, int(time.time()))
            events = ExperimentService.get_experiment_events(exp.id)
            assert len(events) == 2
            # 倒序: 后记录的在前
            assert events[0].event_type == 'xss_success'
