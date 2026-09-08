"""
风险评估模块测试
覆盖: 评估记录删除及权限隔离 (此前为测试盲区)
批量删除 + 列表页行点击/去操作列改造

权限规则:
  - 普通用户只能删除自己的评估记录
  - 管理员 (user_id=None) 可删除任意记录
"""
import pytest
import json as _json
from werkzeug.security import generate_password_hash

from app.extensions import db
from app.models.risk import RiskAssessment
from app.models.user import User
from tests.conftest import login_user


class TestRiskDelete:
    """delete_assessment 权限与行为测试"""

    def _make_user(self, app, username):
        with app.app_context():
            u = User(username=username, password_hash=generate_password_hash('x'))
            db.session.add(u)
            db.session.commit()
            return u.id

    def _make_assessment(self, app, user_id):
        with app.app_context():
            a = RiskAssessment(
                user_id=user_id,
                cvss_score=9.0, asset_score=3.0, exploit_score=8.0,
                exposure_score=5.0, ai_score=7.0,
                final_score=85.0, risk_level='Critical',
                scoring_detail='{}', source='manual'
            )
            db.session.add(a)
            db.session.commit()
            return a.id

    def test_delete_own_succeeds(self, app, db, test_user):
        """普通用户删除自己的记录成功"""
        from app.services.risk_service import RiskEngine
        svc = RiskEngine()
        aid = self._make_assessment(app, test_user.id)
        with app.app_context():
            ok, err = svc.delete_assessment(aid, user_id=test_user.id)
            assert ok is True
            assert err is None
            assert db.session.get(RiskAssessment, aid) is None

    def test_delete_other_forbidden(self, app, db, test_user):
        """普通用户不能删除他人记录"""
        from app.services.risk_service import RiskEngine
        svc = RiskEngine()
        other_id = self._make_user(app, 'risk_other_user')
        aid = self._make_assessment(app, other_id)
        with app.app_context():
            ok, err = svc.delete_assessment(aid, user_id=test_user.id)
            assert ok is False
            assert '无权' in err
            assert db.session.get(RiskAssessment, aid) is not None

    def test_delete_as_admin_any(self, app, db):
        """管理员 (user_id=None) 可删除任意用户的记录"""
        from app.services.risk_service import RiskEngine
        svc = RiskEngine()
        uid = self._make_user(app, 'risk_target_user')
        aid = self._make_assessment(app, uid)
        with app.app_context():
            ok, err = svc.delete_assessment(aid, user_id=None)
            assert ok is True
            assert db.session.get(RiskAssessment, aid) is None

    def test_delete_nonexistent(self, app, db, test_user):
        """删除不存在的记录返回明确错误"""
        from app.services.risk_service import RiskEngine
        svc = RiskEngine()
        with app.app_context():
            ok, err = svc.delete_assessment(999999, user_id=test_user.id)
            assert ok is False
            assert '不存在' in err


class TestRiskBatchDelete:
    """批量删除 + 列表页行点击/去操作列改造"""

    def _make_user(self, app, username):
        with app.app_context():
            u = User(username=username, password_hash=generate_password_hash('x'))
            db.session.add(u)
            db.session.commit()
            return u.id

    def _make_assessments(self, app, user_id, n=3):
        with app.app_context():
            ids = []
            for i in range(n):
                a = RiskAssessment(
                    user_id=user_id,
                    cvss_score=5.0, asset_score=3.0, exploit_score=5.0,
                    exposure_score=5.0, ai_score=5.0,
                    final_score=50.0, risk_level='Medium',
                    scoring_detail='{}', source='auto'
                )
                db.session.add(a)
                db.session.commit()
                ids.append(a.id)
            return ids

    # ---- service 层批量删除 ----

    def test_batch_delete_own_records(self, app, db, test_user):
        """普通用户可批量删除自己的多条记录"""
        from app.services.risk_service import RiskEngine
        svc = RiskEngine()
        ids = self._make_assessments(app, test_user.id, 4)
        with app.app_context():
            count, err = svc.batch_delete_assessments(ids[:2], user_id=test_user.id)
            assert count == 2
            assert err is None
            assert db.session.get(RiskAssessment, ids[0]) is None
            assert db.session.get(RiskAssessment, ids[1]) is None
            # 剩余两条仍存在
            assert db.session.get(RiskAssessment, ids[2]) is not None
            assert db.session.get(RiskAssessment, ids[3]) is not None

    def test_batch_delete_other_forbidden(self, app, db, test_user):
        """批量删除时跳过不属于当前用户的记录"""
        from app.services.risk_service import RiskEngine
        svc = RiskEngine()
        other_id = self._make_user(app, 'batch_other')
        my_ids = self._make_assessments(app, test_user.id, 2)
        other_ids = self._make_assessments(app, other_id, 2)
        with app.app_context():
            # 尝试删自己的 + 别人的混合 ID
            mixed = [my_ids[0], other_ids[0], other_ids[1]]
            count, err = svc.batch_delete_assessments(mixed, user_id=test_user.id)
            assert count == 1  # 只删了自己的那条
            assert db.session.get(RiskAssessment, my_ids[0]) is None
            # 他人的不受影响
            assert db.session.get(RiskAssessment, other_ids[0]) is not None
            assert db.session.get(RiskAssessment, other_ids[1]) is not None

    def test_batch_delete_empty_selection(self, app, test_user):
        """空列表返回提示"""
        from app.services.risk_service import RiskEngine
        svc = RiskEngine()
        with app.app_context():
            count, err = svc.batch_delete_assessments([], user_id=test_user.id)
            assert count == 0
            assert '未选择' in err

    def test_batch_delete_as_admin(self, app, db):
        """管理员 (user_id=None) 可跨用户批量删除"""
        from app.services.risk_service import RiskEngine
        svc = RiskEngine()
        uid1 = self._make_user(app, 'admin_target_1')
        uid2 = self._make_user(app, 'admin_target_2')
        ids1 = self._make_assessments(app, uid1, 2)
        ids2 = self._make_assessments(app, uid2, 2)
        with app.app_context():
            count, err = svc.batch_delete_assessments([ids1[0], ids2[1]], user_id=None)
            assert count == 2
            assert db.session.get(RiskAssessment, ids1[0]) is None
            assert db.session.get(RiskAssessment, ids2[1]) is None

    # ---- 路由层: HTMX 批量删除 ----

    def test_batch_delete_route_htmx(self, client, app, test_user):
        """HTMX 批量删除: 返回片段而非重定向"""
        from app.services.risk_service import RiskEngine
        svc = RiskEngine()

        login_user(client, 'testuser', 'test123456')

        # 创建测试数据
        ids = []
        with app.app_context():
            for i in range(3):
                a = RiskAssessment(
                    user_id=test_user.id,
                    cvss_score=5.0, asset_score=3.0, exploit_score=5.0,
                    exposure_score=5.0, ai_score=5.0,
                    final_score=50.0, risk_level='Medium',
                    scoring_detail='{}', source='auto'
                )
                db.session.add(a)
                db.session.commit()
                ids.append(a.id)

        resp = client.post('/risk/batch-delete',
                           data={'ids': _json.dumps([ids[0], ids[1]]),
                                 'page': '1'},
                           headers={'HX-Request': 'true'})
        assert resp.status_code == 200
        html = resp.data.decode('utf-8')
        # 片段中应包含统计卡和表格
        assert '总评估' in html or '评估历史' in html
        # 已删除的记录不在数据库中
        with app.app_context():
            assert db.session.get(RiskAssessment, ids[0]) is None
            assert db.session.get(RiskAssessment, ids[1]) is None
            # 未选中的仍在
            assert db.session.get(RiskAssessment, ids[2]) is not None

    # ---- 模板: 行点击 + 去操作列 ----

    def test_list_page_no_operations_column(self, client, app, test_user):
        """列表模板: 无操作列, 有删除进入选择模式按钮 + 行点击 data-href"""
        login_user(client, 'testuser', 'test123456')
        # 确保有一条记录让表格渲染出 data-href 行
        with app.app_context():
            a = RiskAssessment(
                user_id=test_user.id,
                cvss_score=5.0, asset_score=3.0, exploit_score=5.0,
                exposure_score=5.0, ai_score=5.0,
                final_score=50.0, risk_level='Medium',
                scoring_detail='{}', source='auto'
            )
            db.session.add(a)
            db.session.commit()
        resp = client.get('/risk')
        assert resp.status_code == 200
        html = resp.data.decode('utf-8')
        # 不应有操作列头
        assert '<th>操作</th>' not in html
        # 应有「删除」进入选择模式按钮
        assert 'enterSelectBtn' in html
        # 选择模式下才显示的全选/确认删除控件
        assert 'selectAllCheck' in html
        assert 'confirmDeleteBtn' in html
        # 应有 data-href 行点击属性
        assert 'data-href' in html

    def test_list_page_row_click_to_detail(self, client, app, test_user):
        """每行包含指向详情的 data-href 链接"""
        from app.services.risk_service import RiskEngine
        svc = RiskEngine()
        aid = None
        with app.app_context():
            a = RiskAssessment(
                user_id=test_user.id,
                cvss_score=7.0, asset_score=5.0, exploit_score=6.0,
                exposure_score=4.0, ai_score=8.0,
                final_score=65.0, risk_level='High',
                scoring_detail='{}', source='auto'
            )
            db.session.add(a)
            db.session.commit()
            aid = a.id

        login_user(client, 'testuser', 'test123456')
        resp = client.get('/risk')
        html = resp.data.decode('utf-8')
        assert f'/risk/{aid}' in html
