"""
AI分析模块测试
覆盖: AIService 业务逻辑、JSON解析、Ollama 可用性检测
注意: 实际 Ollama 调用需要本地服务, 此处测试逻辑层 + 模拟
"""

import pytest
import requests as req_lib
from unittest.mock import patch, MagicMock
from tests.conftest import login_user


class TestAIServiceUnit:
    """AIService 单元测试"""

    def test_parse_json_output_valid(self, app, db):
        """正确解析 JSON 字符串"""
        from app.services.ai_service import AIService
        result = AIService._parse_json_output('{"risk_level": "High", "vulnerability_analysis": "SQLi"}')
        assert result is not None
        assert result['risk_level'] == 'High'

    def test_parse_json_output_markdown(self, app, db):
        """解析 Markdown 代码块包裹的 JSON"""
        from app.services.ai_service import AIService
        text = '```json\n{"risk_level": "Medium", "fix_solution": "使用参数化查询"}\n```'
        result = AIService._parse_json_output(text)
        assert result is not None
        assert result['risk_level'] == 'Medium'

    def test_parse_json_output_empty(self, app, db):
        """空输入返回 None"""
        from app.services.ai_service import AIService
        assert AIService._parse_json_output('') is None
        assert AIService._parse_json_output(None) is None

    def test_parse_json_output_invalid(self, app, db):
        """无效 JSON 返回 None"""
        from app.services.ai_service import AIService
        assert AIService._parse_json_output('这不是JSON') is None

    def test_apply_parsed_result(self, app, db, test_user):
        """解析结果正确应用到 AIAnalysis 模型"""
        from app.services.ai_service import AIService
        from app.models.ai_analysis import AIAnalysis

        with app.app_context():
            analysis = AIAnalysis(
                user_id=test_user.id, input_data='test',
                prompt='test', model='test', status='running'
            )
            db.session.add(analysis)
            db.session.flush()

            parsed = {
                'risk_level': 'High',
                'vulnerability_analysis': 'SQL注入漏洞',
                'possible_attack': "输入 ' OR 1=1",
                'impact': '数据泄露',
                'fix_solution': '参数化查询',
                'security_advice': '定期代码审计'
            }
            AIService._apply_parsed_result(analysis, parsed)

            assert analysis.risk_level == 'High'
            assert 'SQL注入' in analysis.vulnerability_analysis

    def test_apply_parsed_invalid_risk(self, app, db, test_user):
        """无效风险等级回退为 Medium"""
        from app.services.ai_service import AIService
        from app.models.ai_analysis import AIAnalysis

        with app.app_context():
            analysis = AIAnalysis(
                user_id=test_user.id, input_data='test',
                prompt='test', model='test', status='running'
            )
            db.session.add(analysis)
            db.session.flush()

            parsed = {'risk_level': 'SuperCritical'}  # 不在合法集合中
            AIService._apply_parsed_result(analysis, parsed)
            assert analysis.risk_level == 'Medium'

    @patch('app.services.ollama_service.requests.get')
    def test_ollama_availability(self, mock_get, app, db):
        """Ollama 可用性检测"""
        from app.services.ollama_service import OllamaService

        # 模拟可用
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        svc = OllamaService()
        assert svc.is_available() is True

        # 模拟不可用 (使用 requests.ConnectionError)
        mock_get.side_effect = req_lib.ConnectionError('Connection refused')
        assert svc.is_available() is False


class TestAIRoutes:
    """AI 路由集成测试"""

    def test_ai_history_requires_login(self, client, db):
        """未登录访问 AI 历史被重定向"""
        resp = client.get('/ai/history')
        assert resp.status_code == 302

    def test_ai_history_page(self, client, test_user):
        """登录后 AI 历史页正常加载"""
        login_user(client, 'testuser', 'test123456')
        resp = client.get('/ai/history')
        assert resp.status_code == 200
        assert 'AI分析'.encode() in resp.data


class TestAIHistoryEnhancements:
    """AI 历史页升级 (搜索/筛选/排序/统计/行内删除) 测试"""

    def _make(self, app, db, user, **kw):
        from app.models.ai_analysis import AIAnalysis
        with app.app_context():
            a = AIAnalysis(
                user_id=user.id,
                input_data=kw.get('input_data', ''),
                model=kw.get('model', 'qwen2.5'),
                status=kw.get('status', 'completed'),
                risk_level=kw.get('risk_level', 'Info'),
                vulnerability_analysis=kw.get('va', '')
            )
            if kw.get('experiment_id'):
                a.experiment_id = kw['experiment_id']
            if kw.get('scan_task_id'):
                a.scan_task_id = kw['scan_task_id']
            db.session.add(a)
            db.session.commit()
            return a.id  # 在上下文内取回 id, 避免 detach 后属性刷新报错

    def test_filter_by_risk(self, client, app, db, test_user):
        """按风险等级筛选仅返回匹配记录"""
        login_user(client, 'testuser', 'test123456')
        self._make(app, db, test_user, risk_level='Critical', va='严重SQL注入内容')
        self._make(app, db, test_user, risk_level='Low', va='轻微问题内容')
        resp = client.get('/ai/history?risk=Critical')
        assert resp.status_code == 200
        assert '严重SQL注入内容'.encode() in resp.data
        assert '轻微问题内容'.encode() not in resp.data

    def test_filter_by_source_experiment(self, client, app, db, test_user):
        """按来源(实验)筛选仅返回有实验关联的记录"""
        login_user(client, 'testuser', 'test123456')
        from app.services.experiment_service import ExperimentService
        exp, _ = ExperimentService.create_experiment(test_user.id, None, '来源实验', 'http://192.168.56.101', 'low')
        self._make(app, db, test_user, experiment_id=exp.id, va='实验分析内容')
        self._make(app, db, test_user, va='自定义分析内容')
        resp = client.get('/ai/history?source=experiment')
        assert resp.status_code == 200
        assert '实验分析内容'.encode() in resp.data
        assert '自定义分析内容'.encode() not in resp.data

    def test_htmx_returns_partial(self, client, app, db, test_user):
        """HTMX 请求返回结果片段 (无 base.html 外壳)"""
        login_user(client, 'testuser', 'test123456')
        self._make(app, db, test_user, va='HTMX片段内容')
        resp = client.get('/ai/history?q=HTMX', headers={'HX-Request': 'true'})
        assert resp.status_code == 200
        assert b'<html' not in resp.data
        assert 'HTMX片段内容'.encode() in resp.data

    def test_stats_cards_present(self, client, app, db, test_user):
        """历史页显示统计卡片 (总数/已完成/失败/高危)"""
        login_user(client, 'testuser', 'test123456')
        self._make(app, db, test_user, status='completed', risk_level='High')
        self._make(app, db, test_user, status='failed')
        resp = client.get('/ai/history')
        assert resp.status_code == 200
        assert '分析总数'.encode() in resp.data
        assert '高危/严重'.encode() in resp.data

    def test_row_delete_removes_record(self, client, app, db, test_user):
        """行内删除按钮 (POST) 移除对应记录"""
        login_user(client, 'testuser', 'test123456')
        aid = self._make(app, db, test_user, va='待删除分析内容')
        resp = client.post(f'/ai/{aid}/delete', follow_redirects=True)
        assert resp.status_code == 200
        from app.services.ai_service import AIService
        _, err = AIService().get_analysis_by_id(aid, user_id=test_user.id)
        assert err is not None  # 记录已不存在


class TestDashboard:
    """Dashboard 测试"""

    def test_dashboard_requires_login(self, client, db):
        """未登录访问 Dashboard 被重定向"""
        resp = client.get('/security-dashboard')
        assert resp.status_code == 302

    def test_dashboard_user_view(self, client, test_user):
        """普通用户 Dashboard 正常加载"""
        login_user(client, 'testuser', 'test123456')
        resp = client.get('/security-dashboard')
        assert resp.status_code == 200
        assert 'Dashboard'.encode() in resp.data

    def test_dashboard_admin_view(self, client, admin_user):
        """管理员 Dashboard 显示管理员视图"""
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/security-dashboard')
        assert resp.status_code == 200
        assert '管理员视图'.encode() in resp.data

    def test_dashboard_api_returns_json(self, client, test_user):
        """Dashboard API 返回 JSON 数据"""
        login_user(client, 'testuser', 'test123456')
        resp = client.get('/security-dashboard/api')
        assert resp.status_code == 200
        assert resp.content_type.startswith('application/json')
        data = resp.get_json()
        assert 'user_stats' in data

    def test_dashboard_stats_partial(self, client, test_user):
        """Dashboard 统计卡片 HTMX 片段端点"""
        login_user(client, 'testuser', 'test123456')
        resp = client.get('/security-dashboard/stats')
        assert resp.status_code == 200
        # 应返回 HTML 片段而非完整页面
        assert b'<html' not in resp.data


class TestAICustomUpgrade:
    """自定义分析升级 (场景/上限/RAG/模板) 测试"""

    def test_prepare_custom_stores_scene_and_truncates(self, app, db, test_user):
        """_prepare_custom_analysis: 存储 scene, 输入上限 5000"""
        from app.services.ai_service import AIService
        svc = AIService()
        big = 'A' * 8000
        with app.app_context():
            analysis, prompt, model = svc._prepare_custom_analysis(
                test_user.id, big, scene='code')
            assert analysis is not None
            assert analysis.scene == 'code'
            # input_data 截断到 5000
            assert len(analysis.input_data) == 5000
            # 场景化提示词已注入
            assert '代码' in prompt

    def test_prepare_custom_invalid_scene_falls_back(self, app, db, test_user):
        """非法 scene 回退为 general"""
        from app.services.ai_service import AIService
        svc = AIService()
        with app.app_context():
            analysis, _, _ = svc._prepare_custom_analysis(
                test_user.id, 'hello', scene='not_a_real_scene')
            assert analysis.scene == 'general'

    def test_prepare_custom_rag_context_appended(self, app, db, test_user):
        """use_rag=True 时 prompt 追加知识库补充段落"""
        from app.services.ai_service import AIService
        from unittest.mock import patch
        svc = AIService()
        with app.app_context():
            with patch.object(svc.rag, 'retrieve_general_context',
                              return_value='[MySQL] 弱密码风险') as m:
                analysis, prompt, _ = svc._prepare_custom_analysis(
                    test_user.id, 'MySQL 弱密码', scene='general', use_rag=True)
                assert m.called
                assert '安全知识补充' in prompt

    @patch('app.routes.ai.AIService.is_available', return_value=True)
    def test_custom_page_has_upgrades(self, mock_avail, client, test_user):
        """/ai/custom 模板包含场景按钮/字符计数/RAG/场景下拉"""
        login_user(client, 'testuser', 'test123456')
        resp = client.get('/ai/custom')
        assert resp.status_code == 200
        html = resp.data.decode('utf-8')
        assert 'scenario-btn' in html
        assert 'char-count' in html
        assert 'use_rag' in html
        assert 'id="scene"' in html
        assert 'retrieve_general_context' not in html  # 不应泄露内部方法名

    def test_build_custom_prompt_scene_hint(self, app, db):
        """场景化提示词: code/log/config/phishing 各注入针对性引导"""
        from app.services.prompt_service import PromptBuilder
        pb = PromptBuilder()
        base = pb.build_custom_prompt('x')
        for scene, kw in [('code', '代码'), ('log', '日志'),
                          ('config', '配置'), ('phishing', '钓鱼')]:
            out = pb.build_custom_prompt('x', scene=scene)
            assert kw in out
            assert len(out) > len(base)  # 确实附加了内容

    def test_rag_general_context_returns_string(self, app, db):
        """retrieve_general_context: 始终返回 str (无 chroma 时返回 '')"""
        from app.services.rag_service import RAGService
        svc = RAGService()
        # 不抛异常, 返回字符串
        out = svc.retrieve_general_context('SELECT 注入测试')
        assert isinstance(out, str)

