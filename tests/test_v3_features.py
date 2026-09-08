"""
v3.0 新功能测试模块
覆盖: 风险评分模型, Prompt场景模板, MCP工具框架, 知识图谱, RBAC权限
"""

import pytest
import json
from app.extensions import db


# ==================== 风险评分模型测试 ====================

class TestRiskEngine:
    """RiskEngine 多因素风险评分测试"""

    def test_calculate_basic(self, app, db, client, test_user):
        """基本评分计算: 验证加权公式正确"""
        from app.services.risk_service import RiskEngine
        with app.app_context():
            engine = RiskEngine()
            assessment = engine.calculate(
                cvss=8.0, asset=6.0, exploit=7.0,
                exposure=5.0, ai_conf=6.0,
                user_id=test_user.id, source='manual'
            )

            # 加权计算: (8*0.35 + 6*0.20 + 7*0.20 + 5*0.10 + 6*0.15) * 10
            # = (2.8 + 1.2 + 1.4 + 0.5 + 0.9) * 10 = 6.8 * 10 = 68.0
            assert assessment.final_score == 68.0
            assert assessment.risk_level == 'High'
            assert assessment.source == 'manual'

    def test_risk_level_classification(self, app):
        """风险等级分类阈值测试"""
        from app.models.risk import RiskAssessment
        with app.app_context():
            assert RiskAssessment.classify_risk(90) == 'Critical'
            assert RiskAssessment.classify_risk(80) == 'Critical'
            assert RiskAssessment.classify_risk(60) == 'High'
            assert RiskAssessment.classify_risk(59.9) == 'Medium'
            assert RiskAssessment.classify_risk(40) == 'Medium'
            assert RiskAssessment.classify_risk(39.9) == 'Low'
            assert RiskAssessment.classify_risk(0) == 'Low'

    def test_clamp_values(self, app):
        """评分值范围限制测试"""
        from app.services.risk_service import RiskEngine
        with app.app_context():
            engine = RiskEngine()
            assert engine._clamp(15.0) == 10.0
            assert engine._clamp(-3.0) == 0.0
            assert engine._clamp(5.0) == 5.0

    def test_severity_to_cvss(self, app):
        """severity标签到CVSS转换测试"""
        from app.services.risk_service import RiskEngine
        with app.app_context():
            assert RiskEngine._severity_to_cvss('Critical') == 9.5
            assert RiskEngine._severity_to_cvss('High') == 7.5
            assert RiskEngine._severity_to_cvss('Medium') == 5.0
            assert RiskEngine._severity_to_cvss('Low') == 2.5
            assert RiskEngine._severity_to_cvss('Unknown') == 5.0

    def test_scoring_detail_json(self, app, db, client, test_user):
        """评分明细 JSON 格式测试"""
        from app.services.risk_service import RiskEngine
        with app.app_context():
            engine = RiskEngine()
            assessment = engine.calculate(
                cvss=7.0, asset=5.0, exploit=5.0,
                exposure=5.0, ai_conf=5.0,
                user_id=test_user.id
            )
            detail = json.loads(assessment.scoring_detail)
            assert 'factors' in detail
            assert 'cvss' in detail['factors']
            assert detail['factors']['cvss']['value'] == 7.0
            assert detail['factors']['cvss']['weight'] == 0.35

    def test_risk_routes_require_login(self, client):
        """风险评估页面需要登录"""
        response = client.get('/risk', follow_redirects=True)
        assert response.status_code == 200
        assert b'login' in response.data.lower() or b'\xe7\x99\xbb\xe5\xbd\x95' in response.data


# ==================== Prompt场景模板测试 ====================

class TestPromptScene:
    """PromptBuilder 场景化模板自动匹配测试"""

    def test_detect_scene_sql(self, app):
        """SQL注入场景检测"""
        from app.services.prompt_service import PromptBuilder
        with app.app_context():
            builder = PromptBuilder()

            class MockVuln:
                name = 'SQL Injection Test'
                class category:
                    name = 'SQL Injection'

            scene = builder._detect_scene(MockVuln())
            assert scene == 'sql_injection'

    def test_detect_scene_xss(self, app):
        """XSS场景检测"""
        from app.services.prompt_service import PromptBuilder
        with app.app_context():
            builder = PromptBuilder()

            class MockVuln:
                name = 'XSS Test'
                class category:
                    name = 'XSS'

            scene = builder._detect_scene(MockVuln())
            assert scene == 'xss'

    def test_detect_scene_general(self, app):
        """无匹配时使用通用场景"""
        from app.services.prompt_service import PromptBuilder
        with app.app_context():
            builder = PromptBuilder()

            class MockVuln:
                name = 'Unknown Vuln'
                class category:
                    name = 'Other'

            scene = builder._detect_scene(MockVuln())
            assert scene == 'general'

    def test_detect_scene_none_vulnerability(self, app):
        """空漏洞对象返回通用场景"""
        from app.services.prompt_service import PromptBuilder
        with app.app_context():
            builder = PromptBuilder()
            scene = builder._detect_scene(None)
            assert scene == 'general'

    def test_scene_templates_seeded(self, app, db, seed_data):
        """场景模板种子数据验证"""
        from app.models.prompt_template import PromptTemplate
        with app.app_context():
            sql_tmpl = PromptTemplate.query.filter_by(scene='sql_injection', is_active=True).first()
            xss_tmpl = PromptTemplate.query.filter_by(scene='xss', is_active=True).first()
            assert sql_tmpl is not None
            assert xss_tmpl is not None
            assert 'SQL注入' in sql_tmpl.content or 'sql' in sql_tmpl.content.lower()

    def test_prompt_template_version(self, app, db, seed_data):
        """Prompt模板版本号字段"""
        from app.models.prompt_template import PromptTemplate
        with app.app_context():
            tmpl = PromptTemplate.query.first()
            assert tmpl is not None
            assert tmpl.version >= 1


# ==================== MCP工具框架测试 ====================

class TestMCPFramework:
    """MCP 工具调用框架测试"""

    def test_tool_registry(self, app):
        """工具注册表测试"""
        from app.services.mcp.tool_registry import ToolRegistry, register_all_tools
        with app.app_context():
            ToolRegistry.reset()
            registry = register_all_tools()
            tools = registry.list_tools()
            assert len(tools) >= 6
            assert registry.has('scanner')
            assert registry.has('knowledge')
            assert registry.has('risk')
            assert registry.has('dashboard')
            assert registry.has('report')

    def test_tool_schema(self, app):
        """工具 schema 格式测试"""
        from app.services.mcp.tool_registry import ToolRegistry, register_all_tools
        with app.app_context():
            ToolRegistry.reset()
            registry = register_all_tools()
            schemas = registry.list_schemas()
            for schema in schemas:
                assert 'name' in schema
                assert 'description' in schema
                assert 'parameters' in schema

    def test_tool_executor_missing_tool(self, app):
        """执行不存在的工具返回错误"""
        from app.services.mcp.tool_registry import ToolRegistry, register_all_tools
        from app.services.mcp.tool_executor import ToolExecutor
        with app.app_context():
            ToolRegistry.reset()
            registry = register_all_tools()
            executor = ToolExecutor(registry)
            result = executor.execute('nonexistent_tool')
            assert result.success is False
            assert '不存在' in result.error

    def test_tool_executor_missing_params(self, app):
        """缺少必需参数返回错误"""
        from app.services.mcp.tool_registry import ToolRegistry, register_all_tools
        from app.services.mcp.tool_executor import ToolExecutor
        with app.app_context():
            ToolRegistry.reset()
            registry = register_all_tools()
            executor = ToolExecutor(registry)
            result = executor.execute('scanner')  # 缺少 target 参数
            assert result.success is False

    def test_mcp_manager_tools_api(self, app, db, client, test_user):
        """MCP 工具列表 API 测试"""
        from app.services.mcp.tool_registry import ToolRegistry
        from tests.conftest import login_user
        with app.app_context():
            ToolRegistry.reset()
            # 登录后访问 (使用正确的 /login 路由和测试用户密码)
            login_user(client, test_user.username, 'test123456')
            response = client.get('/mcp/api/tools')
            assert response.status_code == 200
            data = response.get_json()
            assert isinstance(data, list)
            assert len(data) >= 6


# ==================== RBAC 权限测试 ====================

class TestRBAC:
    """RBAC 角色权限模型测试"""

    def test_roles_seeded(self, app, db, seed_data):
        """角色种子数据验证"""
        from app.models.rbac import Role
        with app.app_context():
            admin = Role.query.filter_by(code='admin').first()
            student = Role.query.filter_by(code='student').first()
            teacher = Role.query.filter_by(code='teacher').first()
            auditor = Role.query.filter_by(code='auditor').first()
            researcher = Role.query.filter_by(code='researcher').first()
            assert admin is not None
            assert student is not None
            assert teacher is not None
            assert auditor is not None
            assert researcher is not None

    def test_admin_has_all_permissions(self, app, db, seed_data):
        """管理员角色拥有所有权限"""
        from app.models.rbac import Role
        with app.app_context():
            admin = Role.query.filter_by(code='admin').first()
            assert admin is not None
            assert admin.has_permission('experiment:create')
            assert admin.has_permission('user:manage')
            assert admin.has_permission('vulnerability:manage')

    def test_student_limited_permissions(self, app, db, seed_data):
        """学生角色权限受限"""
        from app.models.rbac import Role
        with app.app_context():
            student = Role.query.filter_by(code='student').first()
            assert student is not None
            assert student.has_permission('experiment:create')
            assert student.has_permission('scan:start')
            assert not student.has_permission('user:manage')
            assert not student.has_permission('vulnerability:manage')

    def test_auditor_readonly(self, app, db, seed_data):
        """审计员角色仅有只读权限"""
        from app.models.rbac import Role
        with app.app_context():
            auditor = Role.query.filter_by(code='auditor').first()
            assert auditor is not None
            assert auditor.has_permission('experiment:view')
            assert auditor.has_permission('audit:view')
            assert not auditor.has_permission('experiment:create')
            assert not auditor.has_permission('scan:start')

    def test_permission_required_decorator(self, app, db):
        """@permission_required 装饰器函数"""
        from app.utils.permission import permission_required
        # 验证装饰器可正常使用
        @permission_required('test:perm')
        def dummy_view():
            return 'ok'
        assert callable(dummy_view)

    def test_get_user_permissions_admin(self, app, db, seed_data, admin_user):
        """管理员获取所有权限"""
        from app.utils.permission import get_user_permissions
        with app.app_context():
            perms = get_user_permissions(admin_user)
            assert len(perms) > 10  # admin 应有大量权限
