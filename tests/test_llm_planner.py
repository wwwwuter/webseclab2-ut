"""
LLM 动态规划器 (ReAct 循环) 测试
覆盖: 输出解析 / JSON 容错 / ReAct 决策循环 / user_id 注入 / 回退固定链
"""

import pytest

from app.services.mcp.llm_planner import LLMPlanner
from app.services.mcp.tool_registry import register_all_tools
from app.services.mcp.base_tool import ToolResult


class FakeLLM:
    """模拟 LLM 后端, 按预设响应序列返回"""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def chat(self, prompt, model=None):
        self.calls.append(prompt)
        idx = len(self.calls) - 1
        if idx < len(self.responses):
            return self.responses[idx], None
        return '{"action": "final", "answer": "默认结束"}', None


class FakeExecutor:
    """模拟工具执行器, 不真正执行工具"""

    def __init__(self):
        self.execution_log = []
        self.executed = []

    def execute(self, tool_name, **kwargs):
        self.executed.append((tool_name, kwargs))
        return ToolResult(
            success=True, data={}, summary=f'{tool_name} 执行成功', name=tool_name,
        )


def _make_planner(monkeypatch, responses, max_iterations=None):
    """创建带 mock LLM 和 mock executor 的规划器"""
    registry = register_all_tools()
    planner = LLMPlanner(registry=registry, max_iterations=max_iterations)
    planner.executor = FakeExecutor()
    monkeypatch.setattr(planner, '_build_llm', lambda: FakeLLM(responses))
    return planner


# ==================== 输出解析 ====================

class TestParseAction:
    def test_parse_tool_action(self):
        action = LLMPlanner._parse_action(
            '{"action": "scanner", "params": {"target": "127.0.0.1"}}'
        )
        assert action['type'] == 'tool'
        assert action['tool'] == 'scanner'
        assert action['params']['target'] == '127.0.0.1'

    def test_parse_final_action(self):
        action = LLMPlanner._parse_action('{"action": "final", "answer": "分析完成"}')
        assert action['type'] == 'final'
        assert action['answer'] == '分析完成'

    def test_parse_markdown_code_block(self):
        text = '```json\n{"action": "final", "answer": "x"}\n```'
        action = LLMPlanner._parse_action(text)
        assert action['type'] == 'final'
        assert action['answer'] == 'x'

    def test_parse_with_extra_text(self):
        text = '好的，我将调用工具：\n{"action": "dashboard", "params": {}}'
        action = LLMPlanner._parse_action(text)
        assert action['type'] == 'tool'
        assert action['tool'] == 'dashboard'

    def test_parse_invalid(self):
        assert LLMPlanner._parse_action('这不是 JSON') is None
        assert LLMPlanner._parse_action('') is None
        assert LLMPlanner._parse_action(None) is None

    def test_parse_missing_action(self):
        assert LLMPlanner._parse_action('{"params": {}}') is None


class TestExtractJson:
    def test_direct_json(self):
        assert LLMPlanner._extract_json('{"a": 1}') == {'a': 1}

    def test_code_block(self):
        assert LLMPlanner._extract_json('```json\n{"a": 1}\n```') == {'a': 1}

    def test_brace_extraction(self):
        assert LLMPlanner._extract_json('前缀 {"a": 1} 后缀') == {'a': 1}

    def test_invalid(self):
        assert LLMPlanner._extract_json('无 JSON') is None


# ==================== ReAct 决策循环 ====================

class TestPlanReAct:
    def test_llm_unavailable(self, monkeypatch):
        registry = register_all_tools()
        planner = LLMPlanner(registry=registry)
        monkeypatch.setattr(planner, '_build_llm', lambda: None)

        tool_calls, results, final_answer, error = planner.plan(user_id=1)
        assert error is not None
        assert tool_calls == []

    def test_immediate_final(self, monkeypatch):
        planner = _make_planner(monkeypatch, ['{"action": "final", "answer": "无需工具"}'])
        tool_calls, results, final_answer, error = planner.plan(user_id=1)
        assert error is None
        assert tool_calls == []
        assert final_answer == '无需工具'

    def test_react_loop_tool_then_final(self, monkeypatch):
        responses = [
            '{"action": "dashboard", "params": {}}',
            '{"action": "final", "answer": "态势分析完成"}',
        ]
        planner = _make_planner(monkeypatch, responses)
        tool_calls, results, final_answer, error = planner.plan(user_id=1)

        assert error is None
        assert len(tool_calls) == 1
        assert tool_calls[0]['tool'] == 'dashboard'
        assert final_answer == '态势分析完成'
        # 工具结果反馈给 LLM (第二轮 prompt 包含观察)
        assert len(planner.executor.executed) == 1

    def test_user_id_force_injected(self, monkeypatch):
        # LLM 尝试传入恶意 user_id, 应被系统覆盖
        responses = [
            '{"action": "dashboard", "params": {"user_id": 999}}',
            '{"action": "final", "answer": "done"}',
        ]
        planner = _make_planner(monkeypatch, responses)
        tool_calls, results, final_answer, error = planner.plan(user_id=42)

        assert error is None
        assert tool_calls[0]['params']['user_id'] == 42

    def test_unknown_tool_rejected(self, monkeypatch):
        responses = ['{"action": "hack_the_planet", "params": {}}']
        planner = _make_planner(monkeypatch, responses)
        tool_calls, results, final_answer, error = planner.plan(user_id=1)

        assert error is not None
        assert '不存在的工具' in error

    def test_max_iterations_reached(self, monkeypatch):
        # LLM 一直调用工具不输出 final, 应达到最大轮数后报错
        responses = ['{"action": "dashboard", "params": {}}'] * 10
        planner = _make_planner(monkeypatch, responses, max_iterations=2)
        tool_calls, results, final_answer, error = planner.plan(user_id=1)

        assert error is not None
        assert '最大迭代' in error
        assert len(tool_calls) == 2

    def test_llm_chat_error(self, monkeypatch):
        registry = register_all_tools()
        planner = LLMPlanner(registry=registry)
        planner.executor = FakeExecutor()

        class FailingLLM:
            def chat(self, prompt, model=None):
                return '', '模型推理超时'

        monkeypatch.setattr(planner, '_build_llm', lambda: FailingLLM())
        tool_calls, results, final_answer, error = planner.plan(user_id=1)
        assert error is not None
        assert '模型推理超时' in error


# ==================== MCPManager 回退 ====================

class TestMCPManagerFallback:
    def test_fallback_when_llm_unavailable(self, app, client, test_user, monkeypatch):
        """LLM 不可用时, execute_analysis_plan 回退到固定工具链"""
        from tests.conftest import login_user
        login_user(client, 'testuser', 'test123456')

        from app.services.mcp.mcp_manager import MCPManager
        manager = MCPManager()
        monkeypatch.setattr(manager.planner, '_build_llm', lambda: None)

        result = manager.execute_analysis_plan(user_id=test_user.id, target='127.0.0.1')

        assert result['success'] is True
        assert result['planner'] == 'fallback'
        assert result['planning_error'] is not None
        # 固定链: scanner + dashboard (无 experiment_id/scan_id)
        assert 'scanner' in result['tools_executed']
        assert 'dashboard' in result['tools_executed']

    def test_react_planner_used_when_available(self, app, client, test_user, monkeypatch):
        """LLM 可用时, execute_analysis_plan 使用动态规划"""
        from tests.conftest import login_user
        login_user(client, 'testuser', 'test123456')

        from app.services.mcp.mcp_manager import MCPManager
        manager = MCPManager()
        manager.planner.executor = FakeExecutor()
        monkeypatch.setattr(
            manager.planner, '_build_llm',
            lambda: FakeLLM([
                '{"action": "dashboard", "params": {}}',
                '{"action": "final", "answer": "态势概览完成"}',
            ]),
        )

        result = manager.execute_analysis_plan(user_id=test_user.id)

        assert result['success'] is True
        assert result['planner'] == 'react'
        assert result['tools_executed'] == ['dashboard']
        assert result['final_answer'] == '态势概览完成'
        assert 'AI 规划总结' in result['summary']


# ==================== 结构化输出 (chat_structured) ====================

class FakeStructuredLLM:
    """模拟支持 chat_structured 的 LLM 后端"""

    def __init__(self, structured_responses, chat_responses=None):
        self.structured_responses = list(structured_responses)
        self.chat_responses = list(chat_responses or [])
        self.structured_calls = []
        self.chat_calls = []

    def chat_structured(self, prompt, schema=None, model=None):
        self.structured_calls.append(prompt)
        idx = len(self.structured_calls) - 1
        if idx < len(self.structured_responses):
            return self.structured_responses[idx]
        return None, '结构化输出失败'

    def chat(self, prompt, model=None):
        self.chat_calls.append(prompt)
        idx = len(self.chat_calls) - 1
        if idx < len(self.chat_responses):
            return self.chat_responses[idx], None
        return '{"action": "final", "answer": "默认结束"}', None


class TestStructuredOutput:
    def test_uses_chat_structured_first(self, monkeypatch):
        """优先使用 chat_structured 获取动作"""
        llm = FakeStructuredLLM([
            ({'action': 'dashboard', 'params': {}}, None),
            ({'action': 'final', 'answer': '结构化完成'}, None),
        ])
        planner = _make_planner(monkeypatch, [])
        monkeypatch.setattr(planner, '_build_llm', lambda: llm)

        tool_calls, results, final_answer, error = planner.plan(user_id=1)

        assert error is None
        assert len(llm.structured_calls) == 2
        assert llm.chat_calls == []  # 未降级到 chat
        assert final_answer == '结构化完成'

    def test_fallback_to_chat_when_structured_fails(self, monkeypatch):
        """chat_structured 失败时降级到 chat + 正则解析"""
        llm = FakeStructuredLLM(
            structured_responses=[(None, '结构化输出失败')],
            chat_responses=['{"action": "final", "answer": "降级完成"}'],
        )
        planner = _make_planner(monkeypatch, [])
        monkeypatch.setattr(planner, '_build_llm', lambda: llm)

        tool_calls, results, final_answer, error = planner.plan(user_id=1)

        assert error is None
        assert len(llm.structured_calls) == 1
        assert len(llm.chat_calls) == 1  # 已降级
        assert final_answer == '降级完成'

    def test_parse_action_dict(self):
        """_parse_action_dict 从 dict 提取动作"""
        assert LLMPlanner._parse_action_dict(
            {'action': 'scanner', 'params': {'target': 'x'}})['type'] == 'tool'
        assert LLMPlanner._parse_action_dict(
            {'action': 'final', 'answer': 'ok'})['type'] == 'final'
        assert LLMPlanner._parse_action_dict({'params': {}}) is None
        assert LLMPlanner._parse_action_dict(None) is None

    def test_planner_schema_has_required_action(self):
        """PLANNER_SCHEMA 必须包含 action 必填字段"""
        schema = LLMPlanner.PLANNER_SCHEMA
        assert schema['type'] == 'object'
        assert 'action' in schema['required']
        assert 'params' in schema['properties']
        assert 'answer' in schema['properties']
