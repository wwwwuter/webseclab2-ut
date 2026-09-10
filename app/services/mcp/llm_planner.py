"""
LLM 动态规划器 (ReAct 循环)

将 MCP 工具链从「固定顺序编排」升级为「LLM 动态规划」:
LLM 根据用户意图和上一步工具执行结果, 逐步决策下一步调用哪个工具,
直到信息足够时输出最终分析总结。

核心流程 (ReAct):
  用户意图 → LLM 决策 (调用工具 / 输出结论)
           → 执行工具 → 结果反馈给 LLM
           → 重复, 直到 LLM 输出 final 或达到最大轮数

设计原则:
  - 优雅降级: LLM 不可用 / 输出无法解析 / 达到最大轮数时, 返回错误,
    由 MCPManager 回退到固定工具链。
  - 安全: 工具名必须存在于注册表; user_id 由系统强制注入, 不信任 LLM 传入。
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from app.services.mcp.tool_registry import ToolRegistry
from app.services.mcp.tool_executor import ToolExecutor

logger = logging.getLogger(__name__)


class LLMPlanner:
    """基于 ReAct 循环的 LLM 工具规划器"""

    # 默认最大迭代轮数 (每轮最多调用一个工具)
    DEFAULT_MAX_ITERATIONS = 6

    # 结构化输出 JSON schema (宽松: 仅 action 必填, 兼容 Ollama/OpenAI 两种后端)
    PLANNER_SCHEMA = {
        'type': 'object',
        'properties': {
            'action': {'type': 'string'},
            'params': {'type': 'object', 'additionalProperties': True},
            'answer': {'type': 'string'},
        },
        'required': ['action'],
    }

    def __init__(self, registry: ToolRegistry = None, executor: ToolExecutor = None,
                 max_iterations: int = None):
        self.registry = registry or ToolRegistry()
        self.executor = executor or ToolExecutor(self.registry)
        self.max_iterations = max_iterations or self.DEFAULT_MAX_ITERATIONS

    # ==================== 对外接口 ====================

    def plan(self, user_id: int, target: str = '',
             experiment_id: int = None, scan_id: int = None,
             model: str = None) -> Tuple[List[Dict[str, Any]], List, Optional[str], Optional[str]]:
        """
        执行 ReAct 循环, 动态规划工具调用序列。

        :param user_id: 用户ID (系统强制注入到每个工具调用)
        :param target: 扫描目标 (可选)
        :param experiment_id: 实验ID (可选)
        :param scan_id: 扫描任务ID (可选)
        :param model: 指定模型 (可选)
        :return: (tool_calls, results, final_answer, error)
                 - tool_calls: 已执行的工具调用列表 [{'tool':..., 'params':...}]
                 - results: 与 tool_calls 一一对应的 ToolResult 列表
                 - final_answer: LLM 最终总结 (成功时非空)
                 - error: 错误信息 (失败时非空)
        """
        llm = self._build_llm()
        if llm is None:
            return [], [], None, 'LLM 服务不可用 (未配置或未启动)'

        system_prompt = self._build_system_prompt()
        user_intent = self._build_user_intent(target, experiment_id, scan_id)

        tool_calls: List[Dict[str, Any]] = []
        results: List = []
        observations: List[str] = []

        for iteration in range(self.max_iterations):
            # 构建本轮 prompt: system + 用户意图 + 历史观察 + 决策指令
            prompt = self._build_turn_prompt(system_prompt, user_intent, observations)

            action, error = self._get_action(llm, prompt, model)
            if error:
                logger.warning('LLM 规划器第 %d 轮调用失败: %s', iteration + 1, error)
                return tool_calls, results, None, f'LLM 调用失败: {error}'
            if action is None:
                logger.warning('LLM 规划器第 %d 轮输出无法解析', iteration + 1)
                return tool_calls, results, None, 'LLM 输出无法解析为有效动作'

            # 输出最终结论
            if action['type'] == 'final':
                return tool_calls, results, action.get('answer', ''), None

            # 调用工具
            tool_name = action['tool']
            if not self.registry.has(tool_name):
                logger.warning('LLM 规划器请求了不存在的工具: %s', tool_name)
                return tool_calls, results, None, f'LLM 请求了不存在的工具: {tool_name}'

            params = action.get('params') or {}
            if not isinstance(params, dict):
                params = {}
            # 强制注入 user_id, 不信任 LLM 传入的值
            params['user_id'] = user_id

            result = self.executor.execute(tool_name, **params)
            tool_calls.append({'tool': tool_name, 'params': params})
            results.append(result)
            observations.append(result.to_text())

            logger.info('LLM 规划器第 %d 轮执行工具 %s: %s',
                        iteration + 1, tool_name, 'OK' if result.success else 'FAIL')

        # 达到最大轮数仍未输出 final
        return tool_calls, results, None, f'达到最大迭代次数 ({self.max_iterations}) 仍未完成'

    # ==================== LLM 后端 ====================

    def _build_llm(self):
        """根据配置构建 LLM 后端 (与 AIService 保持一致的选择逻辑)"""
        try:
            from flask import current_app
            cfg = current_app.config
        except RuntimeError:
            cfg = {}

        mode = cfg.get('LLM_MODE', 'ollama')
        if mode == 'api':
            from app.services.openai_service import OpenAICompatibleService
            return OpenAICompatibleService(
                provider=cfg.get('LLM_API_PROVIDER', 'deepseek'),
                api_key=cfg.get('LLM_API_KEY', ''),
                base_url=cfg.get('LLM_API_BASE_URL', '') or None,
                model=cfg.get('LLM_API_MODEL', '') or None,
            )
        from app.services.ollama_service import OllamaService
        return OllamaService()

    # ==================== Prompt 构建 ====================

    def _build_system_prompt(self) -> str:
        """构建 system prompt, 包含可用工具 schema 和输出格式约束"""
        tools_desc = self._format_tools()
        return (
            '你是一个网络安全分析 Agent，负责根据用户意图，调用工具完成安全分析任务。\n\n'
            '## 可用工具\n'
            f'{tools_desc}\n\n'
            '## 输出格式\n'
            '每轮只输出一个 JSON 对象，不要输出任何其他文字、解释或 markdown 代码块：\n'
            '- 调用工具: {"action": "工具名", "params": {"参数名": "值", ...}}\n'
            '- 完成任务: {"action": "final", "answer": "最终分析总结"}\n\n'
            '## 规则\n'
            '1. 根据用户意图和已有工具结果，决定下一步调用哪个工具\n'
            '2. 工具执行结果会反馈给你，请据此调整后续步骤\n'
            '3. 当信息足够时，输出 final 给出总结\n'
            '4. user_id 参数会自动注入，无需填写\n'
            '5. 只调用与用户意图相关的工具，不要调用无关工具\n'
        )

    def _format_tools(self) -> str:
        """将工具 schema 格式化为可读文本"""
        lines = []
        for schema in self.registry.list_schemas():
            name = schema.get('name', '')
            desc = schema.get('description', '')
            params = schema.get('parameters', {})
            param_parts = []
            for pname, pdef in params.items():
                required = '必填' if pdef.get('required') else '可选'
                pdesc = pdef.get('description', '')
                param_parts.append(f'{pname}({required}: {pdesc})')
            param_text = ', '.join(param_parts) if param_parts else '无参数'
            lines.append(f'- {name}: {desc}\n  参数: {param_text}')
        return '\n'.join(lines)

    def _build_user_intent(self, target: str, experiment_id: int, scan_id: int) -> str:
        """构建用户意图描述"""
        parts = ['## 用户意图']
        if target:
            parts.append(f'- 扫描目标: {target}')
        if experiment_id:
            parts.append(f'- 实验ID: {experiment_id}')
        if scan_id:
            parts.append(f'- 扫描任务ID: {scan_id}')
        if not (target or experiment_id or scan_id):
            parts.append('- 无特定目标，请根据可用工具给出平台安全态势概览')
        return '\n'.join(parts)

    def _build_turn_prompt(self, system_prompt: str, user_intent: str,
                           observations: List[str]) -> str:
        """构建单轮决策 prompt"""
        parts = [system_prompt, user_intent]
        if observations:
            parts.append('\n## 已执行工具的结果')
            parts.extend(observations)
        parts.append('\n请决定下一步：调用工具或输出 final 结论。')
        return '\n\n'.join(parts)

    # ==================== 输出解析 ====================

    def _get_action(self, llm, prompt: str, model: str = None):
        """
        获取 LLM 决策动作, 优先使用结构化输出, 失败时降级到正则解析。

        :return: (action_dict, error)
                 - action_dict: {'type': 'tool'/'final', ...} 或 None (解析失败)
                 - error: 错误信息 (LLM 调用失败时非空)
        """
        # 1. 优先结构化输出 (后端原生 JSON 约束)
        if hasattr(llm, 'chat_structured'):
            parsed, err = llm.chat_structured(prompt, schema=self.PLANNER_SCHEMA, model=model)
            if err is None and isinstance(parsed, dict):
                action = self._parse_action_dict(parsed)
                if action is not None:
                    return action, None
            # 结构化输出失败, 降级到 chat + 正则

        # 2. 降级: 普通 chat + 正则解析
        text, err = llm.chat(prompt, model=model)
        if err:
            return None, err
        return self._parse_action(text), None

    @staticmethod
    def _parse_action_dict(parsed: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """从已解析的 dict 中提取动作 (供结构化输出使用)"""
        if not isinstance(parsed, dict):
            return None
        action = parsed.get('action', '')
        if not action:
            return None

        if action == 'final':
            answer = parsed.get('answer', '')
            return {'type': 'final', 'answer': str(answer)}

        params = parsed.get('params', {})
        if not isinstance(params, dict):
            params = {}
        return {'type': 'tool', 'tool': str(action), 'params': params}

    @staticmethod
    def _parse_action(text: str) -> Optional[Dict[str, Any]]:
        """
        解析 LLM 输出为动作字典。

        :return: {'type': 'tool', 'tool':..., 'params':...}
                 或 {'type': 'final', 'answer':...}
                 或 None (解析失败)
        """
        if not text:
            return None

        parsed = LLMPlanner._extract_json(text)
        if not parsed or not isinstance(parsed, dict):
            return None

        return LLMPlanner._parse_action_dict(parsed)

    @staticmethod
    def _extract_json(text: str) -> Optional[Any]:
        """从 LLM 输出中提取 JSON 对象 (容错处理)"""
        # 1. 直接解析
        try:
            return json.loads(text.strip())
        except (json.JSONDecodeError, ValueError):
            pass

        # 2. 提取 markdown 代码块中的 JSON
        m = re.search(r'```(?:json)?\s*([\s\S]*?)```', text)
        if m:
            try:
                return json.loads(m.group(1).strip())
            except (json.JSONDecodeError, ValueError):
                pass

        # 3. 提取第一个 {...} 块
        m = re.search(r'\{[\s\S]*\}', text)
        if m:
            try:
                return json.loads(m.group(0))
            except (json.JSONDecodeError, ValueError):
                pass

        return None
