"""
MCP 管理器模块
编排 AI 安全分析工具链，并将结果聚合为分析报告。

说明:
  本模块优先使用 LLM 动态规划器 (ReAct 循环) 根据用户意图动态选择工具;
  当 LLM 不可用或规划失败时, 自动回退到固定预设顺序
  (Scanner → Knowledge → Risk → Dashboard) 保证功能可用。

核心流程:
  用户请求 → LLM 动态规划 (ReAct) → 按规划执行工具
           → (失败时) 回退固定工具链
           → 结果聚合为分析报告
           → 返回给用户
"""

import json
import logging
from typing import Dict, Any, List
from app.services.mcp.tool_registry import ToolRegistry, register_all_tools
from app.services.mcp.tool_executor import ToolExecutor
from app.services.mcp.base_tool import ToolResult

logger = logging.getLogger(__name__)


class MCPManager:
    """MCP 工具编排管理器"""

    def __init__(self):
        self.registry = register_all_tools()
        self.executor = ToolExecutor(self.registry)
        self._planner = None

    @property
    def planner(self):
        """惰性初始化 LLM 规划器 (避免循环导入)"""
        if self._planner is None:
            from app.services.mcp.llm_planner import LLMPlanner
            self._planner = LLMPlanner(self.registry, self.executor)
        return self._planner

    def get_available_tools(self) -> List[dict]:
        """获取所有可用工具的 schema"""
        return self.registry.list_schemas()

    def execute_tool(self, tool_name: str, **kwargs) -> ToolResult:
        """执行单个工具"""
        return self.executor.execute(tool_name, **kwargs)

    def execute_analysis_plan(self, user_id: int, target: str = '',
                             experiment_id: int = None,
                             scan_id: int = None) -> Dict[str, Any]:
        """
        执行完整的安全分析计划

        优先使用 LLM 动态规划 (ReAct 循环) 根据用户意图选择工具;
        当 LLM 不可用或规划失败时, 自动回退到固定预设顺序工具链。

        :param user_id: 用户ID
        :param target: 扫描目标 (IP/域名)
        :param experiment_id: 实验ID (可选)
        :param scan_id: 扫描任务ID (可选)
        :return: 综合分析结果
        """
        # Step 1: 尝试 LLM 动态规划
        tool_calls, results, final_answer, planning_error = self.planner.plan(
            user_id=user_id,
            target=target,
            experiment_id=experiment_id,
            scan_id=scan_id,
        )

        if planning_error is None:
            return self._build_plan_result(
                tool_calls, results, final_answer,
                planner='react',
            )

        # Step 2: 回退固定工具链
        logger.warning('LLM 规划失败, 回退固定工具链: %s', planning_error)
        return self._execute_fixed_chain(
            user_id, target, experiment_id, scan_id,
            planning_error=planning_error,
        )

    def _execute_fixed_chain(self, user_id: int, target: str,
                             experiment_id: int, scan_id: int,
                             planning_error: str = None) -> Dict[str, Any]:
        """
        固定预设顺序工具链 (回退方案):
        1. Scanner → 获取端口信息
        2. Knowledge → 查询漏洞知识库
        3. Risk → 计算风险评估
        4. Dashboard → 获取统计数据
        """
        results = {}
        tool_chain = []

        # Step 1: 扫描 (如果有目标地址)
        if target:
            result = self.executor.execute('scanner', target=target, user_id=user_id)
            results['scanner'] = result
            tool_chain.append('scanner')

        # Step 2: 知识库查询
        if experiment_id:
            result = self.executor.execute(
                'knowledge', experiment_id=experiment_id, user_id=user_id
            )
            results['knowledge'] = result
            tool_chain.append('knowledge')

        # Step 3: 风险评估
        if experiment_id:
            result = self.executor.execute(
                'risk', experiment_id=experiment_id, user_id=user_id
            )
            results['risk'] = result
            tool_chain.append('risk')
        elif scan_id:
            result = self.executor.execute(
                'risk', scan_id=scan_id, user_id=user_id
            )
            results['risk'] = result
            tool_chain.append('risk')

        # Step 4: Dashboard 统计
        result = self.executor.execute('dashboard', user_id=user_id)
        results['dashboard'] = result
        tool_chain.append('dashboard')

        # 聚合结果
        summary = self._aggregate_results(results, tool_chain)

        return {
            'success': True,
            'planner': 'fallback',
            'planning_error': planning_error,
            'tools_executed': tool_chain,
            'results': {k: v.to_dict() for k, v in results.items()},
            'summary': summary,
            'final_answer': None,
            'execution_log': self.executor.execution_log,
        }

    def _build_plan_result(self, tool_calls: List[Dict[str, Any]],
                           results: List[ToolResult],
                           final_answer: str,
                           planner: str) -> Dict[str, Any]:
        """构建 LLM 规划的执行结果 (处理可能的重复工具名)"""
        tool_chain = [call['tool'] for call in tool_calls]

        # 用唯一 key 构建 results 字典 (同名工具多次调用时加序号)
        results_dict: Dict[str, ToolResult] = {}
        for i, result in enumerate(results):
            name = tool_chain[i]
            key = name if name not in results_dict else f'{name}_{i}'
            results_dict[key] = result

        summary = self._aggregate_results(results_dict, list(results_dict.keys()))
        if final_answer:
            summary += f'\n\n## AI 规划总结\n{final_answer}'

        return {
            'success': True,
            'planner': planner,
            'planning_error': None,
            'tools_executed': tool_chain,
            'results': {k: v.to_dict() for k, v in results_dict.items()},
            'summary': summary,
            'final_answer': final_answer,
            'execution_log': self.executor.execution_log,
        }

    def _aggregate_results(self, results: Dict[str, ToolResult],
                           tool_chain: List[str]) -> str:
        """聚合多个工具结果为可读摘要"""
        parts = ['## AI 安全分析工具链执行报告\n']
        parts.append(f'执行工具: {" → ".join(tool_chain)}\n')

        for name in tool_chain:
            result = results.get(name)
            if not result:
                continue

            if result.success:
                parts.append(f'### {name} ✓\n{result.summary}\n')
            else:
                parts.append(f'### {name} ✗\n执行失败: {result.error}\n')

        # 最终统计
        success_count = sum(1 for r in results.values() if r.success)
        parts.append(f'\n---\n成功: {success_count}/{len(results)}')

        return '\n'.join(parts)
