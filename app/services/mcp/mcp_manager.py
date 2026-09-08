"""
MCP 管理器模块
按固定顺序编排 AI 安全分析工具链，并将结果聚合为分析报告。

说明:
  本模块不实现 LLM 规划器。execute_analysis_plan 按预设顺序
  (Scanner → Knowledge → Risk → Dashboard) 依次调用工具并聚合结果。

核心流程:
  用户请求 → 按预设工具链依次执行 (ToolExecutor)
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

        按固定预设顺序编排工具链 (非 LLM 动态规划):
        1. Scanner / NmapTool → 获取端口信息
        2. KnowledgeTool → 查询漏洞知识库
        3. RiskTool → 计算风险评估
        4. DashboardTool → 获取统计数据
        5. ReportTool → 生成分析摘要

        :param user_id: 用户ID
        :param target: 扫描目标 (IP/域名)
        :param experiment_id: 实验ID (可选)
        :param scan_id: 扫描任务ID (可选)
        :return: 综合分析结果
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
            'tools_executed': tool_chain,
            'results': {k: v.to_dict() for k, v in results.items()},
            'summary': summary,
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
