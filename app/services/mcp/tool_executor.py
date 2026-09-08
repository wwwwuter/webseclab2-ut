"""
工具执行器模块
负责安全地执行工具, 记录执行日志, 处理异常
"""

import time
import logging
from typing import List, Dict, Any
from app.services.mcp.base_tool import Tool, ToolResult
from app.services.mcp.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


class ToolExecutor:
    """工具执行引擎"""

    def __init__(self, registry: ToolRegistry = None):
        self.registry = registry or ToolRegistry()
        self.execution_log: List[Dict[str, Any]] = []

    def execute(self, tool_name: str, **kwargs) -> ToolResult:
        """
        执行单个工具

        :param tool_name: 工具名称
        :param kwargs: 工具参数
        :return: ToolResult
        """
        tool = self.registry.get(tool_name)
        if not tool:
            return ToolResult(
                success=False,
                error=f'工具不存在: {tool_name}',
                name=tool_name,
            )

        # 参数验证
        error = tool.validate_params(**kwargs)
        if error:
            return ToolResult(
                success=False,
                error=f'参数验证失败: {error}',
                name=tool_name,
            )

        # 执行
        start = time.time()
        try:
            result = tool.execute(**kwargs)
            result.name = tool_name
            result.elapsed_ms = int((time.time() - start) * 1000)
        except Exception as e:
            logger.error(f'工具执行异常 [{tool_name}]: {e}', exc_info=True)
            result = ToolResult(
                success=False,
                error=f'执行异常: {str(e)}',
                elapsed_ms=int((time.time() - start) * 1000),
                name=tool_name,
            )

        # 记录执行日志
        self.execution_log.append({
            'tool': tool_name,
            'params': kwargs,
            'success': result.success,
            'elapsed_ms': result.elapsed_ms,
            'summary': result.summary[:200],
        })

        logger.info(f'工具执行 [{tool_name}]: {"OK" if result.success else "FAIL"} '
                     f'({result.elapsed_ms}ms)')
        return result

    def execute_chain(self, tool_calls: List[Dict[str, Any]]) -> List[ToolResult]:
        """
        按顺序执行工具链

        :param tool_calls: [{'tool': 'scanner', 'params': {...}}, ...]
        :return: ToolResult 列表
        """
        results = []
        for call in tool_calls:
            tool_name = call.get('tool', '')
            params = call.get('params', {})
            result = self.execute(tool_name, **params)
            results.append(result)

            # 如果某个关键工具失败, 可选择终止链
            if not result.success and call.get('critical', False):
                logger.warning(f'关键工具 {tool_name} 失败, 终止工具链')
                break

        return results

    def get_execution_summary(self) -> str:
        """获取执行摘要"""
        if not self.execution_log:
            return '无工具执行记录'

        lines = ['工具执行摘要:']
        for entry in self.execution_log:
            status = '✓' if entry['success'] else '✗'
            lines.append(
                f'  {status} {entry["tool"]} ({entry["elapsed_ms"]}ms): {entry["summary"]}'
            )
        return '\n'.join(lines)
