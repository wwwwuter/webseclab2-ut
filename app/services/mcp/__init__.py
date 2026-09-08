"""
MCP (Model Context Protocol) 工具调用框架
实现 AI Agent 主动调用平台工具的能力

核心组件:
- Tool: 工具基类 (name, description, execute)
- ToolRegistry: 工具注册与发现
- ToolExecutor: 工具执行引擎
- MCPManager: AI 工具链编排管理器

设计原则:
- 每个工具职责单一, 接口统一
- Planner 根据用户意图自动选择工具组合
- 工具执行结果自动聚合为最终分析报告
"""

from app.services.mcp.base_tool import Tool, ToolResult
from app.services.mcp.tool_registry import ToolRegistry
from app.services.mcp.tool_executor import ToolExecutor
from app.services.mcp.mcp_manager import MCPManager

__all__ = ['Tool', 'ToolResult', 'ToolRegistry', 'ToolExecutor', 'MCPManager']
