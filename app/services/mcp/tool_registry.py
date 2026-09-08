"""
工具注册表模块
管理所有 MCP 工具的注册、发现和查询
"""

import logging
from typing import Dict, List, Optional
from app.services.mcp.base_tool import Tool

logger = logging.getLogger(__name__)


class ToolRegistry:
    """工具注册表 (单例模式, 全局共享)"""

    _instance = None
    _tools: Dict[str, Tool] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._tools = {}
        return cls._instance

    def register(self, tool: Tool):
        """注册一个工具"""
        self._tools[tool.name] = tool
        logger.info(f'MCP: 注册工具 {tool.name}')

    def get(self, name: str) -> Optional[Tool]:
        """根据名称获取工具"""
        return self._tools.get(name)

    def list_tools(self) -> List[Tool]:
        """列出所有已注册工具"""
        return list(self._tools.values())

    def list_schemas(self) -> List[dict]:
        """列出所有工具的 schema (供 AI Planner 使用)"""
        return [tool.schema() for tool in self._tools.values()]

    def has(self, name: str) -> bool:
        """检查工具是否已注册"""
        return name in self._tools

    @classmethod
    def reset(cls):
        """重置注册表 (测试用)"""
        cls._instance = None
        cls._tools = {}


def register_all_tools():
    """注册所有内置工具"""
    registry = ToolRegistry()

    from app.services.mcp.tools.scanner_tool import ScannerTool
    from app.services.mcp.tools.nmap_tool import NmapTool
    from app.services.mcp.tools.knowledge_tool import KnowledgeTool
    from app.services.mcp.tools.report_tool import ReportTool
    from app.services.mcp.tools.dashboard_tool import DashboardTool
    from app.services.mcp.tools.risk_tool import RiskTool

    tools = [
        ScannerTool(),
        NmapTool(),
        KnowledgeTool(),
        ReportTool(),
        DashboardTool(),
        RiskTool(),
    ]

    for tool in tools:
        registry.register(tool)

    logger.info(f'MCP: 已注册 {len(tools)} 个工具')
    return registry
