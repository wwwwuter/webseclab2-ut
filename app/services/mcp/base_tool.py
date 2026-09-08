"""
MCP 工具基类模块
定义所有工具的接口规范和结果类型
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ToolResult:
    """工具执行结果"""
    # 是否执行成功
    success: bool = True

    # 结果数据 (字典, 便于 JSON 序列化)
    data: Dict[str, Any] = field(default_factory=dict)

    # 人类可读的结果摘要
    summary: str = ''

    # 错误信息 (失败时)
    error: str = ''

    # 执行耗时 (毫秒)
    elapsed_ms: int = 0

    def to_dict(self):
        """序列化为字典 (供 AI Prompt 使用)"""
        return {
            'success': self.success,
            'summary': self.summary,
            'data': self.data,
            'error': self.error if not self.success else '',
        }

    def to_text(self):
        """转换为可读文本 (供 AI Prompt 上下文)"""
        if self.success:
            return f"[{self.name}] {self.summary}\n{self._format_data()}"
        return f"[{self.name}] 执行失败: {self.error}"

    def _format_data(self):
        """格式化 data 为可读文本"""
        if not self.data:
            return ''
        import json
        return json.dumps(self.data, ensure_ascii=False, indent=2)

    # 子类可覆盖
    name: str = ''


class Tool(ABC):
    """
    MCP 工具基类

    每个工具实现一个具体能力:
    - ScannerTool: 端口扫描
    - NmapTool: Nmap 深度扫描
    - VerifyTool: 漏洞验证
    - KnowledgeTool: 知识库查询
    - ReportTool: 报告生成
    - DashboardTool: 数据统计
    - RiskTool: 风险评估
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """工具唯一名称"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """工具功能描述 (供 Planner 理解工具用途)"""
        pass

    @property
    def parameters(self) -> Dict[str, dict]:
        """
        工具参数定义 (JSON Schema 风格)
        供 Planner 理解如何调用工具
        """
        return {}

    @abstractmethod
    def execute(self, **kwargs) -> ToolResult:
        """
        执行工具

        :param kwargs: 工具参数 (由 parameters 定义)
        :return: ToolResult 实例
        """
        pass

    def validate_params(self, **kwargs) -> Optional[str]:
        """
        验证参数合法性
        :return: 错误信息 或 None
        """
        for param_name, param_def in self.parameters.items():
            if param_def.get('required') and param_name not in kwargs:
                return f'缺少必需参数: {param_name}'
        return None

    def schema(self) -> dict:
        """返回工具 schema (供 AI 理解可用工具)"""
        return {
            'name': self.name,
            'description': self.description,
            'parameters': self.parameters,
        }
