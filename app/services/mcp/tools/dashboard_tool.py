"""
Dashboard 统计工具
获取平台或用户的统计数据
"""

from app.services.mcp.base_tool import Tool, ToolResult


class DashboardTool(Tool):

    @property
    def name(self):
        return 'dashboard'

    @property
    def description(self):
        return '获取安全态势统计数据, 包括实验/扫描/AI分析/风险评估的数量和分布'

    @property
    def parameters(self):
        return {
            'user_id': {'type': 'integer', 'required': True, 'description': '用户ID'},
        }

    def execute(self, **kwargs):
        user_id = kwargs.get('user_id')

        try:
            from app.services.dashboard_service import DashboardService
            svc = DashboardService()
            data = svc.get_user_dashboard(user_id)

            stats = data.get('user_stats', {})
            exp_stats = data.get('experiment_stats', {})
            scan_stats = data.get('scan_stats', {})
            ai_stats = data.get('ai_stats', {})
            risk_stats = data.get('risk_stats', {})

            return ToolResult(
                success=True,
                data={
                    'experiments': stats.get('experiment_count', 0),
                    'scans': stats.get('scan_count', 0),
                    'ai_analyses': stats.get('ai_count', 0),
                    'reports': stats.get('report_count', 0),
                    'experiment_breakdown': exp_stats,
                    'scan_breakdown': scan_stats,
                    'risk_assessments': risk_stats,
                },
                summary=(
                    f'用户统计: {stats.get("experiment_count", 0)}个实验, '
                    f'{stats.get("scan_count", 0)}次扫描, '
                    f'{stats.get("ai_count", 0)}次AI分析'
                ),
                name=self.name,
            )

        except Exception as e:
            return ToolResult(success=False, error=str(e), name=self.name)
