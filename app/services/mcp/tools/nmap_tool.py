"""
Nmap 深度扫描工具
调用 ScannerService 创建 Nmap 扫描任务
"""

from app.services.mcp.base_tool import Tool, ToolResult


class NmapTool(Tool):

    @property
    def name(self):
        return 'nmap'

    @property
    def description(self):
        return '使用 Nmap 创建深度端口扫描任务, 获取详细的服务版本和操作系统信息 (异步执行)'

    @property
    def parameters(self):
        return {
            'target': {'type': 'string', 'required': True, 'description': '扫描目标 IP 或域名'},
            'user_id': {'type': 'integer', 'required': True, 'description': '用户ID'},
        }

    def execute(self, **kwargs):
        target = kwargs.get('target', '')
        user_id = kwargs.get('user_id')

        if not target:
            return ToolResult(success=False, error='缺少扫描目标', name=self.name)

        try:
            from app.services.scanner_service import ScannerService
            scanner = ScannerService()

            task, error = scanner.create_task(
                user_id=user_id,
                target=target,
                scan_type='nmap',
                port_range='common',
            )

            if error:
                return ToolResult(success=False, error=error, name=self.name)

            success, dispatch_error = scanner.dispatch_task(task.id)
            if not success:
                return ToolResult(success=False, error=dispatch_error, name=self.name)

            # 查询同目标的 Nmap 历史已完成扫描结果
            from app.models.scan import ScanTask, ScanResult as SR
            completed = ScanTask.query.filter_by(
                user_id=user_id, target=target,
                scan_type='nmap', status='completed'
            ).order_by(ScanTask.created_time.desc()).first()

            if completed:
                results = SR.query.filter_by(task_id=completed.id, state='open').all()
                ports = [{'port': r.port, 'service': r.service, 'version': r.version} for r in results]
                return ToolResult(
                    success=True,
                    data={
                        'task_id': task.id, 'target': target,
                        'scanner': 'nmap', 'status': 'dispatched',
                        'latest_completed': {
                            'task_id': completed.id, 'open_ports': len(ports), 'ports': ports,
                        },
                    },
                    summary=f'Nmap扫描 #{task.id} 已派发; 历史: {target} 有 {len(ports)} 个开放端口',
                    name=self.name,
                )

            return ToolResult(
                success=True,
                data={'task_id': task.id, 'target': target, 'scanner': 'nmap', 'status': 'dispatched'},
                summary=f'Nmap扫描任务 #{task.id} 已派发, 目标: {target}',
                name=self.name,
            )

        except Exception as e:
            return ToolResult(success=False, error=str(e), name=self.name)
