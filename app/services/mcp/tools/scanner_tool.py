"""
Socket 端口扫描工具
调用 ScannerService 创建并执行 Socket 扫描任务
"""

from app.services.mcp.base_tool import Tool, ToolResult


class ScannerTool(Tool):

    @property
    def name(self):
        return 'scanner'

    @property
    def description(self):
        return '创建 Socket 端口扫描任务, 发现目标主机的开放端口和服务信息 (异步执行)'

    @property
    def parameters(self):
        return {
            'target': {'type': 'string', 'required': True, 'description': '扫描目标 IP 或域名'},
            'port_range': {'type': 'string', 'required': False, 'description': '端口范围, 默认 common'},
            'scan_type': {'type': 'string', 'required': False, 'description': '扫描方式: socket / nmap / both, 默认 socket'},
            'user_id': {'type': 'integer', 'required': True, 'description': '用户ID'},
        }

    def execute(self, **kwargs):
        target = kwargs.get('target', '')
        user_id = kwargs.get('user_id')
        port_range = kwargs.get('port_range', 'common')
        scan_type = kwargs.get('scan_type', 'socket')

        if not target:
            return ToolResult(success=False, error='缺少扫描目标', name=self.name)

        try:
            from app.services.scanner_service import ScannerService
            scanner = ScannerService()

            # 创建扫描任务 (返回 tuple: task, error)
            task, error = scanner.create_task(
                user_id=user_id,
                target=target,
                scan_type=scan_type,
                port_range=port_range,
            )

            if error:
                return ToolResult(success=False, error=error, name=self.name)

            # 异步派发
            success, dispatch_error = scanner.dispatch_task(task.id)
            if not success:
                return ToolResult(success=False, error=dispatch_error, name=self.name)

            # 查询同目标的同类型历史已完成扫描结果
            from app.models.scan import ScanTask, ScanResult as SR
            from app.extensions import db
            completed = ScanTask.query.filter_by(
                user_id=user_id, target=target,
                scan_type=scan_type, status='completed'
            ).order_by(ScanTask.created_time.desc()).first()

            if completed:
                results = SR.query.filter_by(task_id=completed.id, state='open').all()
                ports = [{'port': r.port, 'service': r.service, 'version': r.version} for r in results]
                return ToolResult(
                    success=True,
                    data={'task_id': task.id, 'target': target, 'scan_type': scan_type,
                          'status': 'dispatched',
                          'latest_completed': {'task_id': completed.id, 'open_ports': len(ports), 'ports': ports}},
                    summary=f'扫描任务 #{task.id} ({scan_type}) 已派发; 历史结果: {target} 有 {len(ports)} 个开放端口',
                    name=self.name,
                )

            return ToolResult(
                success=True,
                data={'task_id': task.id, 'target': target, 'scan_type': scan_type, 'status': 'dispatched'},
                summary=f'扫描任务 #{task.id} ({scan_type}) 已派发, 目标: {target} (异步执行中)',
                name=self.name,
            )

        except Exception as e:
            return ToolResult(success=False, error=str(e), name=self.name)
