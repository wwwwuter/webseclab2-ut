"""
报告生成工具
基于实验/扫描数据生成分析报告摘要
"""

from app.services.mcp.base_tool import Tool, ToolResult


class ReportTool(Tool):

    @property
    def name(self):
        return 'report'

    @property
    def description(self):
        return '基于实验数据和扫描结果生成安全分析报告摘要'

    @property
    def parameters(self):
        return {
            'experiment_id': {'type': 'integer', 'required': False, 'description': '实验ID'},
            'scan_id': {'type': 'integer', 'required': False, 'description': '扫描任务ID'},
            'user_id': {'type': 'integer', 'required': True, 'description': '用户ID'},
        }

    def execute(self, **kwargs):
        experiment_id = kwargs.get('experiment_id')
        scan_id = kwargs.get('scan_id')
        user_id = kwargs.get('user_id')

        try:
            report_data = {'sections': []}

            # 实验信息
            if experiment_id:
                from app.models.experiment import Experiment
                from app.extensions import db
                exp = db.session.get(Experiment, experiment_id)
                if exp and exp.is_owner(user_id):
                    report_data['sections'].append({
                        'title': '实验信息',
                        'content': f'实验名称: {exp.experiment_name}\n'
                                   f'目标: {exp.target}\n'
                                   f'DVWA等级: {exp.dvwa_level}\n'
                                   f'状态: {exp.status_label}',
                    })

            # 扫描信息
            if scan_id:
                from app.models.scan import ScanTask, ScanResult
                from app.extensions import db
                task = db.session.get(ScanTask, scan_id)
                if task and task.is_owner(user_id):
                    results = ScanResult.query.filter_by(
                        task_id=scan_id, state='open'
                    ).all()
                    ports_text = '\n'.join(
                        f'  {r.port}/{r.protocol} {r.service} {r.version}'
                        for r in results
                    ) or '  无开放端口'
                    report_data['sections'].append({
                        'title': '扫描结果',
                        'content': f'目标: {task.target}\n'
                                   f'扫描类型: {task.scan_type_label}\n'
                                   f'开放端口: {len(results)}\n{ports_text}',
                    })

            # AI 分析摘要
            if experiment_id:
                from app.models.ai_analysis import AIAnalysis
                latest_ai = AIAnalysis.query.filter_by(
                    experiment_id=experiment_id, status='completed'
                ).order_by(AIAnalysis.created_time.desc()).first()
                if latest_ai:
                    report_data['sections'].append({
                        'title': 'AI分析摘要',
                        'content': f'风险等级: {latest_ai.risk_label}\n'
                                   f'漏洞分析: {(latest_ai.vulnerability_analysis or "")[:200]}\n'
                                   f'修复建议: {(latest_ai.fix_solution or "")[:200]}',
                    })

            summary_parts = [s['title'] for s in report_data['sections']]
            return ToolResult(
                success=True,
                data=report_data,
                summary=f'报告摘要包含: {", ".join(summary_parts)}',
                name=self.name,
            )

        except Exception as e:
            return ToolResult(success=False, error=str(e), name=self.name)
