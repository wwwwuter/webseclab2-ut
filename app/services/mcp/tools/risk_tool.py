"""
风险评估工具
调用 RiskEngine 进行多因素风险评估
"""

from app.services.mcp.base_tool import Tool, ToolResult


class RiskTool(Tool):

    @property
    def name(self):
        return 'risk'

    @property
    def description(self):
        return '执行多因素风险评估, 综合 CVSS/资产/利用/暴露/AI 五个维度计算风险评分'

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
            from app.services.risk_service import RiskEngine
            engine = RiskEngine()

            assessment = None
            if experiment_id:
                assessment, error = engine.assess_from_experiment(experiment_id, user_id)
            elif scan_id:
                assessment, error = engine.assess_from_scan(scan_id, user_id)
            else:
                return ToolResult(
                    success=False,
                    error='需要提供 experiment_id 或 scan_id',
                    name=self.name,
                )

            if error:
                return ToolResult(success=False, error=error, name=self.name)

            return ToolResult(
                success=True,
                data={
                    'final_score': assessment.final_score,
                    'risk_level': assessment.risk_level,
                    'risk_label': assessment.risk_label,
                    'cvss': assessment.cvss_score,
                    'asset': assessment.asset_score,
                    'exploit': assessment.exploit_score,
                    'exposure': assessment.exposure_score,
                    'ai_confidence': assessment.ai_score,
                },
                summary=(
                    f'风险评分: {assessment.final_score:.1f} ({assessment.risk_label}) '
                    f'[CVSS={assessment.cvss_score:.1f}, '
                    f'资产={assessment.asset_score:.1f}, '
                    f'利用={assessment.exploit_score:.1f}, '
                    f'暴露={assessment.exposure_score:.1f}, '
                    f'AI={assessment.ai_score:.1f}]'
                ),
                name=self.name,
            )

        except Exception as e:
            return ToolResult(success=False, error=str(e), name=self.name)
