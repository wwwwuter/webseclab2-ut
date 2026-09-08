"""
漏洞知识库查询工具
查询漏洞分类、OWASP关联、修复方案等知识
"""

from app.services.mcp.base_tool import Tool, ToolResult


class KnowledgeTool(Tool):

    @property
    def name(self):
        return 'knowledge'

    @property
    def description(self):
        return '查询漏洞知识库, 获取漏洞分类、OWASP关联、攻击方式和修复方案等安全知识'

    @property
    def parameters(self):
        return {
            'keyword': {'type': 'string', 'required': False, 'description': '搜索关键词'},
            'category': {'type': 'string', 'required': False, 'description': '漏洞分类名称'},
            'experiment_id': {'type': 'integer', 'required': False, 'description': '关联实验ID'},
            'user_id': {'type': 'integer', 'required': True, 'description': '用户ID'},
        }

    def execute(self, **kwargs):
        keyword = kwargs.get('keyword', '')
        category = kwargs.get('category', '')
        experiment_id = kwargs.get('experiment_id')

        try:
            from app.services.vulnerability_service import VulnerabilityService

            # 通过实验ID关联查找漏洞
            if experiment_id:
                from app.models.experiment import Experiment
                from app.extensions import db
                exp = db.session.get(Experiment, experiment_id)
                if exp and exp.vulnerability_id:
                    vuln = VulnerabilityService.get_vulnerability_by_id(exp.vulnerability_id)
                    if vuln:
                        return self._format_vuln_result(vuln)

            # 关键词搜索
            if keyword:
                pagination = VulnerabilityService.search_vulnerabilities(keyword, page=1, per_page=5)
                vulns = pagination.items
                if vulns:
                    items = [self._vuln_to_dict(v) for v in vulns]
                    return ToolResult(
                        success=True,
                        data={'count': len(items), 'vulnerabilities': items},
                        summary=f'搜索 "{keyword}" 找到 {pagination.total} 条漏洞记录',
                        name=self.name,
                    )

            # 分类筛选
            if category:
                categories = VulnerabilityService.get_all_categories()
                cat_obj = next((c for c in categories if c.name == category), None)
                if cat_obj:
                    pagination = VulnerabilityService.get_vulnerabilities_by_category(cat_obj.id, page=1, per_page=5)
                    items = [self._vuln_to_dict(v) for v in pagination.items]
                    return ToolResult(
                        success=True,
                        data={'category': category, 'count': len(items), 'vulnerabilities': items},
                        summary=f'分类 "{category}" 下有 {pagination.total} 条漏洞',
                        name=self.name,
                    )

            # 默认: 返回统计信息
            stats = VulnerabilityService.get_statistics()
            return ToolResult(
                success=True,
                data={'statistics': stats},
                summary=f'知识库共有 {stats.get("total", 0)} 条漏洞记录',
                name=self.name,
            )

        except Exception as e:
            return ToolResult(success=False, error=str(e), name=self.name)

    def _format_vuln_result(self, vuln):
        """格式化单个漏洞为 ToolResult"""
        data = self._vuln_to_dict(vuln)
        return ToolResult(
            success=True,
            data=data,
            summary=f'漏洞: {vuln.name} [{vuln.severity}] - {vuln.description[:100] if vuln.description else ""}',
            name=self.name,
        )

    @staticmethod
    def _vuln_to_dict(vuln):
        return {
            'id': vuln.id,
            'name': vuln.name,
            'severity': vuln.severity,
            'category': vuln.category.name if vuln.category else '',
            'cve': vuln.cve,
            'description': (vuln.description or '')[:300],
            'attack_method': (vuln.attack_method or '')[:200],
            'solution': (vuln.solution or '')[:200],
        }
