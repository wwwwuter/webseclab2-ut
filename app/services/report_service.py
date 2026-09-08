"""
报告管理服务模块
封装报告创建、查询、下载、删除等业务逻辑
支持实验报告 (PDF) 和 MCP 分析报告 (PDF/Markdown/JSON)
"""

import os
import json
import secrets
from datetime import datetime
from app.extensions import db
from app.models.report import Report
from app.models.user import User
from app.models.experiment import Experiment
from app.models.scan import ScanTask, ScanResult
from app.models.vulnerability import Vulnerability
from app.models.ai_analysis import AIAnalysis
from app.utils.pdf_generator import PDFGenerator


class ReportService:
    """报告管理服务类"""

    def __init__(self, output_dir=None):
        if output_dir is None:
            output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'reports')
        self.output_dir = output_dir
        self.pdf_gen = PDFGenerator(output_dir=output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

    def create_experiment_report(self, user_id, experiment_id):
        """
        基于实验生成完整报告
        :param user_id: 用户ID
        :param experiment_id: 实验ID
        :return: (Report对象, 错误信息)
        """
        experiment = db.session.get(Experiment, experiment_id)
        if not experiment:
            return None, '实验不存在'
        if not experiment.is_owner(user_id):
            return None, '无权为该实验生成报告'

        user = db.session.get(User, user_id)

        # 获取关联漏洞
        vulnerability = None
        if experiment.vulnerability_id:
            vulnerability = db.session.get(Vulnerability, experiment.vulnerability_id)

        # 获取扫描结果
        scan_results = None
        latest_task = ScanTask.query.filter_by(
            experiment_id=experiment_id
        ).order_by(ScanTask.created_time.desc()).first()
        if latest_task:
            scan_results = ScanResult.query.filter_by(
                task_id=latest_task.id
            ).order_by(ScanResult.port).all()

        # 获取AI分析
        ai_analysis = AIAnalysis.query.filter_by(
            experiment_id=experiment_id
        ).order_by(AIAnalysis.created_time.desc()).first()

        # 生成PDF
        title = f'{experiment.experiment_name} - 安全实验报告'
        filename, file_size, error = self.pdf_gen.generate_experiment_report(
            experiment=experiment,
            vulnerability=vulnerability,
            scan_results=scan_results,
            ai_analysis=ai_analysis,
            user=user
        )

        if error:
            report = Report(
                user_id=user_id,
                experiment_id=experiment_id,
                title=title,
                status=Report.STATUS_FAILED,
                error_message=error
            )
            db.session.add(report)
            db.session.commit()
            return report, error

        # 保存报告记录
        report = Report(
            user_id=user_id,
            experiment_id=experiment_id,
            title=title,
            description=self._build_description(experiment, vulnerability, scan_results, ai_analysis),
            file_path=filename,
            file_size=file_size,
            status=Report.STATUS_GENERATED
        )
        db.session.add(report)
        db.session.commit()

        return report, None

    # ==================== MCP 报告接口 ====================

    def create_mcp_report(self, user_id, plan_data, report_format='pdf'):
        """
        基于 MCP 分析数据创建报告 (PDF/Markdown/JSON)
        :param user_id: 用户ID
        :param plan_data: MCP 分析结果字典
        :param report_format: 'pdf' / 'md' / 'json'
        :return: (Report对象, 错误信息)
        """
        type_map = {
            'pdf': Report.TYPE_MCP_PDF,
            'md': Report.TYPE_MCP_MD,
            'json': Report.TYPE_MCP_JSON,
        }
        report_type = type_map.get(report_format)
        if not report_type:
            return None, f'不支持的报告格式: {report_format}'

        query = plan_data.get('query', 'AI 安全分析')
        title = f'MCP 分析报告 - {query[:30]}'
        description = self._build_mcp_description(plan_data)
        random_suffix = secrets.token_hex(4)

        try:
            if report_format == 'pdf':
                filename, file_size, error = self.pdf_gen.generate_mcp_report(
                    plan_data, user=db.session.get(User, user_id)
                )
                if error:
                    report = Report(
                        user_id=user_id, title=title,
                        report_type=report_type,
                        status=Report.STATUS_FAILED,
                        error_message=error,
                    )
                    db.session.add(report)
                    db.session.commit()
                    return report, error
            elif report_format == 'md':
                content = self._generate_mcp_markdown(plan_data)
                filename = f'mcp_report_{random_suffix}.md'
                filepath = os.path.join(self.output_dir, filename)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                file_size = os.path.getsize(filepath)
            else:  # json
                content = self._generate_mcp_json(plan_data)
                filename = f'mcp_report_{random_suffix}.json'
                filepath = os.path.join(self.output_dir, filename)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                file_size = os.path.getsize(filepath)

            report = Report(
                user_id=user_id,
                title=title,
                description=description,
                file_path=filename,
                file_size=file_size,
                status=Report.STATUS_GENERATED,
                report_type=report_type,
            )
            db.session.add(report)
            db.session.commit()
            return report, None

        except Exception as e:
            return None, f'报告生成失败: {str(e)}'

    def _generate_mcp_markdown(self, plan_data):
        """生成 Markdown 格式的 MCP 分析报告"""
        lines = []
        query = plan_data.get('query', 'AI 安全分析')
        tools = plan_data.get('tools_executed') or plan_data.get('planned_tools') or []
        results = plan_data.get('results', {})
        summary = plan_data.get('summary', '')

        lines.append('# AI 安全分析报告')
        lines.append('')
        lines.append(f'> **分析请求**: {query}')
        lines.append(f'> **生成时间**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        lines.append(f'> **执行工具**: {" → ".join(tools) if tools else "无"}')
        lines.append('')

        if summary:
            lines.append('## 分析摘要')
            lines.append('')
            lines.append(summary)
            lines.append('')

        lines.append('---')
        lines.append('')

        # 按工具逐一输出结果
        for name in tools:
            r = results.get(name, {})
            lines.append(f'## {name.capitalize()}')
            lines.append('')
            status = '✅ 成功' if r.get('success') else '❌ 失败'
            lines.append(f'**状态**: {status}')
            if r.get('summary'):
                lines.append(f'**摘要**: {r["summary"]}')
            if r.get('elapsed_ms'):
                lines.append(f'**耗时**: {r["elapsed_ms"]}ms')
            lines.append('')

            data = r.get('data', {})
            if data:
                # 针对各工具类型做格式化输出
                if name == 'risk' and r.get('success'):
                    lines.append(f'| 指标 | 值 |')
                    lines.append(f'|------|------|')
                    lines.append(f'| 综合评分 | {data.get("final_score", 0)} / 100 |')
                    lines.append(f'| 风险等级 | {data.get("risk_label", "-")} |')
                    lines.append(f'| CVSS | {data.get("cvss", 0)} |')
                    lines.append(f'| 资产价值 | {data.get("asset", 0)} |')
                    lines.append(f'| 利用难度 | {data.get("exploit", 0)} |')
                    lines.append(f'| 暴露面 | {data.get("exposure", 0)} |')
                    lines.append(f'| AI 置信度 | {data.get("ai_confidence", 0)} |')
                    lines.append('')
                elif name == 'scanner' and data.get('latest_completed'):
                    ports = data['latest_completed'].get('ports', [])
                    if ports:
                        lines.append('| 端口 | 服务 | 版本 |')
                        lines.append('|------|------|------|')
                        for p in ports:
                            lines.append(f'| {p.get("port", "-")} | {p.get("service", "-")} | {p.get("version", "-")} |')
                        lines.append('')
                elif name == 'knowledge':
                    vulns = data.get('vulnerabilities', [])
                    if not vulns and data.get('name'):
                        vulns = [data]
                    for v in vulns:
                        lines.append(f'### {v.get("name", "未知漏洞")}')
                        lines.append('')
                        lines.append(f'- **严重程度**: {v.get("severity", "-")}')
                        lines.append(f'- **CVE**: {v.get("cve", "-")}')
                        if v.get('description'):
                            lines.append(f'- **描述**: {v["description"][:200]}')
                        if v.get('solution'):
                            lines.append(f'- **修复方案**: {v["solution"][:200]}')
                        lines.append('')
                else:
                    lines.append('```json')
                    lines.append(json.dumps(data, indent=2, ensure_ascii=False))
                    lines.append('```')
                    lines.append('')

            lines.append('---')
            lines.append('')

        lines.append(f'*报告由 WebSecLab 平台自动生成 | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}*')
        return '\n'.join(lines)

    def _generate_mcp_json(self, plan_data):
        """生成 JSON 格式的 MCP 分析报告"""
        output = {
            'report_type': 'mcp_analysis',
            'generated_at': datetime.now().isoformat(),
            'platform': 'WebSecLab v3.0',
            'query': plan_data.get('query', ''),
            'summary': plan_data.get('summary', ''),
            'tools_executed': plan_data.get('tools_executed') or plan_data.get('planned_tools') or [],
            'results': plan_data.get('results', {}),
        }
        return json.dumps(output, indent=2, ensure_ascii=False)

    @staticmethod
    def _build_mcp_description(plan_data):
        """构建 MCP 报告描述"""
        parts = []
        query = plan_data.get('query', '')
        if query:
            parts.append(f'查询: {query[:50]}')

        tools = plan_data.get('tools_executed') or plan_data.get('planned_tools') or []
        if tools:
            parts.append(f'工具: {", ".join(tools)}')

        results = plan_data.get('results', {})
        risk = results.get('risk', {})
        if risk.get('success'):
            d = risk.get('data', {})
            parts.append(f'风险: {d.get("risk_label", "-")}({d.get("final_score", 0)}/100)')

        scanner = results.get('scanner', {})
        if scanner.get('success'):
            lc = scanner.get('data', {}).get('latest_completed', {})
            port_count = len(lc.get('ports', []))
            if port_count:
                parts.append(f'扫描: {port_count}个端口')

        return ' | '.join(parts) if parts else 'MCP 分析报告'

    # ==================== 查询接口 ====================

    def save_graph_snapshot(self, user_id, b64_png, title=None):
        """
        保存知识图谱 PNG 快照为「图谱快照」报告, 同步到 /report 页面
        :param b64_png: 形如 'data:image/png;base64,xxxx' 或纯 base64 字符串
        :param title: 报告标题 (默认按时间生成)
        :return: (Report对象, 错误信息)
        """
        if not b64_png:
            return None, '图片数据为空'

        # 剥离 data URL 前缀
        if ',' in b64_png:
            header, b64_png = b64_png.split(',', 1)
        import base64
        b64_png = b64_png.strip()
        try:
            raw = base64.b64decode(b64_png)
        except Exception:
            return None, '图片数据解码失败'

        # 合法性: 至少含 PNG 文件头 且 体积合理 (避免空/畸形数据)
        if len(raw) < 16 or raw[:4] != b'\x89PNG':
            return None, '图片内容无效'

        filename = f'graph_{secrets.token_hex(8)}.png'
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(raw)

        report = Report(
            user_id=user_id,
            title=title or f'知识图谱快照 {datetime.now().strftime("%Y-%m-%d %H:%M")}',
            description='知识图谱可视化快照 (PNG)',
            file_path=filename,
            status=Report.STATUS_GENERATED,
            report_type=Report.TYPE_GRAPH_PNG,
            file_size=len(raw),
        )
        db.session.add(report)
        db.session.commit()
        return report, None

    def get_user_reports(self, user_id, page=1, per_page=10,
                         report_type=None, status=None, keyword=None,
                         sort_by='created_time', order='desc'):
        """
        获取用户报告列表 (分页 + 筛选 + 搜索 + 排序)
        :param report_type: 按类型过滤 (experiment/mcp_pdf/mcp_md/mcp_json/graph_png)
        :param status: 按状态过滤 (generated/failed)
        :param keyword: 标题模糊搜索
        :param sort_by: 'created_time' / 'file_size'
        :param order: 'asc' / 'desc'
        """
        query = Report.query.filter_by(user_id=user_id)

        if report_type:
            query = query.filter(Report.report_type == report_type)
        if status:
            query = query.filter(Report.status == status)
        if keyword:
            like = f'%{keyword}%'
            query = query.filter(Report.title.ilike(like))

        is_asc = (order == 'asc')
        if sort_by == 'file_size':
            query = query.order_by(Report.file_size.asc() if is_asc else Report.file_size.desc())
        else:
            query = query.order_by(Report.created_time.asc() if is_asc else Report.created_time.desc())

        return query.paginate(page=page, per_page=per_page, error_out=False)

    def get_user_report_stats(self, user_id):
        """用户报告概览统计: 各类型数量 + 失败数"""
        reports = Report.query.filter_by(user_id=user_id).all()
        stats = {
            'total': len(reports),
            'experiment': 0,
            'mcp': 0,
            'graph_png': 0,
            'failed': 0,
        }
        for r in reports:
            if r.report_type == 'graph_png':
                stats['graph_png'] += 1
            elif r.report_type and r.report_type.startswith('mcp_'):
                stats['mcp'] += 1
            elif r.report_type == 'experiment':
                stats['experiment'] += 1
            if r.status == Report.STATUS_FAILED:
                stats['failed'] += 1
        return stats

    def get_report_by_id(self, report_id, user_id=None):
        """获取报告详情 (带用户隔离)"""
        report = db.session.get(Report, report_id)
        if not report:
            return None, '报告不存在'
        if user_id is not None and not report.is_owner(user_id):
            return None, '无权访问该报告'
        return report, None

    def get_report_file(self, report_id, user_id):
        """
        获取报告文件路径
        :return: (文件绝对路径, 原始文件名, MIME类型, 错误信息)
        """
        report = db.session.get(Report, report_id)
        if not report:
            return None, None, None, '报告不存在'
        if not report.is_owner(user_id):
            return None, None, None, '无权下载该报告'
        if report.status != Report.STATUS_GENERATED:
            return None, None, None, '报告生成失败，无法下载'

        reports_dir = self.pdf_gen.output_dir
        filepath = os.path.join(reports_dir, report.file_path)

        if not os.path.exists(filepath):
            return None, None, None, '报告文件不存在'

        ext = report.file_extension
        download_name = f'{report.title}.{ext}'
        mime_type = report.mime_type
        return filepath, download_name, mime_type, None

    def delete_report(self, report_id, user_id):
        """删除报告及其PDF文件"""
        report = db.session.get(Report, report_id)
        if not report:
            return False, '报告不存在'
        if not report.is_owner(user_id):
            return False, '无权删除该报告'

        # 删除PDF文件
        if report.file_path:
            filepath = os.path.join(self.pdf_gen.output_dir, report.file_path)
            if os.path.exists(filepath):
                os.remove(filepath)

        db.session.delete(report)
        db.session.commit()
        return True, None

    @staticmethod
    def _build_description(experiment, vulnerability, scan_results, ai_analysis):
        """构建报告描述"""
        parts = []
        parts.append(f'实验: {experiment.experiment_name}')
        if vulnerability:
            parts.append(f'漏洞: {vulnerability.name}')
        if scan_results:
            parts.append(f'扫描: {len(scan_results)}个开放端口')
        if ai_analysis:
            parts.append(f'AI分析: {ai_analysis.risk_label}')
        return ' | '.join(parts)
