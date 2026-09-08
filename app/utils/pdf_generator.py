"""
PDF报告生成模块
使用ReportLab生成标准化Web安全实验报告PDF
支持中文 (SimSun/SimHei)
"""

import os
import secrets
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 Table, TableStyle, PageBreak, HRFlowable)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# 尝试注册中文字体
_FONT_REGISTERED = False
_FONT_NAME = 'Helvetica'
_FONT_NAME_BOLD = 'Helvetica-Bold'


def _register_chinese_font():
    """注册中文字体"""
    global _FONT_REGISTERED, _FONT_NAME, _FONT_NAME_BOLD

    if _FONT_REGISTERED:
        return

    # Windows常见字体路径
    font_paths = [
        (os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'Fonts', 'simhei.ttf'),
         os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'Fonts', 'simsun.ttc')),
    ]

    for heiti_path, songti_path in font_paths:
        try:
            if os.path.exists(heiti_path):
                pdfmetrics.registerFont(TTFont('SimHei', heiti_path))
                _FONT_NAME = 'SimHei'
                _FONT_NAME_BOLD = 'SimHei'
                _FONT_REGISTERED = True
                return
        except Exception:
            pass

        try:
            if os.path.exists(songti_path):
                pdfmetrics.registerFont(TTFont('SimSun', songti_path))
                _FONT_NAME = 'SimSun'
                _FONT_NAME_BOLD = 'SimSun'
                _FONT_REGISTERED = True
                return
        except Exception:
            pass


class PDFGenerator:
    """PDF报告生成器"""

    def __init__(self, output_dir='reports'):
        """
        初始化PDF生成器
        :param output_dir: PDF输出目录
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        _register_chinese_font()

    def generate_experiment_report(self, experiment, vulnerability=None,
                                    scan_results=None, ai_analysis=None, user=None):
        """
        生成实验报告PDF
        :param experiment: Experiment对象
        :param vulnerability: Vulnerability对象
        :param scan_results: ScanResult列表
        :param ai_analysis: AIAnalysis对象
        :param user: User对象
        :return: (文件路径, 文件大小, 错误信息)
        """
        # 生成随机文件名
        random_suffix = secrets.token_hex(4)
        filename = f'report_{experiment.id}_{random_suffix}.pdf'
        filepath = os.path.join(self.output_dir, filename)

        try:
            doc = SimpleDocTemplate(
                filepath,
                pagesize=A4,
                topMargin=2 * cm,
                bottomMargin=2 * cm,
                leftMargin=2 * cm,
                rightMargin=2 * cm
            )

            styles = self._get_styles()
            story = []

            # ===== 封面 =====
            story.extend(self._build_cover(experiment, user))
            story.append(PageBreak())

            # ===== 一、实验基本信息 =====
            story.append(Paragraph('一、实验基本信息', styles['Heading1']))
            story.append(Spacer(1, 10))
            story.extend(self._build_experiment_info(experiment, user))
            story.append(Spacer(1, 15))

            # ===== 二、漏洞信息 =====
            if vulnerability:
                story.append(HRFlowable(width='100%', color=colors.grey))
                story.append(Paragraph('二、漏洞信息', styles['Heading1']))
                story.append(Spacer(1, 10))
                story.extend(self._build_vulnerability_info(vulnerability))
                story.append(Spacer(1, 15))

            # ===== 三、实验过程 =====
            story.append(HRFlowable(width='100%', color=colors.grey))
            story.append(Paragraph('三、实验过程', styles['Heading1']))
            story.append(Spacer(1, 10))
            story.extend(self._build_experiment_process(experiment))
            story.append(Spacer(1, 15))

            # ===== 四、扫描结果 =====
            if scan_results:
                story.append(HRFlowable(width='100%', color=colors.grey))
                story.append(Paragraph('四、扫描结果', styles['Heading1']))
                story.append(Spacer(1, 10))
                story.extend(self._build_scan_results(scan_results))
                story.append(Spacer(1, 15))

            # ===== 五、AI智能分析 =====
            if ai_analysis and ai_analysis.status == 'completed':
                story.append(HRFlowable(width='100%', color=colors.grey))
                story.append(Paragraph('五、AI智能分析', styles['Heading1']))
                story.append(Spacer(1, 10))
                story.extend(self._build_ai_analysis(ai_analysis))
                story.append(Spacer(1, 15))

            # ===== 六、安全总结 =====
            story.append(HRFlowable(width='100%', color=colors.grey))
            story.append(Paragraph('六、安全总结', styles['Heading1']))
            story.append(Spacer(1, 10))
            story.extend(self._build_security_summary(experiment, vulnerability, ai_analysis))

            # 构建PDF
            doc.build(story)

            file_size = os.path.getsize(filepath)
            return filename, file_size, None

        except Exception as e:
            # 清理失败文件
            if os.path.exists(filepath):
                os.remove(filepath)
            return '', 0, f'PDF生成失败: {str(e)}'

    def generate_mcp_report(self, plan_data, user=None):
        """
        生成 MCP AI Agent 分析报告 PDF

        :param plan_data: MCP 分析计划结果 dict，包含:
            - tools_executed / planned_tools: 工具列表
            - results: 各工具结果 {tool_name: {success, summary, data, error}}
            - execution_log: 执行日志列表
            - summary: Markdown 摘要
            - query: 用户查询 (可选)
        :param user: User 对象 (可选)
        :return: (文件路径, 文件大小, 错误信息)
        """
        random_suffix = secrets.token_hex(4)
        filename = f'mcp_report_{random_suffix}.pdf'
        filepath = os.path.join(self.output_dir, filename)

        try:
            doc = SimpleDocTemplate(
                filepath, pagesize=A4,
                topMargin=2 * cm, bottomMargin=2 * cm,
                leftMargin=2 * cm, rightMargin=2 * cm,
            )
            styles = self._get_styles()
            story = []

            tool_names = plan_data.get('tools_executed') or plan_data.get('planned_tools') or []
            results = plan_data.get('results', {})
            exec_log = plan_data.get('execution_log') or []
            total_ms = plan_data.get('total_ms', 0)
            if not total_ms and exec_log:
                total_ms = sum(e.get('elapsed_ms', 0) for e in exec_log)

            # 提取各工具数据
            r_data = results.get('risk', {}).get('data', {}) if results.get('risk', {}).get('success') else {}
            k_data = results.get('knowledge', {}).get('data', {}) if results.get('knowledge', {}).get('success') else {}
            s_data = results.get('scanner', {}).get('data', {}) if results.get('scanner', {}).get('success') else {}
            d_data = results.get('dashboard', {}).get('data', {}) if results.get('dashboard', {}).get('success') else {}
            rpt = results.get('report', {}).get('data', {}) if results.get('report', {}).get('success') else {}

            vulns = k_data.get('vulnerabilities', []) or ([k_data] if k_data.get('name') else [])
            ports = s_data.get('latest_completed', {}).get('ports', []) if s_data.get('latest_completed') else []

            # ===== 封面 =====
            story.extend(self._build_mcp_cover(plan_data, user, total_ms))
            story.append(PageBreak())

            # ===== 一、分析概览 =====
            story.append(Paragraph('一、分析概览', styles['Heading1']))
            story.append(Spacer(1, 10))
            story.extend(self._build_mcp_overview(tool_names, total_ms, plan_data))
            story.append(Spacer(1, 15))

            # ===== 二、工具调用记录 =====
            if exec_log:
                story.append(HRFlowable(width='100%', color=colors.grey))
                story.append(Paragraph('二、工具调用记录', styles['Heading1']))
                story.append(Spacer(1, 10))
                story.extend(self._build_mcp_tool_log(exec_log))
                story.append(Spacer(1, 15))

            # ===== 三、扫描结果 =====
            if ports:
                story.append(HRFlowable(width='100%', color=colors.grey))
                story.append(Paragraph('三、端口扫描结果', styles['Heading1']))
                story.append(Spacer(1, 10))
                story.extend(self._build_mcp_scan_results(ports, s_data))
                story.append(Spacer(1, 15))

            # ===== 四、风险评估 =====
            if r_data:
                story.append(HRFlowable(width='100%', color=colors.grey))
                story.append(Paragraph('四、风险评估', styles['Heading1']))
                story.append(Spacer(1, 10))
                story.extend(self._build_mcp_risk(r_data))
                story.append(Spacer(1, 15))

            # ===== 五、漏洞详情 =====
            if vulns:
                story.append(HRFlowable(width='100%', color=colors.grey))
                story.append(Paragraph('五、漏洞详情', styles['Heading1']))
                story.append(Spacer(1, 10))
                story.extend(self._build_mcp_vulns(vulns, styles))
                story.append(Spacer(1, 15))

            # ===== 六、AI 综合分析 =====
            story.append(HRFlowable(width='100%', color=colors.grey))
            story.append(Paragraph('六、AI 综合分析', styles['Heading1']))
            story.append(Spacer(1, 10))
            story.extend(self._build_mcp_ai_summary(ports, vulns, r_data, d_data, styles))
            story.append(Spacer(1, 15))

            # ===== 七、修复建议 =====
            if vulns:
                story.append(HRFlowable(width='100%', color=colors.grey))
                story.append(Paragraph('七、修复建议', styles['Heading1']))
                story.append(Spacer(1, 10))
                story.extend(self._build_mcp_fix_advice(vulns, styles))
                story.append(Spacer(1, 15))

            # ===== 页脚 =====
            story.extend(self._build_mcp_footer())

            doc.build(story)
            file_size = os.path.getsize(filepath)
            return filename, file_size, None

        except Exception as e:
            if os.path.exists(filepath):
                os.remove(filepath)
            return '', 0, f'PDF生成失败: {str(e)}'

    def _build_mcp_cover(self, plan_data, user, total_ms):
        """MCP 报告封面"""
        styles = self._get_styles()
        elements = []
        elements.append(Spacer(1, 80))
        elements.append(Paragraph('WebSecLab', styles['CNTitle']))
        elements.append(Paragraph('AI Agent 安全分析报告', styles['CNTitle']))
        elements.append(Spacer(1, 30))

        query = plan_data.get('query', '')
        if query:
            elements.append(Paragraph(query, styles['CNSubTitle']))

        elements.append(Spacer(1, 50))

        tool_names = plan_data.get('tools_executed') or plan_data.get('planned_tools') or []
        info_data = [
            ['分析用户', user.username if user else '-'],
            ['生成时间', datetime.now().strftime('%Y-%m-%d %H:%M')],
            ['调用工具', '、'.join(tool_names) if tool_names else '-'],
            ['总耗时', f'{total_ms / 1000:.2f} 秒' if total_ms else '-'],
        ]
        info_table = Table(info_data, colWidths=[4 * cm, 8 * cm])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), _FONT_NAME),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.grey),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(info_table)
        return elements

    def _build_mcp_overview(self, tool_names, total_ms, plan_data):
        """分析概览"""
        styles = self._get_styles()
        data = [
            ['调用工具数', str(len(tool_names))],
            ['总耗时', f'{total_ms / 1000:.2f}s' if total_ms else '-'],
            ['执行状态', '成功'],
        ]
        if plan_data.get('query'):
            data.insert(0, ['分析请求', plan_data['query'][:100]])
        return [self._make_info_table(data)]

    def _build_mcp_tool_log(self, exec_log):
        """工具调用日志表格"""
        data = [['工具', '耗时', '状态', '摘要']]
        for entry in exec_log:
            data.append([
                entry.get('tool', '-'),
                f"{entry.get('elapsed_ms', 0)}ms",
                '成功' if entry.get('success') else '失败',
                (entry.get('summary', '') or '-')[:60],
            ])
        if len(data) > 1:
            table = Table(data, colWidths=[3 * cm, 2 * cm, 2 * cm, 9 * cm])
            table.setStyle(self._get_table_style())
            return [table]
        return []

    def _build_mcp_scan_results(self, ports, s_data):
        """扫描结果"""
        styles = self._get_styles()
        elements = []
        target = s_data.get('target', '-')
        elements.append(Paragraph(f'扫描目标: {target}', styles['CNBody']))
        elements.append(Spacer(1, 5))

        if ports:
            data = [['端口', '服务', '版本']]
            for p in ports[:30]:
                data.append([
                    str(p.get('port', '-')),
                    p.get('service', '-') or '-',
                    (p.get('version', '-') or '-')[:40],
                ])
            if len(data) > 1:
                table = Table(data, colWidths=[3 * cm, 5 * cm, 8 * cm])
                table.setStyle(self._get_table_style())
                elements.append(table)
        return elements

    def _build_mcp_risk(self, r_data):
        """风险评估"""
        styles = self._get_styles()
        data = [
            ['综合评分', f"{r_data.get('final_score', 0):.1f} / 100"],
            ['风险等级', r_data.get('risk_label', '-')],
            ['CVSS', f"{r_data.get('cvss', 0):.1f}"],
            ['资产价值', f"{r_data.get('asset', 0):.1f}"],
            ['利用难度', f"{r_data.get('exploit', 0):.1f}"],
            ['暴露面', f"{r_data.get('exposure', 0):.1f}"],
            ['AI 置信度', f"{r_data.get('ai_confidence', 0):.1f}"],
        ]
        return [self._make_info_table(data)]

    def _build_mcp_vulns(self, vulns, styles):
        """漏洞详情"""
        elements = []
        wrap_style = ParagraphStyle(
            'MCPCellWrap', parent=styles['CNBody'],
            fontSize=10, wordWrap='CJK', breakLongWords=True,
        )
        for i, v in enumerate(vulns, 1):
            elements.append(Paragraph(
                f"<b>{i}. {v.get('name', '未知漏洞')}</b>"
                f"  [{v.get('severity', '?')}]",
                styles['CNHeading'],
            ))
            vdata = [
                ['CVE', Paragraph(str(v.get('cve', '-')), wrap_style)],
                ['分类', Paragraph(str(v.get('category', '-')), wrap_style)],
                ['描述', Paragraph(str(v.get('description', '-'))[:300], wrap_style)],
                ['攻击方式', Paragraph(str(v.get('attack_method', '-'))[:200], wrap_style)],
                ['修复方案', Paragraph(str(v.get('solution', '-'))[:200], wrap_style)],
            ]
            elements.append(self._make_info_table(vdata))
            elements.append(Spacer(1, 10))
        return elements

    def _build_mcp_ai_summary(self, ports, vulns, r_data, d_data, styles):
        """AI 综合分析"""
        elements = []
        parts = []

        if ports:
            port_list = '、'.join(str(p.get('port', '')) for p in ports)
            parts.append(f'目标主机开放 {len(ports)} 个端口: {port_list}。')
            for p in ports:
                if p.get('service'):
                    parts.append(f'{p["port"]} 端口运行 {p["service"]}'
                                 + (f' ({p["version"]})' if p.get('version') else '') + '。')

        if vulns:
            if len(vulns) == 1:
                parts.append(f'根据漏洞知识库分析，发现 {vulns[0].get("name", "未知")} 漏洞，'
                             f'风险等级为 {vulns[0].get("severity", "未知")}。')
            else:
                parts.append(f'根据漏洞知识库分析，共发现 {len(vulns)} 个漏洞。')

        if r_data:
            score = r_data.get('final_score', 0)
            label = r_data.get('risk_label', '未知')
            parts.append(f'多因素风险评估综合五个维度，最终评分 {score:.1f}/100，'
                         f'风险等级 {label}。')
            if score >= 70:
                parts.append('建议立即采取修复措施。')
            elif score >= 40:
                parts.append('建议尽快安排修复计划。')
            else:
                parts.append('当前风险可控，建议持续关注。')

        if d_data and not ports and not vulns and not r_data:
            parts.append(
                f'当前平台安全态势: {d_data.get("experiments", 0)} 个实验、'
                f'{d_data.get("scans", 0)} 次扫描、'
                f'{d_data.get("ai_analyses", 0)} 次 AI 分析。')

        if not parts:
            parts.append('本次分析未获取足够数据，请确保填写扫描目标或实验 ID 以获得完整分析。')

        elements.append(Paragraph(' '.join(parts), styles['CNBody']))
        return elements

    def _build_mcp_fix_advice(self, vulns, styles):
        """修复建议"""
        elements = []
        elements.append(Paragraph(
            '<b>核心原则: 始终使用参数化查询或 ORM，永远不要拼接用户输入到 SQL 语句中。</b>',
            styles['CNBody']))
        elements.append(Spacer(1, 8))

        advice = [
            ('Flask (Python)', '使用 cursor.execute("SELECT ... WHERE id=?", (id,))'),
            ('Spring Boot (Java)', '使用 JPA 参数绑定: repository.findById(id)'),
            ('Express (Node.js)', '使用参数化查询: pool.query("SELECT ... WHERE id=$1", [id])'),
            ('PHP (PDO)', '使用预处理: $pdo->prepare("SELECT ... WHERE id=:id")'),
            ('Laravel', '使用 Eloquent ORM: User::findOrFail($id)'),
        ]
        data = [['框架', '修复方法']]
        for fw, fix in advice:
            data.append([fw, fix])
        table = Table(data, colWidths=[4 * cm, 12 * cm])
        table.setStyle(self._get_table_style())
        elements.append(table)

        for v in vulns[:3]:
            if v.get('solution'):
                elements.append(Spacer(1, 8))
                elements.append(Paragraph(
                    f'<b>{v["name"]}:</b> {v["solution"][:200]}', styles['CNBody']))
        return elements

    def _build_mcp_footer(self):
        """MCP 报告页脚"""
        styles = self._get_styles()
        elements = [
            Spacer(1, 20),
            HRFlowable(width='100%', color=colors.grey),
            Spacer(1, 5),
            Paragraph(
                f'报告由 WebSecLab AI Agent 自动生成 | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
                styles['CNSubTitle'],
            ),
        ]
        return elements

    def _get_styles(self):
        """获取PDF样式"""
        styles = getSampleStyleSheet()

        styles.add(ParagraphStyle(
            name='CNTitle',
            fontName=_FONT_NAME_BOLD,
            fontSize=22,
            alignment=1,  # center
            spaceAfter=20,
            spaceBefore=40
        ))

        styles.add(ParagraphStyle(
            name='CNSubTitle',
            fontName=_FONT_NAME,
            fontSize=14,
            alignment=1,
            spaceAfter=10,
            textColor=colors.grey
        ))

        styles.add(ParagraphStyle(
            name='CNBody',
            fontName=_FONT_NAME,
            fontSize=10,
            leading=16,
            spaceAfter=6
        ))

        styles.add(ParagraphStyle(
            name='CNHeading',
            fontName=_FONT_NAME_BOLD,
            fontSize=12,
            spaceAfter=8,
            spaceBefore=12,
            textColor=colors.HexColor('#2c3e50')
        ))

        # 覆盖Heading1
        styles['Heading1'].fontName = _FONT_NAME_BOLD
        styles['Heading1'].fontSize = 14
        styles['Heading1'].textColor = colors.HexColor('#2c3e50')
        styles['Heading1'].spaceBefore = 12
        styles['Heading1'].spaceAfter = 8

        styles['Normal'].fontName = _FONT_NAME
        styles['Normal'].fontSize = 10
        styles['Normal'].leading = 16

        return styles

    def _build_cover(self, experiment, user):
        """构建封面"""
        styles = self._get_styles()
        elements = []
        elements.append(Spacer(1, 80))
        elements.append(Paragraph('WebSecLab', styles['CNTitle']))
        elements.append(Paragraph('Web安全实验报告', styles['CNTitle']))
        elements.append(Spacer(1, 30))

        title = experiment.experiment_name if experiment else '安全实验'
        elements.append(Paragraph(title, styles['CNSubTitle']))
        elements.append(Spacer(1, 50))

        info_data = [
            ['实验用户', user.username if user else 'Unknown'],
            ['生成时间', datetime.now().strftime('%Y-%m-%d %H:%M')],
            ['平台版本', 'WebSecLab v1.0'],
        ]
        info_table = Table(info_data, colWidths=[4 * cm, 8 * cm])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), _FONT_NAME),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.grey),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(info_table)
        return elements

    def _build_experiment_info(self, experiment, user):
        """构建实验基本信息"""
        data = [
            ['实验名称', experiment.experiment_name or '-'],
            ['实验用户', user.username if user else '-'],
            ['目标地址', experiment.target or '-'],
            ['DVWA等级', (experiment.dvwa_level or '-').upper()],
            ['实验状态', experiment.status_label],
            ['创建时间', experiment.created_time.strftime('%Y-%m-%d %H:%M') if experiment.created_time else '-'],
        ]
        return [self._make_info_table(data)]

    def _build_vulnerability_info(self, vulnerability):
        """构建漏洞信息"""
        styles = self._get_styles()
        elements = []

        wrap_style = ParagraphStyle(
            'CellWrap', parent=styles['CNBody'],
            fontSize=10, wordWrap='CJK', breakLongWords=True,
        )
        data = [
            ['漏洞名称', Paragraph(str(vulnerability.name), wrap_style)],
            ['CVE编号', Paragraph(str(getattr(vulnerability, 'cve', '') or '-'), wrap_style)],
            ['OWASP分类', Paragraph(str(vulnerability.owasp.name if getattr(vulnerability, 'owasp', None) else '-'), wrap_style)],
            ['严重程度', Paragraph(str(vulnerability.severity or '-'), wrap_style)],
        ]
        elements.append(self._make_info_table(data))

        if vulnerability.description:
            elements.append(Paragraph('<b>漏洞描述:</b>', styles['CNBody']))
            elements.append(Paragraph(str(vulnerability.description)[:500], styles['CNBody']))

        if vulnerability.solution:
            elements.append(Spacer(1, 5))
            elements.append(Paragraph('<b>修复方案:</b>', styles['CNBody']))
            elements.append(Paragraph(str(vulnerability.solution)[:500], styles['CNBody']))

        return elements

    def _build_experiment_process(self, experiment):
        """构建实验过程"""
        styles = self._get_styles()
        elements = []

        # 实验日志
        if hasattr(experiment, 'logs'):
            from sqlalchemy import text
            try:
                logs = experiment.logs.order_by(text('created_time')).all()
            except Exception:
                logs = experiment.logs.all()
            if logs:
                elements.append(Paragraph('<b>操作日志:</b>', styles['CNBody']))
                log_data = [['时间', '操作', '详情']]
                for log in logs[:20]:
                    log_data.append([
                        log.time.strftime('%H:%M:%S') if log.time else '-',
                        log.action or '-',
                        (log.description or '-')[:50]
                    ])
                if len(log_data) > 1:
                    log_table = Table(log_data, colWidths=[3 * cm, 4 * cm, 9 * cm])
                    log_table.setStyle(self._get_table_style())
                    elements.append(log_table)
            else:
                elements.append(Paragraph('暂无操作日志记录', styles['CNBody']))
        else:
            elements.append(Paragraph('暂无操作日志记录', styles['CNBody']))

        return elements

    def _build_scan_results(self, scan_results):
        """构建扫描结果"""
        styles = self._get_styles()
        elements = []

        elements.append(Paragraph(f'共发现 {len(scan_results)} 个开放端口:', styles['CNBody']))
        elements.append(Spacer(1, 5))

        data = [['端口', '协议', '状态', '服务', '版本']]
        for r in scan_results[:30]:
            data.append([
                str(r.port),
                r.protocol or 'TCP',
                r.state or 'open',
                r.service or '-',
                (r.version or '-')[:30]
            ])

        if len(data) > 1:
            table = Table(data, colWidths=[2 * cm, 2 * cm, 2 * cm, 4 * cm, 6 * cm])
            table.setStyle(self._get_table_style())
            elements.append(table)

        return elements

    def _build_ai_analysis(self, ai_analysis):
        """构建AI分析结果"""
        styles = self._get_styles()
        elements = []

        data = [
            ['风险等级', ai_analysis.risk_label],
            ['使用模型', ai_analysis.model or '-'],
        ]
        elements.append(self._make_info_table(data))

        sections = [
            ('漏洞分析', ai_analysis.vulnerability_analysis),
            ('攻击方式', ai_analysis.possible_attack),
            ('安全影响', ai_analysis.impact),
            ('修复建议', ai_analysis.fix_solution),
            ('安全建议', ai_analysis.security_advice),
        ]

        for title, content in sections:
            if content:
                elements.append(Spacer(1, 5))
                elements.append(Paragraph(f'<b>{title}:</b>', styles['CNBody']))
                elements.append(Paragraph(str(content)[:600], styles['CNBody']))

        return elements

    def _build_security_summary(self, experiment, vulnerability, ai_analysis):
        """构建安全总结"""
        styles = self._get_styles()
        elements = []

        summary_parts = []
        summary_parts.append(f'本次实验针对 {experiment.experiment_name} 进行了安全评估。')

        if vulnerability:
            summary_parts.append(f'实验涉及的漏洞类型为 {vulnerability.name}，')
            if vulnerability.severity:
                summary_parts.append(f'严重程度为 {vulnerability.severity}。')

        if ai_analysis and ai_analysis.status == 'completed':
            summary_parts.append(f'AI分析评估风险等级为 {ai_analysis.risk_label}。')
            if ai_analysis.fix_solution:
                summary_parts.append(f'建议: {ai_analysis.fix_solution[:200]}')

        summary_parts.append('\n\n建议持续进行安全测试和漏洞修复，提升系统整体安全性。')

        elements.append(Paragraph(''.join(summary_parts), styles['CNBody']))

        # 页脚信息
        elements.append(Spacer(1, 30))
        elements.append(HRFlowable(width='100%', color=colors.grey))
        elements.append(Spacer(1, 5))
        elements.append(Paragraph(
            f'报告由 WebSecLab 平台自动生成 | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
            styles['CNSubTitle']
        ))

        return elements

    def _make_info_table(self, data):
        """创建信息表格"""
        table = Table(data, colWidths=[4 * cm, 12 * cm])
        table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), _FONT_NAME),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8f9fa')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#495057')),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        return table

    @staticmethod
    def _get_table_style():
        """获取数据表格样式"""
        return TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), _FONT_NAME),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#343a40')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
        ])
