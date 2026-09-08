"""
实验报告模型模块
定义Report表，存储生成的报告记录 (PDF/Markdown/JSON)
关系: User 1:N Report, Experiment 1:N Report
"""

from datetime import datetime
from app.extensions import db


class Report(db.Model):
    """实验报告表"""
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # 用户ID
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # 关联实验ID (可选，MCP报告可为空)
    experiment_id = db.Column(db.Integer, db.ForeignKey('experiments.id'), nullable=True)

    # 报告标题
    title = db.Column(db.String(256), nullable=False)

    # 报告描述
    description = db.Column(db.Text, default='')

    # 文件路径 (相对于reports/目录)
    file_path = db.Column(db.String(512), default='')

    # 报告状态: generated / failed
    status = db.Column(db.String(16), default='generated')

    # 报告类型: experiment / mcp_pdf / mcp_md / mcp_json
    report_type = db.Column(db.String(16), default='experiment', server_default='experiment')

    # 文件大小 (字节)
    file_size = db.Column(db.Integer, default=0)

    # 错误信息
    error_message = db.Column(db.Text, default='')

    # 创建时间
    created_time = db.Column(db.DateTime, default=datetime.now)

    # 关系
    user = db.relationship('User', backref=db.backref('reports', lazy='dynamic'))
    experiment = db.relationship('Experiment', backref=db.backref('reports', lazy='dynamic'))

    # 状态常量
    STATUS_GENERATED = 'generated'
    STATUS_FAILED = 'failed'

    # 类型常量
    TYPE_EXPERIMENT = 'experiment'
    TYPE_MCP_PDF = 'mcp_pdf'
    TYPE_MCP_MD = 'mcp_md'
    TYPE_MCP_JSON = 'mcp_json'
    TYPE_GRAPH_PNG = 'graph_png'

    def __repr__(self):
        return f'<Report {self.id} {self.title}>'

    @property
    def status_badge(self):
        badge_map = {'generated': 'success', 'failed': 'danger'}
        return badge_map.get(self.status, 'secondary')

    @property
    def status_label(self):
        label_map = {'generated': '已生成', 'failed': '生成失败'}
        return label_map.get(self.status, self.status)

    @property
    def type_label(self):
        """报告类型中文标签"""
        label_map = {
            'experiment': '实验报告',
            'mcp_pdf': 'MCP-PDF',
            'mcp_md': 'MCP-Markdown',
            'mcp_json': 'MCP-JSON',
            'graph_png': '图谱快照',
        }
        return label_map.get(self.report_type, '报告')

    @property
    def type_badge(self):
        """报告类型 Bootstrap badge 颜色"""
        badge_map = {
            'experiment': 'primary',
            'mcp_pdf': 'danger',
            'mcp_md': 'info',
            'mcp_json': 'warning',
            'graph_png': 'success',
        }
        return badge_map.get(self.report_type, 'secondary')

    @property
    def is_mcp_report(self):
        """是否为 MCP 分析报告"""
        return self.report_type and self.report_type.startswith('mcp_')

    @property
    def file_extension(self):
        """根据类型返回文件扩展名"""
        ext_map = {
            'experiment': 'pdf',
            'mcp_pdf': 'pdf',
            'mcp_md': 'md',
            'mcp_json': 'json',
            'graph_png': 'png',
        }
        return ext_map.get(self.report_type, 'pdf')

    @property
    def mime_type(self):
        """根据类型返回 MIME 类型"""
        mime_map = {
            'experiment': 'application/pdf',
            'mcp_pdf': 'application/pdf',
            'mcp_md': 'text/markdown',
            'mcp_json': 'application/json',
            'graph_png': 'image/png',
        }
        return mime_map.get(self.report_type, 'application/octet-stream')

    @property
    def file_size_kb(self):
        """返回文件大小(KB)"""
        if self.file_size:
            return round(self.file_size / 1024, 1)
        return 0

    def is_owner(self, user_id):
        """验证用户是否为报告所有者"""
        return self.user_id == user_id
