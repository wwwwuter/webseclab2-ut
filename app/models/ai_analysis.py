"""
AI分析结果模型模块
定义AIAnalysis表，存储Ollama大模型的漏洞分析结果
关系: User 1:N AIAnalysis, Experiment 1:N, ScanTask 1:N, Vulnerability 1:N
"""

from datetime import datetime
from app.extensions import db


class AIAnalysis(db.Model):
    """AI分析结果表"""
    __tablename__ = 'ai_analyses'

    # 主键
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # 用户ID
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # 关联实验ID (可选)
    experiment_id = db.Column(db.Integer, db.ForeignKey('experiments.id'), nullable=True)

    # 关联扫描任务ID (可选)
    scan_task_id = db.Column(db.Integer, db.ForeignKey('scan_tasks.id'), nullable=True)

    # 关联漏洞ID (可选)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'), nullable=True)

    # 输入数据 (漏洞信息/扫描结果摘要)
    input_data = db.Column(db.Text, default='')

    # 发送给模型的Prompt
    prompt = db.Column(db.Text, default='')

    # AI模型原始输出
    raw_output = db.Column(db.Text, default='')

    # 风险等级: Critical / High / Medium / Low / Info
    risk_level = db.Column(db.String(16), default='Info')

    # 漏洞分析
    vulnerability_analysis = db.Column(db.Text, default='')

    # 可能攻击方式
    possible_attack = db.Column(db.Text, default='')

    # 影响范围
    impact = db.Column(db.Text, default='')

    # 修复建议
    fix_solution = db.Column(db.Text, default='')

    # 安全建议
    security_advice = db.Column(db.Text, default='')

    # 使用的模型名称
    model = db.Column(db.String(64), default='')

    # 自定义分析场景: general / code / log / config / phishing
    scene = db.Column(db.String(32), default='general')

    # 分析状态: pending / running / completed / failed
    status = db.Column(db.String(16), default='pending')

    # 错误信息
    error_message = db.Column(db.Text, default='')

    # 创建时间
    created_time = db.Column(db.DateTime, default=datetime.now)

    # 关系: 多对一 -> User
    user = db.relationship('User', backref=db.backref('ai_analyses', lazy='dynamic'))

    # 关系: 多对一 -> Experiment
    experiment = db.relationship('Experiment', backref=db.backref('ai_analyses', lazy='dynamic'))

    # 关系: 多对一 -> ScanTask
    scan_task = db.relationship('ScanTask', backref=db.backref('ai_analyses', lazy='dynamic'))

    # 关系: 多对一 -> Vulnerability
    vulnerability = db.relationship('Vulnerability', backref=db.backref('ai_analyses', lazy='dynamic'))

    # 风险等级常量
    RISK_CRITICAL = 'Critical'
    RISK_HIGH = 'High'
    RISK_MEDIUM = 'Medium'
    RISK_LOW = 'Low'
    RISK_INFO = 'Info'

    # 状态常量
    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_COMPLETED = 'completed'
    STATUS_FAILED = 'failed'

    def __repr__(self):
        return f'<AIAnalysis {self.id} [{self.risk_level}] {self.status}>'

    @property
    def risk_badge(self):
        """返回风险等级对应的Bootstrap颜色类"""
        badge_map = {
            'Critical': 'dark',
            'High': 'danger',
            'Medium': 'warning',
            'Low': 'info',
            'Info': 'secondary'
        }
        return badge_map.get(self.risk_level, 'secondary')

    @property
    def risk_label(self):
        """返回风险等级的中文标签"""
        label_map = {
            'Critical': '严重',
            'High': '高危',
            'Medium': '中危',
            'Low': '低危',
            'Info': '信息'
        }
        return label_map.get(self.risk_level, self.risk_level)

    @property
    def status_badge(self):
        """返回状态对应的Bootstrap颜色类"""
        badge_map = {
            'pending': 'secondary',
            'running': 'primary',
            'completed': 'success',
            'failed': 'danger'
        }
        return badge_map.get(self.status, 'secondary')

    @property
    def status_label(self):
        """返回状态的中文标签"""
        label_map = {
            'pending': '等待中',
            'running': '分析中',
            'completed': '已完成',
            'failed': '失败'
        }
        return label_map.get(self.status, self.status)

    def is_owner(self, user_id):
        """验证用户是否为分析结果所有者"""
        return self.user_id == user_id
