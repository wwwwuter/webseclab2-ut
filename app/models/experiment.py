"""
实验管理模型模块
定义Experiment实验任务表和ExperimentLog实验日志表
关系: User 1:N Experiment, Vulnerability 1:N Experiment, Experiment 1:N ExperimentLog
"""

from datetime import datetime
from app.extensions import db


class Experiment(db.Model):
    """实验任务表"""
    __tablename__ = 'experiments'

    # 主键
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # 用户ID (外键关联User)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # 漏洞ID (外键关联Vulnerability)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'), nullable=True)

    # 实验名称
    experiment_name = db.Column(db.String(128), nullable=False)

    # 目标地址 (DVWA地址)
    target = db.Column(db.String(256), default='')

    # DVWA安全等级: low / medium / high / impossible
    dvwa_level = db.Column(db.String(16), default='low')

    # 实验唯一Token
    token = db.Column(db.String(32), unique=True, nullable=False, index=True)

    # 实验状态: created / running / success / failed / closed
    status = db.Column(db.String(16), default='created', index=True)

    # 实验结果
    result = db.Column(db.Text, default='')

    # 创建时间
    created_time = db.Column(db.DateTime, default=datetime.now)

    # 完成时间
    completed_time = db.Column(db.DateTime, nullable=True)

    # 关系: 多对一 -> User
    user = db.relationship('User', backref=db.backref('experiments', lazy='dynamic'))

    # 关系: 多对一 -> Vulnerability
    vulnerability = db.relationship('Vulnerability', backref=db.backref('experiments', lazy='dynamic'))

    # 关系: 一对多 -> ExperimentLog
    logs = db.relationship('ExperimentLog', backref='experiment', lazy='dynamic',
                           order_by='ExperimentLog.time.desc()')

    # 状态常量
    STATUS_CREATED = 'created'
    STATUS_RUNNING = 'running'
    STATUS_SUCCESS = 'success'
    STATUS_FAILED = 'failed'
    STATUS_CLOSED = 'closed'

    VALID_STATUSES = [STATUS_CREATED, STATUS_RUNNING, STATUS_SUCCESS, STATUS_FAILED, STATUS_CLOSED]

    ACTION_STATES = {
        'start': (STATUS_CREATED,),
        'complete': (STATUS_RUNNING,),
        'close': (STATUS_CREATED, STATUS_RUNNING),
    }
    NAME_MAX_LENGTH = 128
    TARGET_MAX_LENGTH = 256
    RESULT_MAX_LENGTH = 20000

    def can_perform(self, action):
        return self.status in self.ACTION_STATES.get(action, ())

    # DVWA等级常量
    DVWA_LEVELS = ['low', 'medium', 'high', 'impossible']

    def __repr__(self):
        return f'<Experiment {self.experiment_name} [{self.status}]>'

    @property
    def status_badge(self):
        """返回状态对应的Bootstrap颜色类"""
        badge_map = {
            'created': 'secondary',
            'running': 'primary',
            'success': 'success',
            'failed': 'danger',
            'closed': 'dark'
        }
        return badge_map.get(self.status, 'secondary')

    @property
    def status_label(self):
        """返回状态的中文标签"""
        label_map = {
            'created': '已创建',
            'running': '进行中',
            'success': '已完成',
            'failed': '失败',
            'closed': '已关闭'
        }
        return label_map.get(self.status, self.status)

    def is_owner(self, user_id):
        """验证指定用户是否为实验所有者"""
        return self.user_id == user_id


class ExperimentLog(db.Model):
    """实验日志表 - 记录实验关键操作"""
    __tablename__ = 'experiment_logs'

    # 主键
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # 实验ID (外键关联Experiment)
    experiment_id = db.Column(db.Integer, db.ForeignKey('experiments.id'), nullable=False, index=True)

    # 操作类型
    action = db.Column(db.String(32), nullable=False)

    # 操作描述
    description = db.Column(db.Text, default='')

    # 操作时间
    time = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f'<ExperimentLog [{self.action}] {self.description}>'
