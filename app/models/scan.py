"""
扫描任务模型模块
定义ScanTask扫描任务表和ScanResult扫描结果表
关系: User 1:N ScanTask, Experiment 1:N ScanTask, ScanTask 1:N ScanResult
"""

from datetime import datetime
from app.extensions import db


class ScanTask(db.Model):
    """扫描任务表"""
    __tablename__ = 'scan_tasks'

    # 主键
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # 用户ID (外键关联User)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # 用户内展示序号 (每位用户从 1 自增, 不依赖全局主键; 用于列表「ID」列)
    display_id = db.Column(db.Integer, nullable=True, index=True)

    # 实验ID (外键关联Experiment，可选)
    experiment_id = db.Column(db.Integer, db.ForeignKey('experiments.id'), nullable=True)

    # 扫描目标IP/域名
    target = db.Column(db.String(256), nullable=False)

    # 扫描类型: socket / nmap / both
    scan_type = db.Column(db.String(16), default='socket')

    # 端口范围 (如: 1-1024 或 common)
    port_range = db.Column(db.String(32), default='common')

    # 任务状态: created / running / completed / failed
    status = db.Column(db.String(16), default='created', index=True)

    # 错误信息
    error_message = db.Column(db.Text, default='')

    # 开始时间
    start_time = db.Column(db.DateTime, nullable=True)

    # 结束时间
    end_time = db.Column(db.DateTime, nullable=True)

    # 进度跟踪字段 (0-100)
    progress = db.Column(db.Integer, default=0)

    # 进度描述信息 (如 "正在扫描端口 443/1024")
    progress_message = db.Column(db.String(256), default='')

    # 总端口数
    total_ports = db.Column(db.Integer, default=0)

    # 已扫描端口数
    scanned_ports = db.Column(db.Integer, default=0)

    # 创建时间
    created_time = db.Column(db.DateTime, default=datetime.now)

    # 关系: 多对一 -> User
    user = db.relationship('User', backref=db.backref('scan_tasks', lazy='dynamic'))

    # 关系: 多对一 -> Experiment
    experiment = db.relationship('Experiment', backref=db.backref('scan_tasks', lazy='dynamic'))

    # 关系: 一对多 -> ScanResult
    results = db.relationship('ScanResult', backref='task', lazy='dynamic',
                              order_by='ScanResult.port')

    # 状态常量
    STATUS_CREATED = 'created'
    STATUS_RUNNING = 'running'
    STATUS_COMPLETED = 'completed'
    STATUS_FAILED = 'failed'

    # 扫描类型常量
    TYPE_SOCKET = 'socket'
    TYPE_NMAP = 'nmap'
    TYPE_BOTH = 'both'

    def __repr__(self):
        return f'<ScanTask {self.target} [{self.scan_type}] {self.status}>'

    @property
    def status_badge(self):
        """返回状态对应的Bootstrap颜色类"""
        badge_map = {
            'created': 'secondary',
            'running': 'primary',
            'completed': 'success',
            'failed': 'danger'
        }
        return badge_map.get(self.status, 'secondary')

    @property
    def status_label(self):
        """返回状态的中文标签"""
        label_map = {
            'created': '等待中',
            'running': '扫描中',
            'completed': '已完成',
            'failed': '失败'
        }
        return label_map.get(self.status, self.status)

    @property
    def scan_type_label(self):
        """返回扫描类型的中文标签"""
        label_map = {
            'socket': 'Socket扫描',
            'nmap': 'Nmap扫描',
            'both': 'Socket+Nmap'
        }
        return label_map.get(self.scan_type, self.scan_type)

    @property
    def open_ports_count(self):
        """返回开放端口数量（直接查询数据库，避免 ORM 关系缓存不一致）"""
        from app.extensions import db as _db
        try:
            return int(ScanResult.query.filter_by(
                task_id=self.id, state='open'
            ).count())
        except Exception:
            # 回退：用 func.count（兼容极端 session 状态）
            from sqlalchemy import func as _func
            try:
                return int(_db.session.query(
                    _func.count(ScanResult.id)
                ).filter(
                    ScanResult.task_id == self.id,
                    ScanResult.state == 'open'
                ).scalar() or 0)
            except Exception:
                return 0

    def is_owner(self, user_id):
        """验证指定用户是否为任务所有者"""
        return self.user_id == user_id


class ScanResult(db.Model):
    """扫描结果表"""
    __tablename__ = 'scan_results'

    # 主键
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # 任务ID (外键关联ScanTask)
    task_id = db.Column(db.Integer, db.ForeignKey('scan_tasks.id'), nullable=False, index=True)

    # 端口号
    port = db.Column(db.Integer, nullable=False)

    # 协议 (TCP/UDP)
    protocol = db.Column(db.String(8), default='TCP')

    # 端口状态 (open/closed/filtered)
    state = db.Column(db.String(16), default='open')

    # 服务名称
    service = db.Column(db.String(64), default='')

    # 服务版本
    version = db.Column(db.String(128), default='')

    # Banner信息
    banner = db.Column(db.Text, default='')

    # 创建时间
    created_time = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f'<ScanResult {self.port}/{self.protocol} {self.state} {self.service}>'

    @property
    def state_badge(self):
        """返回端口状态对应的Bootstrap颜色类"""
        badge_map = {
            'open': 'success',
            'closed': 'danger',
            'filtered': 'warning'
        }
        return badge_map.get(self.state, 'secondary')
