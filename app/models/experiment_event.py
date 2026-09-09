"""
实验事件模型模块
记录 DVWA Hook 上报的实验事件, 用于自动验证实验是否真正复现漏洞

关系: Experiment 1:N ExperimentEvent
"""

from datetime import datetime
from app.extensions import db


class ExperimentEvent(db.Model):
    """实验事件表 - 记录 DVWA Hook 上报的关键事件"""
    __tablename__ = 'experiment_events'

    # 主键
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # 实验ID (外键关联Experiment)
    experiment_id = db.Column(db.Integer, db.ForeignKey('experiments.id'), nullable=False, index=True)

    # 事件类型 (如 sqli_success / xss_success / command_injection_success)
    event_type = db.Column(db.String(64), nullable=False, index=True)

    # 事件负载 (Hook 上报的原始数据, JSON 字符串)
    payload = db.Column(db.Text, default='')

    # 去重指纹 (experiment_id + event_type + payload 的哈希, 防止重复上报)
    fingerprint = db.Column(db.String(64), unique=True, nullable=False, index=True)

    # 是否触发自动判定成功
    triggered_success = db.Column(db.Boolean, default=False)

    # 事件时间 (Hook 上报时间)
    event_time = db.Column(db.DateTime, default=datetime.now)

    # 记录创建时间
    created_time = db.Column(db.DateTime, default=datetime.now)

    # 关系: 多对一 -> Experiment
    experiment = db.relationship('Experiment', backref=db.backref('events', lazy='dynamic'))

    def __repr__(self):
        return f'<ExperimentEvent [{self.event_type}] exp={self.experiment_id}>'

    @property
    def event_label(self):
        """返回事件类型的中文标签"""
        label_map = {
            'sqli_success': 'SQL注入成功',
            'xss_success': 'XSS成功',
            'command_injection_success': '命令注入成功',
            'file_upload_success': '文件上传成功',
            'csrf_success': 'CSRF成功',
            'access_control_success': '越权访问成功',
            'deserialization_success': '反序列化成功',
            'misconfig_success': '配置错误利用成功',
        }
        return label_map.get(self.event_type, self.event_type)
