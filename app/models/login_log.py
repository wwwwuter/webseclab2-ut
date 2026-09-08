"""
登录记录模型

记录用户每次登录的时间 / IP / User-Agent / 浏览器 / 操作系统，
供个人中心「最近登录」模块展示（最多 5 条）。
"""

from datetime import datetime

from app.extensions import db


class LoginLog(db.Model):
    """登录记录表"""

    __tablename__ = 'login_logs'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # 关联用户
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # 登录时间
    login_time = db.Column(db.DateTime, default=datetime.now)

    # 登录 IP（已处理 X-Forwarded-For 取首个）
    ip_address = db.Column(db.String(64), nullable=True)

    # 原始 User-Agent
    user_agent = db.Column(db.String(256), nullable=True)

    # 解析后的浏览器（如 Chrome / Firefox，未知为 None）
    browser = db.Column(db.String(64), nullable=True)

    # 解析后的操作系统（如 Windows / Macintosh / Linux，未知为 None）
    os = db.Column(db.String(64), nullable=True)

    def __repr__(self):
        return f'<LoginLog user={self.user_id} {self.login_time} {self.ip_address}>'
