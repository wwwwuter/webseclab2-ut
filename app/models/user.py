"""
用户模型模块
定义User表结构、密码加密、Flask-Login集成
"""

from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db, login_manager


class User(UserMixin, db.Model):
    """用户模型类"""
    __tablename__ = 'users'

    # 主键
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # 用户名，唯一，不可为空
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)

    # 密码摘要，禁止明文存储
    password_hash = db.Column(db.String(256), nullable=False)

    # 角色: admin(管理员) / user(普通用户)
    role = db.Column(db.String(16), nullable=False, default='user')

    # 邮箱，唯一
    email = db.Column(db.String(128), unique=True, nullable=True)

    # 昵称（可选，默认与用户名相同；用于个人中心展示）
    nickname = db.Column(db.String(64), nullable=True)

    # 创建时间
    created_time = db.Column(db.DateTime, default=datetime.now)

    def display_name(self):
        """展示名：优先昵称，否则用户名"""
        return self.nickname or self.username

    def set_password(self, password):
        """对明文密码进行Hash加密并保存"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """验证明文密码是否与存储的Hash匹配"""
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        """判断用户是否为管理员"""
        return self.role == 'admin'

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login回调: 根据user_id加载用户对象"""
    return db.session.get(User, int(user_id))
