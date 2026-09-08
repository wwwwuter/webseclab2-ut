"""
WebSecLab 扩展组件统一管理
所有Flask扩展在此处初始化，禁止在业务代码中重复创建
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect

# 数据库实例
db = SQLAlchemy()

# 数据库迁移实例
migrate = Migrate()

# 登录管理器实例
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = '请先登录后再访问该页面'
login_manager.login_message_category = 'warning'

# CSRF 防护实例 (CSRFProtect); 实际开关由配置 WTF_CSRF_ENABLED 控制
csrf = CSRFProtect()
