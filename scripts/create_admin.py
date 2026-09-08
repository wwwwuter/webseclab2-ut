"""
初始化管理员账号脚本
运行方式: python scripts/create_admin.py
自动创建: username=admin, password=admin123, role=admin
"""

import sys
import os

# 将项目根目录加入Python路径
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from app import create_app
from app.extensions import db
from app.models.user import User


def create_admin():
    """创建初始管理员账号"""
    app = create_app()

    with app.app_context():
        # 检查管理员是否已存在
        admin = User.query.filter_by(username='admin').first()
        if admin:
            print('[信息] 管理员账号已存在，跳过创建')
            print(f'  用户名: {admin.username}')
            print(f'  角色: {admin.role}')
            return

        # 创建管理员
        admin = User(
            username='admin',
            email='admin@webeclab.local',
            role='admin'
        )
        admin.set_password('admin123')

        db.session.add(admin)
        db.session.commit()

        print('[成功] 管理员账号创建完成!')
        print('  用户名: admin')
        print('  密码: admin123')
        print('  角色: admin')
        print('\n[警告] 请在生产环境中修改默认密码!')


if __name__ == '__main__':
    create_admin()
