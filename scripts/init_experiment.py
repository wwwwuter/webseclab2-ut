"""
实验模块初始化脚本
运行方式: python scripts/init_experiment.py
功能: 为test用户创建一个SQL Injection DVWA实验记录
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.services.experiment_service import ExperimentService


def init_test_experiment():
    """初始化测试实验数据"""
    app = create_app()

    with app.app_context():
        print('========== WebSecLab 实验模块初始化 ==========')

        # 1. 确保test用户存在
        test_user = User.query.filter_by(username='test').first()
        if not test_user:
            test_user = User(username='test', email='test@webeclab.local', role='user')
            test_user.set_password('test123')
            db.session.add(test_user)
            db.session.commit()
            print('[用户] 创建测试用户: test / test123')
        else:
            print('[用户] 测试用户已存在')

        # 2. 获取SQL Injection漏洞
        vuln = Vulnerability.query.filter_by(name='SQL Injection').first()
        if not vuln:
            print('[警告] 未找到SQL Injection漏洞，请先运行 init_vulnerability.py')
            # 使用第一个漏洞
            vuln = Vulnerability.query.first()
            if not vuln:
                print('[错误] 数据库无任何漏洞数据，无法创建实验')
                return

        vuln_id = vuln.id
        print(f'[漏洞] 使用漏洞: {vuln.name} (ID={vuln_id})')

        # 3. 创建实验
        experiment, error = ExperimentService.create_experiment(
            user_id=test_user.id,
            vulnerability_id=vuln_id,
            experiment_name='DVWA SQL Injection Low',
            target='http://192.168.56.101/dvwa',
            dvwa_level='low'
        )

        if error:
            print(f'[错误] {error}')
        else:
            print(f'[实验] 创建成功!')
            print(f'  名称: {experiment.experiment_name}')
            print(f'  Token: {experiment.token}')
            print(f'  状态: {experiment.status_label}')
            print(f'  DVWA等级: {experiment.dvwa_level}')

        print('========== 初始化完成 ==========')


if __name__ == '__main__':
    init_test_experiment()
