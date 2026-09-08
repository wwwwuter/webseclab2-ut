"""
认证服务模块
封装用户注册、登录验证等业务逻辑
"""

from datetime import date
from sqlalchemy import or_, case
from app.extensions import db
from app.models.user import User


class AuthService:
    """认证服务类"""

    @staticmethod
    def register(username, password, email=None):
        """
        用户注册
        :param username: 用户名
        :param password: 明文密码
        :param email: 邮箱(可选)
        :return: (User对象, 错误信息)
        """
        # 检查用户名是否已存在
        if User.query.filter_by(username=username).first():
            return None, '用户名已存在'

        # 检查邮箱是否已被使用
        if email and User.query.filter_by(email=email).first():
            return None, '邮箱已被注册'

        # 创建新用户
        user = User(username=username, email=email, role='user')
        user.set_password(password)

        db.session.add(user)
        db.session.commit()
        return user, None

    @staticmethod
    def authenticate(username, password):
        """
        用户登录验证
        :param username: 用户名
        :param password: 明文密码
        :return: User对象或None
        """
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            return user
        return None

    @staticmethod
    def get_user_by_id(user_id):
        """根据ID获取用户"""
        return db.session.get(User, user_id)

    @staticmethod
    def get_all_users():
        """获取所有用户(管理员功能)"""
        return User.query.order_by(User.created_time.desc()).all()

    # ==================== 管理后台增强功能 ====================

    @staticmethod
    def get_user_stats():
        """用户 KRI 概览统计: 总数 / 管理员 / 普通用户 / 今日新增"""
        total = User.query.count()
        admins = User.query.filter_by(role='admin').count()
        today = date.today().isoformat()
        today_new = User.query.filter(
            db.func.date(User.created_time) == today
        ).count()
        return {
            'total': total,
            'admins': admins,
            'normal': total - admins,
            'today_new': today_new,
        }

    @staticmethod
    def get_users_filtered(keyword=None, role=None, sort_by=None,
                           order='desc', page=1, per_page=15):
        """
        用户列表: 支持关键词搜索(用户名/邮箱) + 角色筛选 + 排序 + 分页
        :param keyword: 用户名或邮箱模糊匹配
        :param role: 'admin' / 'user' 精确筛选
        :param sort_by: 'username' / 'role' / 'created_time'
        :param order: 'asc' / 'desc'
        :return: Pagination 对象
        """
        query = User.query

        if keyword:
            like = f'%{keyword}%'
            query = query.filter(or_(
                User.username.ilike(like),
                User.email.ilike(like),
            ))

        if role in ('admin', 'user'):
            query = query.filter(User.role == role)

        is_asc = (order == 'asc')

        if sort_by == 'username':
            col = User.username
            query = query.order_by(col.asc() if is_asc else col.desc())
        elif sort_by == 'role':
            # 语义排序: admin 优先于 user
            role_order = case((User.role == 'admin', 0), else_=1)
            query = query.order_by(
                role_order.asc() if is_asc else role_order.desc(),
                User.created_time.desc()
            )
        elif sort_by == 'created_time':
            col = User.created_time
            query = query.order_by(col.asc() if is_asc else col.desc())
        else:
            # 默认: 最新注册在前
            query = query.order_by(User.created_time.desc())

        return query.paginate(page=page, per_page=per_page, error_out=False)

    @staticmethod
    def set_role(user_id, new_role, operator_id=None):
        """
        修改用户角色 (高危操作)
        - 校验角色合法性
        - 禁止修改自己的角色 (防自锁)
        - 禁止降级最后一名管理员
        :return: (bool 成功, str 错误信息)
        """
        if new_role not in ('admin', 'user'):
            return False, '无效的角色'

        user = db.session.get(User, user_id)
        if not user:
            return False, '用户不存在'

        if operator_id is not None and user.id == operator_id:
            return False, '不能修改自己的角色'

        if user.role == new_role:
            return False, f'用户已经是 {new_role} 角色'

        # 降级管理员前, 确保系统至少保留一名管理员
        if user.role == 'admin' and new_role != 'admin':
            admin_count = User.query.filter_by(role='admin').count()
            if admin_count <= 1:
                return False, '系统必须保留至少一名管理员'

        user.role = new_role
        db.session.commit()
        return True, None

    @staticmethod
    def delete_user(user_id, operator_id=None):
        """
        删除用户 (高危操作)
        - 禁止删除自己
        - 禁止删除最后一名管理员
        - 用户名下存在实验/扫描/报告/AI分析/风险数据时, 拒绝删除以避免产生孤儿数据
        :return: (bool 成功, str 错误信息)
        """
        user = db.session.get(User, user_id)
        if not user:
            return False, '用户不存在'

        if operator_id is not None and user.id == operator_id:
            return False, '不能删除自己'

        if user.role == 'admin':
            admin_count = User.query.filter_by(role='admin').count()
            if admin_count <= 1:
                return False, '系统必须保留至少一名管理员'

        # 检查是否存在关联数据 (避免外键孤儿)
        related = AuthService._count_user_related(user_id)
        if related:
            parts = '、'.join(f'{k} {v} 条' for k, v in related.items())
            return False, f'该用户名下存在关联数据({parts}),请先清理后再删除'

        db.session.delete(user)
        db.session.commit()
        return True, None

    @staticmethod
    def _count_user_related(user_id):
        """统计用户名下的关联业务数据 (仅返回非零项)"""
        from app.models.experiment import Experiment
        from app.models.scan import ScanTask
        from app.models.report import Report
        from app.models.ai_analysis import AIAnalysis
        from app.models.risk import RiskAssessment

        counts = {
            '实验': Experiment.query.filter_by(user_id=user_id).count(),
            '扫描任务': ScanTask.query.filter_by(user_id=user_id).count(),
            '报告': Report.query.filter_by(user_id=user_id).count(),
            'AI分析': AIAnalysis.query.filter_by(user_id=user_id).count(),
            '风险': RiskAssessment.query.filter_by(user_id=user_id).count(),
        }
        return {k: v for k, v in counts.items() if v > 0}
