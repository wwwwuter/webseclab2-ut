"""
权限控制装饰器模块
实现 RBAC 基于角色的访问控制

支持两种模式:
1. @admin_required — 传统管理员检查 (向后兼容)
2. @permission_required('experiment:create') — 细粒度权限检查

权限检查逻辑:
- 先检查用户是否为 admin (role 字段) → 如果是, 拥有所有权限
- 再检查用户的 RBAC 角色是否包含所需权限
- 两者任一通过即可访问
"""

from functools import wraps
from flask import abort
from flask_login import current_user


def admin_required(f):
    """
    管理员权限装饰器
    仅允许role=admin的用户访问，否则返回403
    使用方式:
        @app.route('/admin')
        @login_required
        @admin_required
        def admin_page():
            ...
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def permission_required(*permission_codes):
    """
    细粒度权限检查装饰器

    用法:
        @login_required
        @permission_required('experiment:create')
        def create_experiment():
            ...

        @login_required
        @permission_required('ai:analyze', 'ai:view')  # 任一权限即可
        def ai_page():
            ...

    检查逻辑:
    1. Admin (role=admin) → 全部通过
    2. 检查用户 RBAC 角色是否包含指定权限之一
    3. 通过 → 继续; 不通过 → 403
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)

            # Admin 拥有所有权限
            if current_user.is_admin():
                return f(*args, **kwargs)

            # 检查 RBAC 角色权限
            if _check_user_permissions(current_user, permission_codes):
                return f(*args, **kwargs)

            abort(403)
        return decorated_function
    return decorator


def _check_user_permissions(user, permission_codes):
    """
    检查用户是否拥有指定权限之一

    :param user: User 模型实例
    :param permission_codes: 权限代码元组
    :return: bool
    """
    try:
        from app.models.rbac import Role, Permission

        # 获取用户的 RBAC 角色
        if not hasattr(user, 'rbac_roles'):
            return False

        user_roles = user.rbac_roles.filter_by(is_active=True).all()
        if not user_roles:
            return False

        # 检查每个角色是否包含任一所需权限
        for role in user_roles:
            for code in permission_codes:
                if role.has_permission(code):
                    return True

        return False

    except Exception:
        # RBAC 表不存在或查询失败时, 降级为仅 Admin 可访问
        return False


def get_user_permissions(user):
    """
    获取用户所有权限代码集合

    :param user: User 模型实例
    :return: set of permission codes
    """
    permissions = set()

    # Admin 拥有所有权限
    if user.is_admin():
        try:
            from app.models.rbac import Permission
            all_perms = Permission.query.filter_by(is_active=True).all()
            return {p.code for p in all_perms}
        except Exception:
            return {'*'}  # 通配符表示全部权限

    try:
        if hasattr(user, 'rbac_roles'):
            for role in user.rbac_roles.filter_by(is_active=True).all():
                permissions.update(role.permission_codes)
    except Exception:
        pass

    return permissions
