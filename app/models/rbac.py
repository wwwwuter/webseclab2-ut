"""
RBAC 权限模型模块
实现企业级基于角色的访问控制 (Role-Based Access Control)

表结构:
- Role: 角色表 (Admin, Teacher, Student, Auditor, Researcher)
- Permission: 权限表 (细粒度操作权限)
- RolePermission: 角色-权限关联表 (多对多)
- UserRole: 用户-角色关联表 (多对多)

权限命名规范: resource:action
  experiment:create / experiment:view / experiment:delete
  scan:start / scan:view
  vulnerability:manage
  ai:analyze / ai:view
  report:view / report:generate
  risk:assess / risk:view
  prompt:edit / prompt:view
  knowledge:manage / knowledge:view
  dashboard:view
  user:manage
"""

from datetime import datetime
from app.extensions import db


# 角色-权限关联表 (多对多)
role_permissions = db.Table(
    'role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id'), primary_key=True),
)

# 用户-角色关联表 (多对多, 一个用户可有多个角色)
user_roles = db.Table(
    'user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True),
)


class Role(db.Model):
    """角色表"""
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # 角色唯一标识 (admin / teacher / student / auditor / researcher)
    code = db.Column(db.String(32), unique=True, nullable=False, index=True)

    # 角色显示名称
    name = db.Column(db.String(64), nullable=False)

    # 角色描述
    description = db.Column(db.Text, default='')

    # 是否启用
    is_active = db.Column(db.Boolean, default=True)

    # 创建时间
    created_time = db.Column(db.DateTime, default=datetime.now)

    # 关系: 多对多 → Permission
    permissions = db.relationship(
        'Permission', secondary=role_permissions,
        backref=db.backref('roles', lazy='dynamic'),
        lazy='dynamic'
    )

    # 关系: 多对多 → User
    users = db.relationship(
        'User', secondary=user_roles,
        backref=db.backref('rbac_roles', lazy='dynamic'),
        lazy='dynamic'
    )

    # 角色常量
    CODE_ADMIN = 'admin'
    CODE_TEACHER = 'teacher'
    CODE_STUDENT = 'student'
    CODE_AUDITOR = 'auditor'
    CODE_RESEARCHER = 'researcher'

    def __repr__(self):
        return f'<Role {self.code}: {self.name}>'

    def has_permission(self, permission_code):
        """检查角色是否拥有指定权限"""
        return self.permissions.filter_by(code=permission_code, is_active=True).first() is not None

    @property
    def permission_codes(self):
        """获取角色所有权限代码列表"""
        return [p.code for p in self.permissions.filter_by(is_active=True).all()]


class Permission(db.Model):
    """权限表"""
    __tablename__ = 'permissions'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # 权限唯一标识 (如 experiment:create)
    code = db.Column(db.String(64), unique=True, nullable=False, index=True)

    # 权限显示名称
    name = db.Column(db.String(128), nullable=False)

    # 权限描述
    description = db.Column(db.Text, default='')

    # 权限分组 (experiment / scan / ai / vulnerability / ...)
    group = db.Column(db.String(32), default='general', index=True)

    # 是否启用
    is_active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f'<Permission {self.code}: {self.name}>'

    # 权限常量
    # 实验
    EXP_CREATE = 'experiment:create'
    EXP_VIEW = 'experiment:view'
    EXP_DELETE = 'experiment:delete'
    EXP_MANAGE = 'experiment:manage'

    # 扫描
    SCAN_START = 'scan:start'
    SCAN_VIEW = 'scan:view'

    # 漏洞
    VULN_VIEW = 'vulnerability:view'
    VULN_MANAGE = 'vulnerability:manage'

    # AI
    AI_ANALYZE = 'ai:analyze'
    AI_VIEW = 'ai:view'

    # 报告
    REPORT_VIEW = 'report:view'
    REPORT_GENERATE = 'report:generate'

    # 风险评估
    RISK_ASSESS = 'risk:assess'
    RISK_VIEW = 'risk:view'

    # Prompt
    PROMPT_VIEW = 'prompt:view'
    PROMPT_EDIT = 'prompt:edit'

    # 知识图谱
    KG_VIEW = 'knowledge:view'
    KG_MANAGE = 'knowledge:manage'

    # Dashboard
    DASHBOARD_VIEW = 'dashboard:view'

    # 用户管理
    USER_MANAGE = 'user:manage'

    # 日志审计
    AUDIT_VIEW = 'audit:view'
