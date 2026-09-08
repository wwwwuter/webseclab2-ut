"""
WebSecLab 应用工厂模块
create_app() 创建并配置Flask应用实例
"""

import os
from flask import Flask
from app.config import config_map
from app.extensions import db, migrate, login_manager, csrf
from app.logging_config import setup_logging, get_logger

logger = get_logger(__name__)


def create_app(config_name=None):
    """
    应用工厂函数
    :param config_name: 配置环境名称 (development/testing/production)
    :return: Flask应用实例
    """
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'default')

    app = Flask(__name__)
    app.config.from_object(config_map[config_name])

    # 初始化结构化日志系统
    setup_logging(app)

    # 初始化扩展组件
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)

    # 注册Blueprint
    from app.routes.auth import auth_bp
    from app.routes.main import main_bp
    from app.routes.vulnerability import vuln_bp
    from app.routes.experiment import exp_bp
    from app.routes.scan import scan_bp
    from app.routes.ai import ai_bp
    from app.routes.report import report_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.risk import risk_bp
    from app.routes.mcp import mcp_bp
    from app.routes.knowledge_graph import kg_bp
    from app.routes.profile import profile_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(vuln_bp)
    app.register_blueprint(exp_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(ai_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(risk_bp)
    app.register_blueprint(mcp_bp)
    app.register_blueprint(kg_bp)
    app.register_blueprint(profile_bp)

    # 注册自定义 Jinja 过滤器 (轻量文本渲染: 换行 + 行内/围栏代码块)
    _register_filters(app)

    # 导入模型，确保SQLAlchemy能发现所有表
    from app import models

    # 首次运行时自动创建数据库表
    with app.app_context():
        db.create_all()

        # 种子 Prompt 模板到数据库 (仅首次)
        _seed_prompt_templates()

        # 种子 RBAC 角色和权限 (仅首次)
        _seed_rbac()

        # 历史库补 display_id 列并回填 (扫描列表「ID」列改为用户内唯一)
        _ensure_scan_display_id()

        # 漏洞表补 cvss_score 列 (历史库可能缺此列)
        _ensure_vulnerability_schema()

        # AI分析表补 scene 列 (历史库可能缺此列)
        _ensure_ai_analysis_schema()

        # 用户表补 nickname 列 (个人中心展示名, 历史库可能缺此列)
        _ensure_user_schema()

    # 注册错误处理
    register_error_handlers(app)

    logger.info('WebSecLab 应用初始化完成 [config=%s]', config_name)
    return app


def _register_filters(app):
    """注册自定义 Jinja 过滤器 (轻量文本渲染, 不引入 Markdown 库)"""
    import html as _html
    import re as _re
    from markupsafe import Markup

    _FENCED = _re.compile(r'```[^\n]*\n(.*?)```', _re.DOTALL)

    def light_format(text):
        """将漏洞正文渲染为安全 HTML:
        - 先整体 HTML 转义, 杜绝 XSS
        - 围栏代码块 ```...``` -> <pre><code>
        - 行内 `code` -> <code>
        - 其余换行 -> <br>
        """
        if not text:
            return Markup('')
        escaped = _html.escape(text)
        segments = []
        last = 0
        for m in _FENCED.finditer(escaped):
            segments.append(escaped[last:m.start()])
            segments.append(
                '\n<pre class="bg-light border rounded p-2"><code>'
                + m.group(1)
                + '</code></pre>\n'
            )
            last = m.end()
        segments.append(escaped[last:])
        body = ''.join(segments)
        # 行内代码 (围栏块内已无反引号, 不会误伤)
        body = _re.sub(r'`([^`\n]+)`', r'<code>\1</code>', body)
        # 换行转 <br>
        body = body.replace('\n', '<br>')
        return Markup(body)

    app.jinja_env.filters['light_format'] = light_format


def _ensure_vulnerability_schema():
    """同步 vulnerabilities 表结构到最新模型 (create_all 不会给已存在的表加列)。

    仅补 cvss_score 一列; 其他列由 create_all 在建表时保证。
    全程使用原始 SQL, 避免 ORM mapper 在列尚未就绪时报错。
    """
    from sqlalchemy import text
    import logging
    log = logging.getLogger(__name__)

    try:
        db_cols = [r[0] for r in db.session.execute(
            text('PRAGMA table_info(vulnerabilities)')
        ).fetchall()]

        if 'cvss_score' not in db_cols:
            try:
                db.session.execute(
                    text('ALTER TABLE vulnerabilities ADD COLUMN cvss_score FLOAT')
                )
                db.session.commit()
                db.engine.dispose()
                log.info('[migration] 已添加 vulnerabilities.cvss_score')
            except Exception as e:
                if 'duplicate' not in str(e).lower():
                    raise
    except Exception as e:
        log.error('[migration] vulnerabilities 表结构同步失败: %s', e, exc_info=True)


def _ensure_scan_display_id():
    """同步 scan_tasks 表结构到最新模型 (create_all 不会给已存在的表加列)。

    历史库可能缺少模型中定义的列 (如 experiment_id/error_message/progress 等),
    导致 ORM 查询报 no such column。此函数在启动时检测并补齐所有缺失列,
    并回填 display_id (用户内展示序号)。
    全程使用原始 SQL (text), 避免 ORM mapper 在列尚未就绪时报错。
    """
    from sqlalchemy import text
    import logging
    log = logging.getLogger(__name__)

    # 模型 ScanTask 的完整列定义 (需与 app/models/scan.py 保持一致)
    _SCAN_TASK_COLS = {
        'experiment_id':    'INTEGER',
        'error_message':    "TEXT DEFAULT ''",
        'start_time':       'DATETIME',
        'end_time':         'DATETIME',
        'progress':         'INTEGER DEFAULT 0',
        'progress_message': "VARCHAR(256) DEFAULT ''",
        'total_ports':      'INTEGER DEFAULT 0',
        'scanned_ports':    'INTEGER DEFAULT 0',
        'display_id':       'INTEGER',
    }

    try:
        db_cols = [r[0] for r in db.session.execute(
            text('PRAGMA table_info(scan_tasks)')
        ).fetchall()]

        added = []
        for col_name, col_type in _SCAN_TASK_COLS.items():
            if col_name not in db_cols:
                try:
                    db.session.execute(
                        text(f'ALTER TABLE scan_tasks ADD COLUMN {col_name} {col_type}')
                    )
                    added.append(col_name)
                    log.info('[migration] 已添加 scan_tasks.%s', col_name)
                except Exception as e:
                    # 列已存在 (并发/手动补过) 则跳过
                    if 'duplicate' not in str(e).lower():
                        raise

        if added:
            db.session.commit()
            db.engine.dispose()
            log.info('[migration] 补列完成: %s (连接池已刷新)', ', '.join(added))

        # 回填 display_id IS NULL 的行 (幂等)
        null_rows = db.session.execute(
            text('SELECT COUNT(*) FROM scan_tasks WHERE display_id IS NULL')
        ).scalar()
        if null_rows > 0:
            users = db.session.execute(
                text('SELECT DISTINCT user_id FROM scan_tasks WHERE display_id IS NULL')
            ).fetchall()
            total = 0
            for (uid,) in users:
                rows = db.session.execute(
                    text('SELECT id FROM scan_tasks WHERE user_id=:u AND display_id IS NULL ORDER BY id'),
                    {'u': uid}
                ).fetchall()
                for seq, (rid,) in enumerate(rows, 1):
                    db.session.execute(
                        text('UPDATE scan_tasks SET display_id=:d WHERE id=:r'),
                        {'d': seq, 'r': rid}
                    )
                    total += 1
            db.session.commit()
            db.engine.dispose()
            log.info('[migration] 回填 display_id: %d 行', total)

    except Exception as e:
        log.error('[migration] 表结构同步失败: %s', e, exc_info=True)


def _ensure_ai_analysis_schema():
    """同步 ai_analyses 表结构到最新模型 (create_all 不会给已存在的表加列)。

    仅补 scene 一列; 全程使用原始 SQL, 避免 ORM mapper 在列尚未就绪时报错。
    """
    from sqlalchemy import text
    import logging
    log = logging.getLogger(__name__)

    try:
        db_cols = [r[0] for r in db.session.execute(
            text('PRAGMA table_info(ai_analyses)')
        ).fetchall()]

        if 'scene' not in db_cols:
            try:
                db.session.execute(
                    text("ALTER TABLE ai_analyses ADD COLUMN scene VARCHAR(32) DEFAULT 'general'")
                )
                db.session.commit()
                db.engine.dispose()
                log.info('[migration] 已添加 ai_analyses.scene')
            except Exception as e:
                if 'duplicate' not in str(e).lower():
                    raise
    except Exception as e:
        log.error('[migration] ai_analyses 表结构同步失败: %s', e, exc_info=True)


def _ensure_user_schema():
    """同步 users 表结构到最新模型 (create_all 不会给已存在的表加列)。

    仅补 nickname 一列; 其他列由 create_all 在建表时保证。
    全程使用原始 SQL, 避免 ORM mapper 在列尚未就绪时报错。
    """
    from sqlalchemy import text
    import logging
    log = logging.getLogger(__name__)

    try:
        db_cols = [r[0] for r in db.session.execute(
            text('PRAGMA table_info(users)')
        ).fetchall()]

        if 'nickname' not in db_cols:
            try:
                db.session.execute(
                    text('ALTER TABLE users ADD COLUMN nickname VARCHAR(64)')
                )
                db.session.commit()
                db.engine.dispose()
                log.info('[migration] 已添加 users.nickname')
            except Exception as e:
                if 'duplicate' not in str(e).lower():
                    raise
    except Exception as e:
        log.error('[migration] users 表结构同步失败: %s', e, exc_info=True)


def register_error_handlers(app):
    """注册HTTP错误处理"""

    @app.errorhandler(403)
    def forbidden(e):
        from flask import render_template
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(e):
        from flask import render_template
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(e):
        from flask import render_template
        logger = get_logger('error_handler')
        logger.error('服务器内部错误: %s', e)
        return render_template('errors/500.html'), 500


def _seed_prompt_templates():
    """种子 Prompt 模板到数据库"""
    try:
        from app.services.prompt_service import PromptBuilder
        created = PromptBuilder.seed_default_templates()
        if created:
            logger.info('已创建 %d 个默认 Prompt 模板', created)
    except Exception as e:
        logger.warning('Prompt模板种子失败: %s', e)


def _seed_rbac():
    """种子 RBAC 角色和权限到数据库"""
    try:
        from app.models.rbac import Role, Permission, role_permissions
        from app.extensions import db as _db

        # ===== 定义权限 =====
        permissions_def = [
            # (code, name, group)
            ('experiment:create', '创建实验', 'experiment'),
            ('experiment:view', '查看实验', 'experiment'),
            ('experiment:delete', '删除实验', 'experiment'),
            ('experiment:manage', '管理所有实验', 'experiment'),
            ('scan:start', '启动扫描', 'scan'),
            ('scan:view', '查看扫描', 'scan'),
            ('vulnerability:view', '查看漏洞知识库', 'vulnerability'),
            ('vulnerability:manage', '管理漏洞知识库', 'vulnerability'),
            ('ai:analyze', 'AI分析', 'ai'),
            ('ai:view', '查看AI结果', 'ai'),
            ('report:view', '查看报告', 'report'),
            ('report:generate', '生成报告', 'report'),
            ('risk:assess', '风险评估', 'risk'),
            ('risk:view', '查看风险评估', 'risk'),
            ('prompt:view', '查看Prompt模板', 'prompt'),
            ('prompt:edit', '编辑Prompt模板', 'prompt'),
            ('knowledge:view', '查看知识图谱', 'knowledge'),
            ('knowledge:manage', '管理知识图谱', 'knowledge'),
            ('dashboard:view', '查看Dashboard', 'dashboard'),
            ('user:manage', '用户管理', 'admin'),
            ('audit:view', '查看审计日志', 'admin'),
        ]

        perm_objects = {}
        created_perms = 0
        for code, name, group in permissions_def:
            existing = Permission.query.filter_by(code=code).first()
            if not existing:
                perm = Permission(code=code, name=name, group=group, is_active=True)
                _db.session.add(perm)
                perm_objects[code] = perm
                created_perms += 1
            else:
                perm_objects[code] = existing

        if created_perms > 0:
            _db.session.commit()

        # ===== 定义角色及其权限 =====
        roles_def = {
            'admin': {
                'name': '管理员',
                'description': '拥有所有权限, 管理平台全部功能',
                'permissions': [p[0] for p in permissions_def],  # 所有权限
            },
            'teacher': {
                'name': '教师',
                'description': '管理课程实验、查看学生数据、管理漏洞知识库',
                'permissions': [
                    'experiment:create', 'experiment:view', 'experiment:manage',
                    'scan:start', 'scan:view',
                    'vulnerability:view', 'vulnerability:manage',
                    'ai:analyze', 'ai:view',
                    'report:view', 'report:generate',
                    'risk:assess', 'risk:view',
                    'prompt:view', 'prompt:edit',
                    'knowledge:view', 'knowledge:manage',
                    'dashboard:view',
                ],
            },
            'student': {
                'name': '学生',
                'description': '进行实验、扫描、查看自己的数据和报告',
                'permissions': [
                    'experiment:create', 'experiment:view',
                    'scan:start', 'scan:view',
                    'vulnerability:view',
                    'ai:analyze', 'ai:view',
                    'report:view', 'report:generate',
                    'risk:assess', 'risk:view',
                    'knowledge:view',
                    'dashboard:view',
                ],
            },
            'auditor': {
                'name': '审计员',
                'description': '查看日志、报告和风险评估记录',
                'permissions': [
                    'experiment:view',
                    'scan:view',
                    'vulnerability:view',
                    'ai:view',
                    'report:view',
                    'risk:view',
                    'prompt:view',
                    'knowledge:view',
                    'dashboard:view',
                    'audit:view',
                ],
            },
            'researcher': {
                'name': '研究员',
                'description': '高级扫描、AI实验、Prompt管理和知识图谱',
                'permissions': [
                    'experiment:create', 'experiment:view',
                    'scan:start', 'scan:view',
                    'vulnerability:view', 'vulnerability:manage',
                    'ai:analyze', 'ai:view',
                    'report:view', 'report:generate',
                    'risk:assess', 'risk:view',
                    'prompt:view', 'prompt:edit',
                    'knowledge:view', 'knowledge:manage',
                    'dashboard:view',
                ],
            },
        }

        created_roles = 0
        for role_code, meta in roles_def.items():
            existing = Role.query.filter_by(code=role_code).first()
            if not existing:
                role = Role(
                    code=role_code,
                    name=meta['name'],
                    description=meta['description'],
                    is_active=True,
                )
                _db.session.add(role)
                _db.session.flush()  # 获取 role.id

                # 关联权限
                for perm_code in meta['permissions']:
                    perm = perm_objects.get(perm_code)
                    if perm:
                        role.permissions.append(perm)

                created_roles += 1
            else:
                # 角色已存在, 补充缺失的权限关联
                for perm_code in meta['permissions']:
                    perm = perm_objects.get(perm_code)
                    if perm and not existing.has_permission(perm_code):
                        existing.permissions.append(perm)

        if created_roles > 0:
            _db.session.commit()
            logger.info('已创建 %d 个 RBAC 角色, %d 个权限', created_roles, created_perms)
        elif created_perms > 0:
            _db.session.commit()
            logger.info('已补充 %d 个新权限到现有角色', created_perms)

    except Exception as e:
        logger.warning('RBAC种子失败: %s', e)


def _index_vulnerabilities():
    """为漏洞知识库构建 ChromaDB 向量索引"""
    try:
        from app.models.vulnerability import Vulnerability
        from app.services.chroma_service import ChromaService
        vulns = Vulnerability.query.all()
        if vulns:
            chroma = ChromaService()
            count = chroma.index_vulnerabilities(vulns)
            logger.info('ChromaDB: 已索引 %d 条漏洞记录', count)
    except Exception as e:
        logger.warning('ChromaDB索引失败: %s', e)
