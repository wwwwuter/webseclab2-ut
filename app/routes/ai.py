"""
AI分析路由模块
处理AI漏洞分析的创建、流式输出、查看、历史等功能
支持SSE (Server-Sent Events) 实时推送模型输出
"""

from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, jsonify, Response)
from flask_login import login_required, current_user
from app.services.ai_service import AIService
from app.services.experiment_service import ExperimentService
from app.services.scanner_service import ScannerService
from app.extensions import db

ai_bp = Blueprint('ai', __name__)


def _get_ai():
    """按需创建 AIService, 确保在请求上下文中读取 LLM 配置"""
    return AIService()


# ==================== 分析历史列表 ====================

@ai_bp.route('/ai/history')
@login_required
def ai_history():
    """AI分析历史列表 - 支持搜索/筛选/排序, HTMX 局部刷新"""
    page = request.args.get('page', 1, type=int)
    keyword = request.args.get('q', '').strip()
    source = request.args.get('source', '').strip()
    risk_level = request.args.get('risk', '').strip()
    status = request.args.get('status', '').strip()
    sort_by = request.args.get('sort', 'created_time')
    order = request.args.get('order', 'desc')

    pagination = _get_ai().get_user_analyses(
        current_user.id, page=page,
        keyword=keyword or None,
        source=source or None,
        risk_level=risk_level or None,
        status=status or None,
        sort_by=sort_by,
        order=order
    )
    ollama_available = _get_ai().is_available()
    stats = _get_ai().get_user_statistics(current_user.id)

    if request.headers.get('HX-Request'):
        return render_template('ai/_history_results.html',
                               pagination=pagination,
                               keyword=keyword, source=source,
                               risk_level=risk_level, status=status,
                               sort_by=sort_by, order=order)

    return render_template('ai/history.html',
                           pagination=pagination,
                           ollama_available=ollama_available,
                           stats=stats,
                           keyword=keyword, source=source,
                           risk_level=risk_level, status=status,
                           sort_by=sort_by, order=order)


# ==================== 从实验创建分析 ====================

@ai_bp.route('/ai/analyze/<int:experiment_id>', methods=['GET', 'POST'])
@login_required
def ai_analyze_experiment(experiment_id):
    """基于实验执行AI分析 (SSE流式)"""
    if not _get_ai().is_available():
        flash('Ollama服务未启动，请先运行: ollama serve', 'danger')
        return redirect(url_for('ai.ai_history'))

    if request.method == 'POST':
        model = request.form.get('model', '').strip() or None

        # 准备分析: 创建AIAnalysis记录, 构建Prompt
        gen, error = _get_ai().stream_experiment_analysis(
            user_id=current_user.id,
            experiment_id=experiment_id,
            model=model
        )

        if error:
            flash(f'AI分析失败: {error}', 'danger')
            return redirect(url_for('exp.exp_list'))

        # 返回 SSE 流式响应
        return Response(gen, mimetype='text/event-stream',
                        headers={'Cache-Control': 'no-cache',
                                 'X-Accel-Buffering': 'no'})

    # GET: 显示实验信息和模型选择
    experiment, exp_error = ExperimentService.get_experiment_by_id(
        experiment_id, user_id=current_user.id
    )
    if exp_error:
        flash(exp_error, 'danger')
        return redirect(url_for('exp.exp_list'))

    models = _get_ai().get_models()
    return render_template('ai/analysis.html',
                           experiment=experiment,
                           models=models,
                           analysis_type='experiment')


# ==================== 从扫描任务创建分析 ====================

@ai_bp.route('/ai/analyze-scan/<int:scan_task_id>', methods=['GET', 'POST'])
@login_required
def ai_analyze_scan(scan_task_id):
    """基于扫描任务执行AI分析 (SSE流式)"""
    if not _get_ai().is_available():
        flash('Ollama服务未启动，请先运行: ollama serve', 'danger')
        return redirect(url_for('ai.ai_history'))

    if request.method == 'POST':
        model = request.form.get('model', '').strip() or None

        gen, error = _get_ai().stream_scan_analysis(
            user_id=current_user.id,
            scan_task_id=scan_task_id,
            model=model
        )

        if error:
            flash(f'AI分析失败: {error}', 'danger')
            return redirect(url_for('scan.scan_list'))

        return Response(gen, mimetype='text/event-stream',
                        headers={'Cache-Control': 'no-cache',
                                 'X-Accel-Buffering': 'no'})

    scan_svc = ScannerService()
    task, task_error = scan_svc.get_task_by_id(scan_task_id, user_id=current_user.id)
    if task_error:
        flash(task_error, 'danger')
        return redirect(url_for('scan.scan_list'))

    models = _get_ai().get_models()
    return render_template('ai/analysis.html',
                           task=task,
                           models=models,
                           analysis_type='scan')


# ==================== 自定义分析 ====================

@ai_bp.route('/ai/custom', methods=['GET', 'POST'])
@login_required
def ai_custom():
    """自定义文本AI分析 (SSE流式)"""
    if not _get_ai().is_available():
        flash('Ollama服务未启动，请先运行: ollama serve', 'danger')
        return redirect(url_for('ai.ai_history'))

    if request.method == 'POST':
        input_data = request.form.get('input_data', '').strip()
        model = request.form.get('model', '').strip() or None
        scene = request.form.get('scene', 'general').strip() or 'general'
        use_rag = request.form.get('use_rag') == 'on'

        if not input_data:
            flash('请输入要分析的内容', 'warning')
            return redirect(url_for('ai.ai_custom'))

        gen, error = _get_ai().stream_custom_analysis(
            user_id=current_user.id,
            input_data=input_data,
            model=model,
            scene=scene,
            use_rag=use_rag
        )

        if error:
            flash(f'AI分析失败: {error}', 'danger')
            return redirect(url_for('ai.ai_custom'))

        return Response(gen, mimetype='text/event-stream',
                        headers={'Cache-Control': 'no-cache',
                                 'X-Accel-Buffering': 'no'})

    models = _get_ai().get_models()
    prefill = request.args.get('prefill', '').strip()
    return render_template('ai/analysis.html',
                           models=models,
                           analysis_type='custom',
                           prefill=prefill)


# ==================== 分析结果详情 ====================

@ai_bp.route('/ai/result/<int:analysis_id>')
@login_required
def ai_result(analysis_id):
    """AI分析结果详情页"""
    analysis, error = _get_ai().get_analysis_by_id(analysis_id, user_id=current_user.id)
    if error:
        flash(error, 'danger')
        if '无权访问' in error:
            from flask import abort
            abort(403)
        return redirect(url_for('ai.ai_history'))
    return render_template('ai/result.html', analysis=analysis)


# ==================== 分析结果状态查询 (AJAX) ====================

@ai_bp.route('/ai/api/status/<int:analysis_id>')
@login_required
def ai_api_status(analysis_id):
    """查询分析结果状态 (用于前端轮询)"""
    analysis, error = _get_ai().get_analysis_by_id(analysis_id, user_id=current_user.id)
    if error:
        return jsonify({'error': error}), 403

    return jsonify({
        'status': analysis.status,
        'status_label': analysis.status_label,
        'risk_level': analysis.risk_level,
        'risk_label': analysis.risk_label,
        'risk_badge': analysis.risk_badge,
        'error_message': analysis.error_message or '',
        'vulnerability_analysis': analysis.vulnerability_analysis or '',
        'possible_attack': analysis.possible_attack or '',
        'impact': analysis.impact or '',
        'fix_solution': analysis.fix_solution or '',
        'security_advice': analysis.security_advice or '',
        'model': analysis.model or '',
    })


# ==================== 删除分析 ====================

@ai_bp.route('/ai/<int:analysis_id>/delete', methods=['POST'])
@login_required
def ai_delete(analysis_id):
    """删除AI分析结果 (支持 HTMX 局部刷新)"""
    success, error = _get_ai().delete_analysis(analysis_id, current_user.id)
    if error:
        flash(error, 'danger')
        if request.headers.get('HX-Request'):
            # HTMX 删除失败: 原样返回结果片段 (行不变), 错误提示在下次整页加载时显示
            return _render_history_partial()
        return redirect(url_for('ai.ai_history'))
    flash('分析结果已删除', 'success')
    if request.headers.get('HX-Request'):
        return _render_history_partial()
    return redirect(url_for('ai.ai_history'))


def _render_history_partial():
    """根据当前查询参数重新渲染历史列表片段 (供 HTMX 删除后局部刷新)"""
    page = request.args.get('page', 1, type=int)
    keyword = request.args.get('q', '').strip()
    source = request.args.get('source', '').strip()
    risk_level = request.args.get('risk', '').strip()
    status = request.args.get('status', '').strip()
    sort_by = request.args.get('sort', 'created_time')
    order = request.args.get('order', 'desc')
    pagination = _get_ai().get_user_analyses(
        current_user.id, page=page,
        keyword=keyword or None,
        source=source or None,
        risk_level=risk_level or None,
        status=status or None,
        sort_by=sort_by,
        order=order
    )
    return render_template('ai/_history_results.html',
                           pagination=pagination,
                           keyword=keyword, source=source,
                           risk_level=risk_level, status=status,
                           sort_by=sort_by, order=order)


# ==================== 管理后台: Prompt模板管理 ====================

@ai_bp.route('/ai/admin/templates')
@login_required
def admin_templates():
    """Prompt模板管理列表 (仅管理员) — 支持搜索/场景筛选 (HTMX 局部刷新)"""
    if not current_user.is_admin():
        from flask import abort
        abort(403)

    from app.models.prompt_template import PromptTemplate
    keyword = request.args.get('q', '').strip()
    scene = request.args.get('scene', '').strip()

    query = PromptTemplate.query
    if keyword:
        like = f'%{keyword}%'
        query = query.filter(db.or_(
            PromptTemplate.name.ilike(like),
            PromptTemplate.template_key.ilike(like),
            PromptTemplate.description.ilike(like),
        ))
    if scene:
        query = query.filter(PromptTemplate.scene == scene)

    templates = query.order_by(PromptTemplate.id).all()

    if request.headers.get('HX-Request'):
        return render_template('_admin_templates_list.html',
                               templates=templates, keyword=keyword, scene=scene)

    return render_template('ai/admin_templates.html',
                           templates=templates, keyword=keyword, scene=scene)


@ai_bp.route('/ai/admin/templates/edit/<int:template_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_template(template_id):
    """编辑Prompt模板"""
    if not current_user.is_admin():
        from flask import abort
        abort(403)

    from app.models.prompt_template import PromptTemplate
    template = db.session.get(PromptTemplate, template_id)
    if not template:
        flash('模板不存在', 'danger')
        return redirect(url_for('ai.admin_templates'))

    if request.method == 'POST':
        new_content = request.form.get('content', '').strip()
        new_name = request.form.get('name', '').strip()
        new_desc = request.form.get('description', '').strip()
        new_scene = request.form.get('scene', 'general').strip()
        is_active = request.form.get('is_active') == 'on'

        if not new_content:
            flash('模板内容不能为空', 'warning')
        else:
            template.content = new_content
            if new_name:
                template.name = new_name
            template.description = new_desc
            template.scene = new_scene
            template.is_active = is_active
            # 版本号自增 (便于版本追踪)
            template.version = (template.version or 1) + 1
            db.session.commit()
            flash(f'模板 "{template.name}" 已更新 (v{template.version})', 'success')
            return redirect(url_for('ai.admin_templates'))

    return render_template('ai/admin_edit_template.html', template=template)


@ai_bp.route('/ai/admin/templates/create', methods=['GET', 'POST'])
@login_required
def admin_create_template():
    """新增Prompt模板"""
    if not current_user.is_admin():
        from flask import abort
        abort(403)

    from app.models.prompt_template import PromptTemplate

    if request.method == 'POST':
        template_key = request.form.get('template_key', '').strip()
        name = request.form.get('name', '').strip()
        scene = request.form.get('scene', 'general').strip()
        description = request.form.get('description', '').strip()
        content = request.form.get('content', '').strip()
        variables = request.form.get('variables', '{}').strip()
        is_active = request.form.get('is_active') == 'on'

        if not template_key or not name or not content:
            flash('模板标识、名称和内容为必填项', 'warning')
        else:
            existing = PromptTemplate.query.filter_by(template_key=template_key).first()
            if existing:
                flash(f'模板标识 "{template_key}" 已存在', 'warning')
            else:
                tmpl = PromptTemplate(
                    template_key=template_key,
                    name=name,
                    scene=scene,
                    description=description,
                    content=content,
                    available_variables=variables,
                    is_default=False,
                    is_active=is_active,
                    version=1,
                )
                db.session.add(tmpl)
                db.session.commit()
                flash(f'模板 "{name}" 创建成功', 'success')
                return redirect(url_for('ai.admin_templates'))

    return render_template('ai/admin_create_template.html')


@ai_bp.route('/ai/admin/templates/toggle/<int:template_id>', methods=['POST'])
@login_required
def admin_toggle_template(template_id):
    """切换模板启用/禁用"""
    if not current_user.is_admin():
        from flask import abort
        abort(403)

    from app.models.prompt_template import PromptTemplate
    template = db.session.get(PromptTemplate, template_id)
    if not template:
        flash('模板不存在', 'danger')
    else:
        template.is_active = not template.is_active
        db.session.commit()
        state = '启用' if template.is_active else '禁用'
        flash(f'模板 "{template.name}" 已{state}', 'success')

    return redirect(url_for('ai.admin_templates'))


@ai_bp.route('/ai/admin/templates/delete/<int:template_id>', methods=['POST'])
@login_required
def admin_delete_template(template_id):
    """删除模板 — 系统默认模板 (is_default) 禁止删除"""
    if not current_user.is_admin():
        from flask import abort
        abort(403)

    from app.models.prompt_template import PromptTemplate
    template = db.session.get(PromptTemplate, template_id)
    if not template:
        flash('模板不存在', 'danger')
    elif template.is_default:
        flash(f'系统默认模板 "{template.name}" 不可删除', 'danger')
    else:
        db.session.delete(template)
        db.session.commit()
        flash(f'模板 "{template.name}" 已删除', 'success')

    return redirect(url_for('ai.admin_templates'))


@ai_bp.route('/ai/admin/templates/reset/<int:template_id>', methods=['POST'])
@login_required
def admin_reset_template(template_id):
    """重置模板为默认内容"""
    if not current_user.is_admin():
        from flask import abort
        abort(403)

    from app.models.prompt_template import PromptTemplate
    from app.services.prompt_service import PromptBuilder

    template = db.session.get(PromptTemplate, template_id)
    if not template:
        flash('模板不存在', 'danger')
        return redirect(url_for('ai.admin_templates'))

    default_content = PromptBuilder.DEFAULT_TEMPLATES.get(template.template_key)
    if default_content:
        template.content = default_content
        # 重置视为一次内容变更, 版本号自增以保持审计一致
        template.version = (template.version or 1) + 1
        db.session.commit()
        flash(f'模板 "{template.name}" 已重置为默认内容 (v{template.version})', 'success')
    else:
        flash('未找到默认模板内容', 'warning')

    return redirect(url_for('ai.admin_templates'))
