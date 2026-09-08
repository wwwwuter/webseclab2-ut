"""
风险评估路由模块
提供风险评估的手动创建、自动评估、历史查看和统计API

路由:
  /risk                    - 风险评估历史列表
  /risk/<id>               - 评估详情 (含评分明细可视化)
  /risk/assess/experiment  - 对实验自动评估 (POST)
  /risk/assess/scan        - 对扫描任务自动评估 (POST)
  /risk/manual             - 手动创建评估 (管理员)
  /risk/api/stats          - 统计 JSON API
  /risk/api/distribution   - 风险分布 JSON API
  /risk/api/trend          - 评分趋势 JSON API
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from app.services.risk_service import RiskEngine
from app.utils.permission import admin_required

risk_bp = Blueprint('risk', __name__)
risk_engine = RiskEngine()


# ==================== 用户端路由 ====================

@risk_bp.route('/risk')
@login_required
def risk_list():
    """风险评估历史列表 — admin 查看全平台, 普通用户仅自己的"""
    user_id = None if current_user.is_admin() else current_user.id
    page = request.args.get('page', 1, type=int)
    pagination = risk_engine.get_user_assessments(user_id, page=page)
    stats = risk_engine.get_statistics(user_id=user_id)
    distribution = risk_engine.get_risk_distribution(user_id=user_id)
    return render_template('risk/list.html',
                           pagination=pagination, stats=stats,
                           distribution=distribution)


@risk_bp.route('/risk/<int:assessment_id>')
@login_required
def risk_detail(assessment_id):
    """评估详情 — 含评分明细可视化"""
    import json
    user_id = None if current_user.is_admin() else current_user.id
    assessment, error = risk_engine.get_assessment_by_id(assessment_id, user_id=user_id)
    if error:
        flash(error, 'warning')
        return redirect(url_for('risk.risk_list'))

    detail = {}
    try:
        detail = json.loads(assessment.scoring_detail) if assessment.scoring_detail else {}
    except (json.JSONDecodeError, TypeError):
        pass

    return render_template('risk/detail.html',
                           assessment=assessment, detail=detail)


@risk_bp.route('/risk/<int:assessment_id>/delete', methods=['POST'])
@login_required
def risk_delete(assessment_id):
    """删除风险评估记录 (管理员可删任意, 普通用户仅自己的)"""
    user_id = None if current_user.is_admin() else current_user.id
    success, error = risk_engine.delete_assessment(assessment_id, user_id)
    if error:
        flash(error, 'danger')
    else:
        flash('评估记录已删除', 'success')
    return redirect(url_for('risk.risk_list'))


@risk_bp.route('/risk/batch-delete', methods=['POST'])
@login_required
def risk_batch_delete():
    """批量删除风险评估记录 (HTMX 局部刷新)"""
    import json as _json

    ids_raw = request.form.get('ids', '[]')
    try:
        assessment_ids = _json.loads(ids_raw)
    except _json.JSONDecodeError:
        assessment_ids = []

    user_id = None if current_user.is_admin() else current_user.id
    deleted, error = risk_engine.batch_delete_assessments(assessment_ids, user_id)

    is_htmx = request.headers.get('HX-Request') == 'true'
    if error:
        if is_htmx:
            from flask import render_template_string
            return render_template_string(
                '<div class="alert alert-danger py-1 mb-0 small">{{ msg }}</div>',
                msg=error,
            )
        flash(error, 'danger')
        return redirect(url_for('risk.risk_list'))

    if is_htmx:
        # HTMX: 返回更新后的列表片段 + 重新渲染统计卡片
        page = request.form.get('page', 1, type=int)
        pagination = risk_engine.get_user_assessments(user_id, page=page)
        stats = risk_engine.get_statistics(user_id=user_id)
        distribution = risk_engine.get_risk_distribution(user_id=user_id)

        # 渲染列表区域 (含统计卡 + 表格 + 分页)
        html = render_template('risk/_list_section.html',
                              pagination=pagination, stats=stats,
                              distribution=distribution)
        return html

    flash(f'成功删除 {deleted} 条评估记录', 'success')
    return redirect(url_for('risk.risk_list'))


@risk_bp.route('/risk/assess/experiment', methods=['POST'])
@login_required
def assess_experiment():
    """对实验进行自动风险评估"""
    experiment_id = request.form.get('experiment_id', type=int)
    if not experiment_id:
        flash('请指定实验', 'warning')
        return redirect(url_for('risk.risk_list'))

    assessment, error = risk_engine.assess_from_experiment(experiment_id, current_user.id)
    if error:
        flash(error, 'danger')
    else:
        flash(f'风险评估完成: {assessment.final_score:.1f} 分 ({assessment.risk_label})', 'success')
    return redirect(url_for('risk.risk_list'))


@risk_bp.route('/risk/assess/scan', methods=['POST'])
@login_required
def assess_scan():
    """对扫描任务进行自动风险评估"""
    scan_id = request.form.get('scan_id', type=int)
    if not scan_id:
        flash('请指定扫描任务', 'warning')
        return redirect(url_for('risk.risk_list'))

    assessment, error = risk_engine.assess_from_scan(scan_id, current_user.id)
    if error:
        flash(error, 'danger')
    else:
        flash(f'风险评估完成: {assessment.final_score:.1f} 分 ({assessment.risk_label})', 'success')
    return redirect(url_for('risk.risk_list'))


@risk_bp.route('/risk/batch', methods=['POST'])
@login_required
def batch_assess():
    """批量评估所有未评估的实验"""
    created = risk_engine.batch_assess_experiments(current_user.id)
    flash(f'批量评估完成: 新增 {created} 条评估记录', 'success')
    return redirect(url_for('risk.risk_list'))


# ==================== 管理员端路由 ====================

@risk_bp.route('/risk/manual', methods=['GET', 'POST'])
@login_required
@admin_required
def manual_assess():
    """手动创建风险评估 (管理员)"""
    if request.method == 'POST':
        assessment = risk_engine.calculate(
            cvss=request.form.get('cvss', 5.0, type=float),
            asset=request.form.get('asset', 5.0, type=float),
            exploit=request.form.get('exploit', 5.0, type=float),
            exposure=request.form.get('exposure', 5.0, type=float),
            ai_conf=request.form.get('ai_conf', 5.0, type=float),
            user_id=current_user.id,
            source='manual'
        )
        flash(f'手动评估完成: {assessment.final_score:.1f} 分 ({assessment.risk_label})', 'success')
        return redirect(url_for('risk.risk_detail', assessment_id=assessment.id))

    return render_template('risk/manual.html')


# ==================== JSON API (供 Dashboard 和 ECharts 使用) ====================

@risk_bp.route('/risk/api/stats')
@login_required
def api_stats():
    """风险评估统计概览"""
    user_id = None if current_user.is_admin() else current_user.id
    return jsonify(risk_engine.get_statistics(user_id=user_id))


@risk_bp.route('/risk/api/distribution')
@login_required
def api_distribution():
    """风险等级分布"""
    user_id = None if current_user.is_admin() else current_user.id
    return jsonify(risk_engine.get_risk_distribution(user_id=user_id))


@risk_bp.route('/risk/api/trend')
@login_required
def api_trend():
    """评分趋势 (最近30天)"""
    days = request.args.get('days', 30, type=int)
    user_id = None if current_user.is_admin() else current_user.id
    return jsonify(risk_engine.get_score_trend(user_id=user_id, days=days))
