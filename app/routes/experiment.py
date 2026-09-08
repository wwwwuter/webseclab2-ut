"""
实验管理路由模块
处理实验创建、查看、完成、管理员管理等功能
所有用户端接口强制用户隔离(user_id验证)，防止IDOR漏洞
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from app.utils.permission import admin_required
from app.services.experiment_service import ExperimentService
from app.services.vulnerability_service import VulnerabilityService
from app.models.experiment import Experiment

exp_bp = Blueprint('exp', __name__)


# ==================== 用户端路由 ====================

@exp_bp.route('/experiment')
@login_required
def exp_list():
    """实验列表 - 用户只能看到自己的实验, 支持搜索/筛选/排序 (HTMX 局部刷新)"""
    page = request.args.get('page', 1, type=int)
    keyword = request.args.get('q', '').strip()
    status = request.args.get('status', '').strip()
    dvwa_level = request.args.get('dvwa_level', '').strip()
    sort_by = request.args.get('sort', '').strip()
    order = request.args.get('order', 'desc').strip()

    pagination = ExperimentService.get_user_experiments_filtered(
        current_user.id,
        keyword=keyword or None,
        status=status or None,
        dvwa_level=dvwa_level or None,
        sort_by=sort_by or None,
        order=order,
        page=page
    )
    stats = ExperimentService.get_user_statistics(current_user.id)

    # HTMX 请求: 仅返回结果片段(不含 base.html 外壳)
    if request.headers.get('HX-Request'):
        return render_template('experiment/_list_results.html',
                               pagination=pagination,
                               keyword=keyword, status=status, dvwa_level=dvwa_level,
                               sort_by=sort_by, order=order)

    return render_template('experiment/list.html',
                           pagination=pagination, stats=stats,
                           keyword=keyword, status=status, dvwa_level=dvwa_level,
                           sort_by=sort_by, order=order)


@exp_bp.route('/experiment/create', methods=['GET', 'POST'])
@login_required
def exp_create():
    """创建实验"""
    if request.method == 'POST':
        vulnerability_id = request.form.get('vulnerability_id', type=int)
        experiment_name = request.form.get('experiment_name', '')
        target = request.form.get('target', '')
        dvwa_level = request.form.get('dvwa_level', 'low')

        # 输入验证
        if not experiment_name.strip():
            flash('请输入实验名称', 'danger')
            return redirect(url_for('exp.exp_create'))

        experiment, error = ExperimentService.create_experiment(
            user_id=current_user.id,
            vulnerability_id=vulnerability_id,
            experiment_name=experiment_name,
            target=target,
            dvwa_level=dvwa_level
        )

        if error:
            flash(error, 'danger')
            return redirect(url_for('exp.exp_create'))

        flash(f'实验 "{experiment.experiment_name}" 创建成功，Token: {experiment.token}', 'success')
        return redirect(url_for('exp.exp_detail', experiment_id=experiment.id))

    # GET: 获取漏洞列表供选择 (按分类分组) + 支持从漏洞详情预填
    categories = VulnerabilityService.get_all_categories()
    vulns_by_cat = []
    for cat in categories:
        items = VulnerabilityService.get_vulnerabilities_by_category(cat.id, page=1, per_page=200).items
        if items:
            vulns_by_cat.append({'category': cat, 'items': items})
    # 未分类漏洞单独成组
    uncategorized = VulnerabilityService.get_uncategorized_vulnerabilities()
    if uncategorized:
        vulns_by_cat.append({'category': None, 'items': uncategorized})

    prefill_vuln_id = request.args.get('vulnerability_id', type=int)
    return render_template('experiment/create.html',
                           vulns_by_cat=vulns_by_cat,
                           categories=categories,
                           prefill_vuln_id=prefill_vuln_id)


@exp_bp.route('/experiment/<int:experiment_id>')
@login_required
def exp_detail(experiment_id):
    """实验详情 - 带用户隔离验证"""
    experiment, error = ExperimentService.get_experiment_by_id(
        experiment_id, user_id=current_user.id
    )
    if error:
        flash(error, 'danger')
        if '无权访问' in error:
            from flask import abort
            abort(403)
        return redirect(url_for('exp.exp_list'))

    logs = ExperimentService.get_experiment_logs(experiment_id)
    dvwa_url, _ = ExperimentService.get_dvwa_url(experiment_id, current_user.id)

    # 关联 AI 报告 (通过 Report.experiment 反向引用)
    from app.models.report import Report
    reports = experiment.reports.order_by(Report.created_time.desc()).all()

    # 实验耗时 (完成时间 - 创建时间)
    duration_text = None
    if experiment.completed_time and experiment.created_time:
        delta = experiment.completed_time - experiment.created_time
        total_min = delta.total_seconds() / 60
        if total_min < 1:
            duration_text = '不到 1 分钟'
        elif total_min < 60:
            duration_text = f'{int(total_min)} 分钟'
        else:
            duration_text = f'{int(total_min // 60)} 小时 {int(total_min % 60)} 分钟'

    # 智能返回: 保留列表筛选/排序参数
    filters = {k: request.args.get(k, '') for k in ('q', 'status', 'dvwa_level', 'sort', 'order')}
    filter_args = {k: v for k, v in filters.items() if v}
    back_url = url_for('exp.exp_list', **filter_args) if filter_args else url_for('exp.exp_list')

    return render_template('experiment/detail.html',
                           experiment=experiment,
                           logs=logs,
                           dvwa_url=dvwa_url,
                           reports=reports,
                           duration_text=duration_text,
                           back_url=back_url)


@exp_bp.route('/experiment/<int:experiment_id>/start', methods=['POST'])
@login_required
def exp_start(experiment_id):
    """启动实验"""
    experiment, error = ExperimentService.start_experiment(experiment_id, current_user.id)
    if error:
        flash(error, 'danger')
    else:
        flash('实验已启动', 'success')
    return redirect(url_for('exp.exp_detail', experiment_id=experiment_id))


@exp_bp.route('/experiment/<int:experiment_id>/complete', methods=['GET', 'POST'])
@login_required
def exp_complete(experiment_id):
    """完成实验 - 提交结果"""
    # 先验证权限
    experiment, error = ExperimentService.get_experiment_by_id(
        experiment_id, user_id=current_user.id
    )
    if error:
        flash(error, 'danger')
        if '无权访问' in error:
            from flask import abort
            abort(403)
        return redirect(url_for('exp.exp_list'))

    if request.method == 'POST':
        result_text = request.form.get('result', '')
        status = request.form.get('status', 'success')

        updated, error = ExperimentService.complete_experiment(
            experiment_id, current_user.id, result_text, status
        )
        if error:
            flash(error, 'danger')
        else:
            flash('实验结果已提交', 'success')
            return redirect(url_for('exp.exp_detail', experiment_id=experiment_id))

    return render_template('experiment/result.html', experiment=experiment)


@exp_bp.route('/experiment/<int:experiment_id>/close', methods=['POST'])
@login_required
def exp_close(experiment_id):
    """关闭实验"""
    experiment, error = ExperimentService.close_experiment(experiment_id, current_user.id)
    if error:
        flash(error, 'danger')
    else:
        flash('实验已关闭', 'info')
    return redirect(url_for('exp.exp_detail', experiment_id=experiment_id))


@exp_bp.route('/experiment/<int:experiment_id>/delete', methods=['POST'])
@login_required
def exp_delete(experiment_id):
    """删除实验"""
    success, error = ExperimentService.delete_experiment(experiment_id, current_user.id)
    if error:
        flash(error, 'danger')
        return redirect(url_for('exp.exp_detail', experiment_id=experiment_id))
    flash('实验已删除', 'success')
    return redirect(url_for('exp.exp_list'))


# ==================== 管理员端路由 ====================

@exp_bp.route('/admin/experiment')
@login_required
@admin_required
def admin_exp_list():
    """管理员查看所有实验 - 支持关键词/状态/DVWA等级 多维筛选 (HTMX 局部刷新)"""
    page = request.args.get('page', 1, type=int)
    keyword = request.args.get('q', '').strip()
    status = request.args.get('status', '').strip()
    dvwa_level = request.args.get('dvwa_level', '').strip()
    sort_by = request.args.get('sort', '').strip()
    order = request.args.get('order', 'desc').strip()

    pagination = ExperimentService.get_experiments_filtered(
        keyword=keyword or None,
        status=status or None,
        dvwa_level=dvwa_level or None,
        page=page,
        sort_by=sort_by or None,
        order=order
    )
    stats = ExperimentService.get_admin_statistics()
    dvwa_levels = Experiment.DVWA_LEVELS

    if request.headers.get('HX-Request'):
        return render_template('experiment/_admin_list_results.html',
                               pagination=pagination,
                               keyword=keyword, status=status, dvwa_level=dvwa_level,
                               sort_by=sort_by, order=order)

    return render_template('experiment/admin_list.html',
                           pagination=pagination, stats=stats, dvwa_levels=dvwa_levels,
                           keyword=keyword, status=status, dvwa_level=dvwa_level,
                           sort_by=sort_by, order=order)


@exp_bp.route('/admin/experiment/<int:experiment_id>')
@login_required
@admin_required
def admin_exp_detail(experiment_id):
    """管理员查看任意实验详情 (绕过所有者校验)"""
    experiment, error = ExperimentService.get_experiment_by_id(experiment_id, user_id=None)
    if error:
        flash(error, 'danger')
        return redirect(url_for('exp.admin_exp_list'))
    logs = ExperimentService.get_experiment_logs(experiment_id)
    dvwa_url, _ = ExperimentService.get_dvwa_url(experiment_id, user_id=None)
    return render_template('experiment/detail.html',
                           experiment=experiment, logs=logs, dvwa_url=dvwa_url,
                           admin_view=True)


@exp_bp.route('/admin/experiment/<int:experiment_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_exp_delete(experiment_id):
    """管理员删除任意实验 (绕过所有者校验)"""
    success, error = ExperimentService.delete_experiment(experiment_id, user_id=None)
    if error:
        flash(error, 'danger')
    else:
        flash('实验已删除', 'success')
    return redirect(url_for('exp.admin_exp_list'))
