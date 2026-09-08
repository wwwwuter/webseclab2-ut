"""
扫描管理路由模块
处理扫描任务创建、异步执行、进度查询、停止等功能
所有接口强制用户隔离，防止IDOR漏洞
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from app.services.scanner_service import ScannerService
from app.services.experiment_service import ExperimentService

scan_bp = Blueprint('scan', __name__)
scanner_service = ScannerService()


# ==================== 用户端路由 ====================

@scan_bp.route('/scan')
@login_required
def scan_list():
    """扫描任务列表 - 用户只能看到自己的任务"""
    page = request.args.get('page', 1, type=int)
    pagination = scanner_service.get_user_tasks(current_user.id, page=page)
    return render_template('scan/list.html', pagination=pagination)


@scan_bp.route('/scan/create', methods=['GET', 'POST'])
@login_required
def scan_create():
    """创建扫描任务并异步执行"""
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        scan_type = request.form.get('scan_type', 'socket')
        port_range = request.form.get('port_range', 'common')
        experiment_id = request.form.get('experiment_id', type=int)

        # 创建任务
        task, error = scanner_service.create_task(
            user_id=current_user.id,
            target=target,
            scan_type=scan_type,
            port_range=port_range,
            experiment_id=experiment_id
        )

        if error:
            flash(error, 'danger')
            return redirect(url_for('scan.scan_create'))

        # 异步派发到后台线程执行，立即返回
        success, dispatch_error = scanner_service.dispatch_task(task.id)

        if not success:
            flash(f'任务派发失败: {dispatch_error}', 'danger')
            return redirect(url_for('scan.scan_detail', task_id=task.id))

        flash('扫描任务已创建，正在后台执行...', 'info')
        return redirect(url_for('scan.scan_detail', task_id=task.id))

    # GET: 获取用户的实验列表供关联
    experiments = ExperimentService.get_user_experiments(current_user.id, page=1, per_page=100)
    nmap_available = scanner_service.nmap_scanner.is_available()
    return render_template('scan/create.html',
                           experiments=experiments.items,
                           nmap_available=nmap_available)


@scan_bp.route('/scan/<int:task_id>')
@login_required
def scan_detail(task_id):
    """扫描任务详情 - 带用户隔离验证"""
    task, error = scanner_service.get_task_by_id(task_id, user_id=current_user.id)
    if error:
        flash(error, 'danger')
        if '无权访问' in error:
            from flask import abort
            abort(403)
        return redirect(url_for('scan.scan_list'))

    results = scanner_service.get_task_results(task_id)
    return render_template('scan/detail.html', task=task, results=results)


# 批量删除放在 <int:task_id> 之前，防止被动态规则匹配
@scan_bp.route('/scan/batch_delete', methods=['POST'])
@login_required
def scan_batch_delete():
    """批量删除扫描任务（仅已完成/失败的任务）"""
    task_ids = request.form.getlist('task_ids')
    if not task_ids:
        flash('请选择要删除的任务', 'warning')
        return redirect(url_for('scan.scan_list'))

    deleted, skipped = scanner_service.batch_delete_tasks(task_ids, current_user.id)
    if deleted > 0:
        flash(f'已成功删除 {deleted} 个扫描任务', 'success')
    for reason in skipped:
        flash(reason, 'warning')

    return redirect(url_for('scan.scan_list'))


@scan_bp.route('/scan/<int:task_id>/delete', methods=['POST'])
@login_required
def scan_delete(task_id):
    """删除扫描任务"""
    success, error = scanner_service.delete_task(task_id, current_user.id)
    if error:
        flash(error, 'danger')
        return redirect(url_for('scan.scan_detail', task_id=task_id))
    flash('扫描任务已删除', 'success')
    return redirect(url_for('scan.scan_list'))


@scan_bp.route('/scan/<int:task_id>/stop', methods=['POST'])
@login_required
def scan_stop(task_id):
    """停止正在运行的扫描任务"""
    success, error = scanner_service.stop_task(task_id, current_user.id)
    if error:
        flash(error, 'danger')
    else:
        flash('扫描任务已停止', 'warning')
    return redirect(url_for('scan.scan_detail', task_id=task_id))


# ==================== AJAX 轮询接口 ====================

@scan_bp.route('/scan/api/status/<int:task_id>')
@login_required
def scan_api_status(task_id):
    """
    AJAX 轮询接口 - 返回任务状态、进度、结果
    前端每 2 秒调用一次，用于实时更新扫描进度

    返回字段:
        status: created/running/completed/failed
        progress: 0-100 进度百分比
        progress_message: 进度描述文字
        total_ports: 总端口数
        scanned_ports: 已扫描端口数
        is_running: 是否仍在运行
        open_ports: 开放端口数量
        results: 扫描结果列表 (仅完成时返回)
    """
    task, error = scanner_service.get_task_by_id(task_id, user_id=current_user.id)
    if error:
        return jsonify({'error': error}), 403

    is_running = task.status in ['created', 'running']

    response = {
        'status': task.status,
        'status_label': task.status_label,
        'status_badge': task.status_badge,
        'progress': task.progress or 0,
        'progress_message': task.progress_message or '',
        'total_ports': task.total_ports or 0,
        'scanned_ports': task.scanned_ports or 0,
        'is_running': is_running,
        'open_ports': task.open_ports_count,
    }

    if task.start_time:
        response['start_time'] = task.start_time.strftime('%Y-%m-%d %H:%M:%S')
    if task.end_time:
        response['end_time'] = task.end_time.strftime('%Y-%m-%d %H:%M:%S')
    if task.error_message:
        response['error_message'] = task.error_message

    # 任务完成时返回扫描结果
    if task.status in ['completed', 'failed']:
        results = scanner_service.get_task_results(task_id)
        response['results'] = [
            {
                'port': r.port,
                'protocol': r.protocol,
                'state': r.state,
                'state_badge': r.state_badge,
                'service': r.service or '-',
                'version': r.version or '-',
                'banner': r.banner[:80] + ('...' if len(r.banner) > 80 else '') if r.banner else '-',
            }
            for r in results
        ]
        # 计算耗时
        if task.start_time and task.end_time:
            response['duration'] = round((task.end_time - task.start_time).total_seconds(), 1)

    return jsonify(response)
