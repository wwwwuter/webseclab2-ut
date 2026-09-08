"""
报告管理路由模块
处理报告生成、列表、下载、删除
"""

import os
import json
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file
from flask_login import login_required, current_user
from markupsafe import escape
from app.services.report_service import ReportService
from app.services.experiment_service import ExperimentService

report_bp = Blueprint('report', __name__)
report_service = ReportService()


@report_bp.route('/report')
@login_required
def report_list():
    """报告列表 - 用户只能看自己的 (支持类型/状态筛选 + 标题搜索 + 排序)"""
    page = request.args.get('page', 1, type=int)
    report_type = request.args.get('type', '').strip()
    status = request.args.get('status', '').strip()
    keyword = request.args.get('q', '').strip()
    sort_by = request.args.get('sort', 'created_time').strip()
    order = request.args.get('order', 'desc').strip()

    pagination = report_service.get_user_reports(
        current_user.id, page=page,
        report_type=report_type or None,
        status=status or None,
        keyword=keyword or None,
        sort_by=sort_by, order=order,
    )
    stats = report_service.get_user_report_stats(current_user.id)
    return render_template('report/list.html',
                           pagination=pagination, stats=stats,
                           report_type=report_type, status=status,
                           keyword=keyword, sort_by=sort_by, order=order)


@report_bp.route('/report/create/<int:experiment_id>', methods=['POST'])
@login_required
def report_create(experiment_id):
    """生成实验报告"""
    report, error = report_service.create_experiment_report(
        user_id=current_user.id,
        experiment_id=experiment_id
    )

    if error:
        flash(f'报告生成失败: {error}', 'danger')
    else:
        flash('报告生成成功!', 'success')

    return redirect(url_for('report.report_list'))


@report_bp.route('/report/<int:report_id>')
@login_required
def report_detail(report_id):
    """报告详情 - MD/JSON 报告内联预览 (内容经转义, 防 XSS)"""
    report, error = report_service.get_report_by_id(report_id, user_id=current_user.id)
    if error:
        flash(error, 'danger')
        if '无权访问' in error:
            from flask import abort
            abort(403)
        return redirect(url_for('report.report_list'))

    preview = None
    if report.status == 'generated' and report.report_type in ('mcp_md', 'mcp_json'):
        try:
            filepath = os.path.join(report_service.output_dir, report.file_path)
            with open(filepath, 'r', encoding='utf-8') as f:
                raw = f.read()
            if report.report_type == 'mcp_json':
                try:
                    preview = escape(json.dumps(json.loads(raw), ensure_ascii=False, indent=2))
                except (json.JSONDecodeError, ValueError):
                    preview = escape(raw)
            else:
                # Markdown 以转义后的纯文本展示, 规避 XSS
                preview = escape(raw)
        except (OSError, FileNotFoundError):
            preview = None

    return render_template('report/detail.html', report=report, preview=preview)


@report_bp.route('/report/download/<int:report_id>')
@login_required
def report_download(report_id):
    """下载报告文件 (支持 PDF/Markdown/JSON)"""
    filepath, download_name, mime_type, error = report_service.get_report_file(
        report_id, current_user.id
    )
    if error:
        flash(error, 'danger')
        return redirect(url_for('report.report_list'))

    return send_file(
        filepath,
        as_attachment=True,
        download_name=download_name,
        mimetype=mime_type,
    )


@report_bp.route('/report/<int:report_id>/delete', methods=['POST'])
@login_required
def report_delete(report_id):
    """删除报告"""
    success, error = report_service.delete_report(report_id, current_user.id)
    if error:
        flash(error, 'danger')
    else:
        flash('报告已删除', 'success')
    return redirect(url_for('report.report_list'))
