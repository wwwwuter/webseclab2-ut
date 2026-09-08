"""
主路由模块
处理首页、仪表盘、管理员页面等
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from app.utils.permission import admin_required
from app.services.auth_service import AuthService
from app.services.dashboard_service import DashboardService
from app.services.system_status_service import SystemStatusService
from app.services.vulnerability_service import VulnerabilityService
from app.services.experiment_service import ExperimentService
from app.models.experiment import Experiment

main_bp = Blueprint('main', __name__)
dashboard_service = DashboardService()
system_status_service = SystemStatusService()


@main_bp.route('/')
def index():
    """首页 - 公开访问展示平台总览; 登录后展示「安全实验态势中心」9 模块大屏"""
    # 平台总览 (所有访客可见) — 模块②核心指标(未登录态)
    overview = dashboard_service.get_platform_overview()
    # 系统状态: 仅用缓存占位渲染, 不触发实时探测 -> 首页瞬时返回;
    # 真实状态由前端 JS 异步调用 /api/system-status 补齐 (懒加载)
    system_status = system_status_service.get_status_safe()
    # 登录用户附加 9 模块聚合数据
    home = None
    admin_summary = None
    if current_user.is_authenticated:
        home = dashboard_service.get_home_dashboard(current_user.id)
        if current_user.is_admin():
            admin_summary = dashboard_service.get_admin_home_summary()
    return render_template('dashboard/home.html', overview=overview,
                           system_status=system_status, home=home,
                           admin_summary=admin_summary)


@main_bp.route('/api/system-status')
def system_status_api():
    """系统状态 JSON 接口 — 供首页状态卡 AJAX 异步填充, 避免阻塞首页渲染

    返回: [{'key','name','status','detail'}, ...]  (实时探测, 带 TTL 缓存)
    """
    return jsonify(system_status_service.get_status())


# ==================== 首页「安全实验态势中心」JSON 接口 (登录态) ====================
# 前端 dashboard.js 通过 Fetch 拉取, 实现 AJAX 局部刷新; 不触发整页刷新。

@main_bp.route('/api/dashboard/my-experiments')
@login_required
def api_dash_my_experiments():
    """模块⑤ 我的实验"""
    return jsonify(dashboard_service.get_my_experiments(current_user.id, limit=3))


@main_bp.route('/api/dashboard/trends')
@login_required
def api_dash_trends():
    """模块⑥ 风险趋势 (扫描次数/漏洞数量/风险指数 三序列)"""
    return jsonify(dashboard_service.get_home_trends(user_id=current_user.id, days=7))


@main_bp.route('/api/dashboard/risk-distribution')
@login_required
def api_dash_risk_dist():
    """模块⑦ 漏洞风险分布"""
    return jsonify(dashboard_service.get_home_risk_distribution(current_user.id))


@main_bp.route('/api/dashboard/copilot')
@login_required
def api_dash_copilot():
    """模块④ AI 安全助手摘要"""
    return jsonify(dashboard_service.get_ai_copilot_summary(current_user.id))


@main_bp.route('/api/dashboard/activity')
@login_required
def api_dash_activity():
    """模块⑧ 最近活动"""
    return jsonify(dashboard_service.get_recent_activity(current_user.id, limit=8))


@main_bp.route('/api/dashboard/recommendation')
@login_required
def api_dash_reco():
    """模块⑨ 今日推荐"""
    return jsonify(dashboard_service.get_daily_recommendation(current_user.id) or {})


@main_bp.route('/api/dashboard/admin-summary')
@login_required
@admin_required
def api_dash_admin():
    """管理员首页折叠面板摘要"""
    return jsonify(dashboard_service.get_admin_home_summary())


@main_bp.route('/dashboard')
def dashboard():
    """用户中心已合并进首页「统一工作台」, 此处直接重定向回首页

    登录态首页即个人工作台 (含统计/明细/图表/最近活动/快捷操作);
    未登录态首页展示平台欢迎与总览。两条入口合并为单一页面。
    """
    return redirect(url_for('main.index'))


@main_bp.route('/admin')
@login_required
@admin_required
def admin_panel():
    """管理员统一工作台 — 用户管理 + 漏洞管理 + 实验管理 合并为 Tab 页

    三个管理员功能在同一页面用 Bootstrap 标签页切换:
    - 用户管理: 筛选/排序/分页走本路由 (HX-Request 返回 _admin_user_list 片段)
    - 漏洞管理 / 实验管理: 初始数据在此汇聚, 筛选/分页由各自路由经 HTMX
      局部刷新 #admin-vuln-results / #admin-exp-results
    """
    # ---- 用户管理筛选 (本路由负责) ----
    page = request.args.get('page', 1, type=int)
    keyword = request.args.get('q', '').strip()
    role = request.args.get('role', '').strip()
    sort_by = request.args.get('sort', '').strip()
    order = request.args.get('order', 'desc').strip()

    pagination = AuthService.get_users_filtered(
        keyword=keyword or None,
        role=role or None,
        sort_by=sort_by or None,
        order=order,
        page=page,
    )
    user_stats = AuthService.get_user_stats()

    # HTMX 局部刷新 (用户筛选/排序/分页) — 仅返回表格片段
    if request.headers.get('HX-Request'):
        return render_template('_admin_user_list.html',
                               pagination=pagination,
                               keyword=keyword, role=role,
                               sort_by=sort_by, order=order)

    # ---- 漏洞管理初始数据 (筛选走 vuln.admin_vuln_list 的 HTMX) ----
    vuln_categories = VulnerabilityService.get_all_categories()
    vuln_pagination = VulnerabilityService.get_vulnerabilities_filtered(page=1)
    vuln_stats = VulnerabilityService.get_statistics()

    # ---- 实验管理初始数据 (筛选走 exp.admin_exp_list 的 HTMX) ----
    exp_pagination = ExperimentService.get_experiments_filtered(page=1)
    exp_stats = ExperimentService.get_admin_statistics()
    exp_dvwa_levels = Experiment.DVWA_LEVELS

    return render_template('admin.html',
                           user_stats=user_stats, user_pagination=pagination,
                           user_keyword=keyword, user_role=role,
                           user_sort_by=sort_by, user_order=order,
                           vuln_stats=vuln_stats, vuln_pagination=vuln_pagination,
                           vuln_categories=vuln_categories,
                           vuln_keyword='', vuln_severity='', vuln_source='',
                           vuln_category=None, vuln_sort_by='', vuln_order='desc',
                           exp_stats=exp_stats, exp_pagination=exp_pagination,
                           exp_dvwa_levels=exp_dvwa_levels,
                           exp_keyword='', exp_status='', exp_dvwa_level='',
                           exp_sort_by='', exp_order='desc')


@main_bp.route('/admin/user/<int:user_id>/role', methods=['POST'])
@login_required
@admin_required
def admin_user_role(user_id):
    """修改用户角色 (高危, 禁止改自己 / 保留最后管理员)"""
    new_role = request.form.get('role', '').strip()
    success, error = AuthService.set_role(
        user_id, new_role, operator_id=current_user.id
    )
    if error:
        flash(error, 'danger')
    else:
        flash('用户角色已更新', 'success')
    return redirect(url_for('main.admin_panel'))


@main_bp.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_user_delete(user_id):
    """删除用户 (高危, 禁止删自己 / 保留最后管理员 / 有关联数据则拒绝)"""
    success, error = AuthService.delete_user(
        user_id, operator_id=current_user.id
    )
    if error:
        flash(error, 'danger')
    else:
        flash('用户已删除', 'success')
    return redirect(url_for('main.admin_panel'))
