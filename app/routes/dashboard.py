"""
Dashboard路由模块
提供安全态势可视化面板

HTMX 集成:
- /security-dashboard/stats 返回统计卡片 HTML 片段供 HTMX 轮询刷新
- /security-dashboard/api 返回 JSON 供 ECharts 图表定时更新
"""

import json
from flask import Blueprint, render_template, jsonify, redirect, flash, url_for
from flask_login import login_required, current_user
from app.extensions import db
from app.models.user import User
from app.services.dashboard_service import DashboardService

dashboard_bp = Blueprint('dashboard', __name__)
dashboard_service = DashboardService()


@dashboard_bp.route('/security-dashboard')
@login_required
def security_dashboard():
    """安全态势Dashboard"""
    if current_user.is_admin():
        data = dashboard_service.get_admin_dashboard()
        data['ranking'] = dashboard_service.get_user_risk_ranking(limit=10)
        data['experiments'] = dashboard_service.get_dangerous_experiments(limit=10)
        return render_template('dashboard/index.html', data=data, is_admin=True)
    else:
        data = dashboard_service.get_user_dashboard(current_user.id)
        return render_template('dashboard/index.html', data=data, is_admin=False)


@dashboard_bp.route('/security-dashboard/stats')
@login_required
def dashboard_stats_partial():
    """统计卡片 HTMX 片段 — 供 hx-get 定时刷新 (每 60s)"""
    if current_user.is_admin():
        data = dashboard_service.get_admin_dashboard()
        return render_template('dashboard/_stats_admin.html', data=data)
    else:
        data = dashboard_service.get_user_dashboard(current_user.id)
        return render_template('dashboard/_stats_user.html', data=data)


@dashboard_bp.route('/security-dashboard/api')
@login_required
def dashboard_api():
    """Dashboard数据API (返回JSON供ECharts使用)"""
    if current_user.is_admin():
        data = dashboard_service.get_admin_dashboard()
    else:
        data = dashboard_service.get_user_dashboard(current_user.id)

    return jsonify(data)


@dashboard_bp.route('/security-dashboard/alerts')
@login_required
def dashboard_alerts():
    """异常告警 HTMX 片段 — 供告警区定时刷新 (仅管理员有数据)"""
    alerts = dashboard_service.get_alerts() if current_user.is_admin() else []
    return render_template('dashboard/_alerts.html', alerts=alerts)


@dashboard_bp.route('/security-dashboard/users')
@login_required
def dashboard_users():
    """用户维度下钻: 风险用户排行 + 危险实验排行 (仅管理员)"""
    if not current_user.is_admin():
        flash('无权限访问该页面', 'danger')
        return redirect(url_for('dashboard.security_dashboard'))
    ranking = dashboard_service.get_user_risk_ranking(limit=10)
    experiments = dashboard_service.get_dangerous_experiments(limit=10)
    return render_template('dashboard/_user_ranking.html',
                           ranking=ranking, experiments=experiments)


@dashboard_bp.route('/security-dashboard/users/<int:uid>')
@login_required
def dashboard_user_drill(uid):
    """单用户下钻详情 — 复用用户视图统计数据 (仅管理员)"""
    if not current_user.is_admin():
        flash('无权限访问该页面', 'danger')
        return redirect(url_for('dashboard.security_dashboard'))
    user = db.session.get(User, uid)
    if not user:
        flash('用户不存在', 'warning')
        return redirect(url_for('dashboard.dashboard_users'))
    data = dashboard_service.get_user_dashboard(uid)
    return render_template('dashboard/user_drill.html', data=data, target_user=user)
