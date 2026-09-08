"""
个人中心路由模块

定位：用户资料与账号管理（与首页 Dashboard 职责分离）。
不展示统计图 / 趋势 / AI 图表，仅提供：
  - 基本资料（头像 / 用户名 / 用户ID / 角色 / 邮箱 / 注册时间 / 最近登录）
  - 账号管理（修改头像 / 昵称 / 邮箱 / 密码，AJAX 提交 + Toast）
  - 我的数据（实验 / 扫描 / AI分析 / 报告 四个点击统计卡）
  - 最近登录（读取 LoginLog，最多 5 条）
"""

import os

from flask import (
    Blueprint, render_template, request, jsonify, current_app, url_for,
)
from flask_login import login_required, current_user

from app.extensions import db
from app.models.user import User
from app.models.login_log import LoginLog
from app.services.dashboard_service import DashboardService

profile_bp = Blueprint('profile', __name__, template_folder='../templates')
_dash = DashboardService()

# 头像上传约束
ALLOWED_AVATAR_EXT = {'png', 'jpg', 'jpeg'}
AVATAR_MAX_BYTES = 2 * 1024 * 1024  # 2MB


def _resolve_avatar(user_id):
    """根据 user_id 查找已上传头像，返回 static url 或 None（无列，按文件约定）"""
    base = os.path.join(current_app.root_path, 'static', 'uploads', 'avatars')
    for ext in ALLOWED_AVATAR_EXT:
        if os.path.exists(os.path.join(base, f'{user_id}.{ext}')):
            return url_for('static', filename=f'uploads/avatars/{user_id}.{ext}')
    return None


@profile_bp.route('/profile')
@login_required
def index():
    """个人中心主页"""
    user = current_user
    stats = _dash._get_user_stats(user.id)
    history = (
        LoginLog.query.filter_by(user_id=user.id)
        .order_by(LoginLog.login_time.desc()).limit(5).all()
    )
    last_login = history[0].login_time if history else user.created_time
    return render_template(
        'profile/profile.html',
        user=user,
        stats=stats,
        history=history,
        last_login=last_login,
        avatar_url=_resolve_avatar(user.id),
    )


@profile_bp.route('/profile/edit')
@login_required
def edit():
    """账号管理编辑页"""
    return render_template(
        'profile/edit_profile.html',
        user=current_user,
        avatar_url=_resolve_avatar(current_user.id),
    )


@profile_bp.route('/profile/api/update', methods=['POST'])
@login_required
def api_update():
    """AJAX 修改昵称 / 邮箱"""
    data = request.get_json(silent=True) or request.form
    nickname = (data.get('nickname') or '').strip()
    email = (data.get('email') or '').strip()
    user = current_user

    if email and email != (user.email or ''):
        if '@' not in email or '.' not in email.split('@')[-1]:
            return jsonify(ok=False, msg='邮箱格式不正确')
        if User.query.filter(User.email == email, User.id != user.id).first():
            return jsonify(ok=False, msg='该邮箱已被其他账号使用')
        user.email = email

    if nickname:
        if len(nickname) > 32:
            return jsonify(ok=False, msg='昵称不能超过 32 个字符')
        user.nickname = nickname

    db.session.commit()
    return jsonify(ok=True, msg='保存成功')


@profile_bp.route('/profile/api/change-password', methods=['POST'])
@login_required
def api_change_password():
    """AJAX 修改密码（需当前密码校验 + 二次确认）"""
    data = request.get_json(silent=True) or request.form
    current = data.get('current', '') or ''
    new = data.get('new', '') or ''
    confirm = data.get('confirm', '') or ''

    if not current_user.check_password(current):
        return jsonify(ok=False, msg='当前密码错误')
    if len(new) < 6:
        return jsonify(ok=False, msg='新密码至少 6 位')
    if new != confirm:
        return jsonify(ok=False, msg='两次输入的新密码不一致')

    current_user.set_password(new)
    db.session.commit()
    return jsonify(ok=True, msg='密码修改成功')


@profile_bp.route('/profile/api/avatar', methods=['POST'])
@login_required
def api_avatar():
    """AJAX 上传头像（PNG/JPG/JPEG，≤2MB）"""
    f = request.files.get('avatar')
    if not f or not f.filename:
        return jsonify(ok=False, msg='未选择文件')

    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
    if ext not in ALLOWED_AVATAR_EXT:
        return jsonify(ok=False, msg='仅支持 PNG / JPG / JPEG 格式')

    f.seek(0, os.SEEK_END)
    size = f.tell()
    f.seek(0)
    if size == 0:
        return jsonify(ok=False, msg='文件为空')
    if size > AVATAR_MAX_BYTES:
        return jsonify(ok=False, msg='图片大小不能超过 2MB')

    base = os.path.join(current_app.root_path, 'static', 'uploads', 'avatars')
    os.makedirs(base, exist_ok=True)
    # 清除该用户旧头像，避免多扩展名残留
    for e in ALLOWED_AVATAR_EXT:
        old = os.path.join(base, f'{current_user.id}.{e}')
        if os.path.exists(old):
            os.remove(old)

    path = os.path.join(base, f'{current_user.id}.{ext}')
    f.save(path)
    return jsonify(
        ok=True,
        msg='头像已更新',
        url=url_for('static', filename=f'uploads/avatars/{current_user.id}.{ext}'),
    )


@profile_bp.route('/profile/api/login-history')
@login_required
def api_login_history():
    """AJAX 获取最近登录记录（最多 5 条）"""
    history = (
        LoginLog.query.filter_by(user_id=current_user.id)
        .order_by(LoginLog.login_time.desc()).limit(5).all()
    )
    return jsonify(ok=True, items=[{
        'login_time': h.login_time.strftime('%Y-%m-%d %H:%M') if h.login_time else '',
        'ip_address': h.ip_address or '-',
        'browser': h.browser or '未知',
        'os': h.os or '未知',
    } for h in history])
