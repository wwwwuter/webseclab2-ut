"""
认证路由模块
处理用户注册、登录、退出
"""

import logging
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app.services.auth_service import AuthService
from app.models.login_log import LoginLog
from app.extensions import db

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """用户注册页面"""
    # 已登录用户跳转到首页
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        email = request.form.get('email', '').strip() or None

        # 输入验证
        if not username or not password:
            flash('用户名和密码不能为空', 'danger')
            return render_template('register.html')

        if len(username) < 3 or len(username) > 64:
            flash('用户名长度需在3-64个字符之间', 'danger')
            return render_template('register.html')

        if len(password) < 6:
            flash('密码长度不能少于6位', 'danger')
            return render_template('register.html')

        if password != confirm_password:
            flash('两次输入的密码不一致', 'danger')
            return render_template('register.html')

        # 调用服务层注册
        user, error = AuthService.register(username, password, email)
        if error:
            logger.warning('注册失败: username=%s, error=%s, ip=%s',
                           username, error, request.remote_addr)
            flash(error, 'danger')
            return render_template('register.html')

        logger.info('用户注册成功: username=%s, ip=%s', username, request.remote_addr)
        flash('注册成功，请登录', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """用户登录页面"""
    # 已登录用户跳转到首页
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('请输入用户名和密码', 'danger')
            return render_template('login.html')

        # 验证用户身份
        user = AuthService.authenticate(username, password)
        if user:
            login_user(user)
            logger.info('用户登录成功: username=%s, ip=%s', username, request.remote_addr)
            # 记录登录历史 (失败静默, 不影响登录主流程)
            try:
                ua = request.user_agent
                ip = request.headers.get('X-Forwarded-For', request.remote_addr) or request.remote_addr
                if ',' in ip:
                    ip = ip.split(',')[0].strip()
                db.session.add(LoginLog(
                    user_id=user.id,
                    ip_address=ip,
                    user_agent=(ua.string or '')[:256] if ua and ua.string else None,
                    browser=ua.browser if ua else None,
                    os=ua.platform if ua else None,
                ))
                db.session.commit()
            except Exception as e:
                logger.warning('登录记录写入失败(已忽略): %s', e)
            flash(f'欢迎回来, {user.username}!', 'success')
            # 跳转到登录前访问的页面或首页
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.index'))

        logger.warning('登录失败: username=%s, ip=%s', username, request.remote_addr)
        flash('用户名或密码错误', 'danger')

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """用户退出登录"""
    logger.info('用户退出: username=%s', current_user.username)
    logout_user()
    flash('已成功退出登录', 'info')
    return redirect(url_for('main.index'))
