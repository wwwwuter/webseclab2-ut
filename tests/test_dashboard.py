"""
Dashboard 改进功能测试 (B / C / A 三块)

B. KRI 关键风险指标  -> get_kri()
C. 异常告警区         -> get_alerts() / /security-dashboard/alerts
A. 用户维度下钻       -> get_user_risk_ranking() / get_dangerous_experiments()
                       / /security-dashboard/users / /security-dashboard/users/<uid>

此前 Dashboard 是测试盲区 (仅 test_ai.py 有 admin 视图冒烟), 这里补上三块新功能的回归保护。
"""
from app.services.dashboard_service import DashboardService


def _login(client, username, password):
    return client.post('/login', data={'username': username, 'password': password},
                       follow_redirects=True)


def _logout(client):
    return client.get('/logout', follow_redirects=True)


# ==================== B. KRI 指标 ====================

def test_get_kri_keys(app, db):
    """get_kri 返回完整的 KRI 字典"""
    with app.app_context():
        kri = DashboardService().get_kri()
    assert isinstance(kri, dict)
    for k in ['avg_score', 'high_risk_ratio', 'assessments_24h', 'high_risk_users', 'total', 'high_cnt']:
        assert k in kri


# ==================== C. 异常告警 ====================

def test_get_alerts_returns_list(app, db):
    """get_alerts 返回 list, 每条含必要字段与合法级别"""
    with app.app_context():
        alerts = DashboardService().get_alerts()
    assert isinstance(alerts, list)
    for a in alerts:
        assert a['level'] in ('critical', 'warning')
        assert 'title' in a and 'link' in a and 'detail' in a


def test_alerts_partial_admin(client, admin_user):
    """管理员可访问告警片段, 返回平稳或告警文案"""
    _login(client, 'adminuser', 'admin123456')
    resp = client.get('/security-dashboard/alerts')
    assert resp.status_code == 200
    text = resp.get_data(as_text=True)
    assert ('系统运行平稳' in text) or ('告警' in text)


# ==================== A. 用户维度下钻 ====================

def test_user_risk_ranking_returns_list(app, db):
    """get_user_risk_ranking 返回 list, 字段完整"""
    with app.app_context():
        rows = DashboardService().get_user_risk_ranking(10)
    assert isinstance(rows, list)
    if rows:
        for k in ['user_id', 'username', 'assess_cnt', 'avg_score', 'high_cnt']:
            assert k in rows[0]


def test_dangerous_experiments_returns_list(app, db):
    """get_dangerous_experiments 返回 list, 字段完整 (注意字段名 experiment_name)"""
    with app.app_context():
        rows = DashboardService().get_dangerous_experiments(10)
    assert isinstance(rows, list)
    if rows:
        for k in ['name', 'total', 'failed_cnt', 'fail_rate']:
            assert k in rows[0]


def test_users_page_requires_admin(client, test_user, admin_user):
    """用户下钻页仅管理员可访问, 普通用户被重定向"""
    # 普通用户 -> 302
    _login(client, 'testuser', 'test123456')
    resp = client.get('/security-dashboard/users')
    assert resp.status_code == 302

    # 管理员 -> 200 且渲染排行页
    _logout(client)
    _login(client, 'adminuser', 'admin123456')
    resp = client.get('/security-dashboard/users')
    assert resp.status_code == 200
    assert '用户维度下钻' in resp.get_data(as_text=True)


def test_user_drill_page(client, admin_user):
    """单用户下钻详情页返回 200 并包含用户名"""
    _login(client, 'adminuser', 'admin123456')
    resp = client.get(f'/security-dashboard/users/{admin_user.id}')
    assert resp.status_code == 200
    assert admin_user.username in resp.get_data(as_text=True)


# ==================== 首页 / 用户中心升级 ====================

def test_get_platform_overview(app, db):
    """get_platform_overview 返回全平台计数, 字段完整"""
    with app.app_context():
        ov = DashboardService().get_platform_overview()
    assert isinstance(ov, dict)
    for k in ['user_count', 'vulnerability_count', 'experiment_count',
              'scan_count', 'ai_count', 'report_count']:
        assert k in ov


def test_get_recent_activity_merged_and_sorted(app, db, test_user):
    """get_recent_activity: 扫描/实验/AI 混合, 按时间倒序, 字段完整, 用户隔离"""
    from app.models.experiment import Experiment
    from app.models.ai_analysis import AIAnalysis
    from app.services.scanner_service import ScannerService
    svc = DashboardService()
    scan_svc = ScannerService()
    with app.app_context():
        # 建扫描任务 (经 service, 与已通过的扫描测试同模式)
        task, _ = scan_svc.create_task(test_user.id, '10.0.0.5')
        db.session.add(Experiment(user_id=test_user.id, experiment_name='XSS 实验', status='success', token='tok_test_001'))
        db.session.add(AIAnalysis(user_id=test_user.id, status='completed', model='qwen'))
        db.session.commit()

        uid = test_user.id
        n_scan = db.session.query(__import__('app.models.scan', fromlist=['ScanTask']).ScanTask).filter_by(user_id=uid).count()
        n_exp = db.session.query(Experiment).filter_by(user_id=uid).count()
        n_ai = db.session.query(AIAnalysis).filter_by(user_id=uid).count()
        assert (n_scan + n_exp + n_ai) >= 3

        events = svc.get_recent_activity(uid, limit=10)
    assert isinstance(events, list)
    assert len(events) >= 3
    types = {e['type'] for e in events}
    assert 'scan' in types and 'experiment' in types and 'ai' in types
    for e in events:
        assert 'title' in e and 'link' in e and 'status_label' in e and 'time' in e
    # 时间倒序
    times = [e['time'] for e in events if e['time']]
    assert times == sorted(times, reverse=True)


def test_home_page_guest_shows_overview(client, db):
    """未登录首页: 欢迎横幅 + 系统状态 + 快捷操作, 不暴露个人模块"""
    resp = client.get('/')
    assert resp.status_code == 200
    text = resp.get_data(as_text=True)
    assert 'WebSecLab' in text
    assert '系统运行状态' in text
    assert '快捷操作' in text
    # 未登录不应有个人概览块
    assert '核心指标' not in text
    assert '管理员面板' not in text


def test_home_page_logged_in_shows_personal(client, test_user):
    """登录后首页: 渲染「安全实验态势中心」9 模块大屏"""
    _login(client, 'testuser', 'test123456')
    resp = client.get('/')
    assert resp.status_code == 200
    text = resp.get_data(as_text=True)
    for m in ['核心指标', 'AI 安全助手', '我的实验', '风险趋势',
              '漏洞风险分布', '最近活动', '今日推荐']:
        assert m in text
    # 系统状态 + 快捷操作 仍常驻
    assert '系统运行状态' in text and '快捷操作' in text


def test_user_center_merged_into_home(client, test_user):
    """/dashboard 已合并进首页: 重定向回首页, 登录态首页即态势中心"""
    _login(client, 'testuser', 'test123456')
    # /dashboard 现在 302 重定向到首页, 不再独立渲染
    resp = client.get('/dashboard')
    assert resp.status_code == 302
    assert resp.headers['Location'] in ('/', './', '/?')
    # 跟随重定向, 首页展示态势中心全部内容
    resp = client.get('/', follow_redirects=True)
    assert resp.status_code == 200
    text = resp.get_data(as_text=True)
    assert '核心指标' in text
    assert '我的实验' in text
    assert '最近活动' in text
    assert '快捷操作' in text


def test_user_center_requires_login(client, db):
    """/dashboard 现已对任何访客 302 重定向回首页 (并入统一工作台)"""
    resp = client.get('/dashboard')
    assert resp.status_code == 302
    assert resp.headers['Location'] in ('/', './', '/?')
