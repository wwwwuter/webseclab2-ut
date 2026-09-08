"""首页「安全实验态势中心」渲染回归测试 (UI v3 Step2 新规范)"""
from tests.conftest import login_user


def test_home_public(client):
    r = client.get('/')
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert '系统运行状态' in html
    assert '快捷操作' in html
    # 未登录不应渲染模块③~⑨
    assert '核心指标' not in html
    assert '管理员面板' not in html


def test_home_authed(client, test_user, sample_vulns, seed_data):
    login_user(client, 'testuser', 'test123456')
    r = client.get('/')
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    for marker in ['核心指标', 'AI 安全助手', '我的实验', '风险趋势',
                   '漏洞风险分布', '最近活动', '今日推荐', 'trendChart', 'riskChart']:
        assert marker in html, f'缺少模块标记: {marker}'
    # 今日推荐应渲染出漏洞名 (sample_vulns 已播种)
    assert '开始实验' in html


def test_home_admin_panel(client, admin_user, sample_vulns, seed_data):
    login_user(client, 'adminuser', 'admin123456')
    r = client.get('/')
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert '管理员面板' in html
    assert 'Prompt 数量' in html
    assert '系统日志' in html


def test_api_dashboard_trends(client, test_user, seed_data):
    login_user(client, 'testuser', 'test123456')
    r = client.get('/api/dashboard/trends')
    assert r.status_code == 200
    data = r.get_json()
    assert 'dates' in data and 'scan_counts' in data and 'risk_scores' in data
    assert len(data['dates']) == 7
