"""
MCP 分析报告导出测试 (PDF / Markdown / JSON)
覆盖: 登录校验 / 导出端点返回报告链接 / 报告记录同步
"""

import pytest
import json
import os
from tests.conftest import login_user


@pytest.fixture
def mcp_plan_data():
    """模拟 MCP 完整分析计划结果"""
    return {
        'success': True,
        'query': '扫描目标 192.168.1.1',
        'tools_executed': ['dashboard', 'scanner', 'knowledge', 'risk'],
        'planned_tools': ['dashboard', 'scanner', 'knowledge', 'risk'],
        'results': {
            'dashboard': {'success': True, 'data': {'experiments': 3, 'scans': 5, 'ai_analyses': 2, 'reports': 4}},
            'scanner': {
                'success': True,
                'data': {
                    'target': '192.168.1.1',
                    'task_id': 10,
                    'scan_type': 'socket',
                    'latest_completed': {
                        'ports': [
                            {'port': 22, 'service': 'ssh'},
                            {'port': 80, 'service': 'http'},
                            {'port': 443, 'service': 'https'}
                        ]
                    }
                }
            },
            'knowledge': {
                'success': True,
                'data': {
                    'vulnerabilities': [
                        {
                            'name': 'SQL 注入漏洞',
                            'severity': 'Critical',
                            'cve': 'CVE-2024-0001',
                            'category': 'Injection',
                            'description': 'SQL 注入攻击',
                            'attack_method': 'UNION 注入',
                            'solution': '使用参数化查询'
                        },
                        {
                            'name': 'XSS 跨站脚本',
                            'severity': 'High',
                            'category': 'XSS',
                            'description': '反射型 XSS'
                        }
                    ],
                    'statistics': {'total': 15}
                }
            },
            'risk': {
                'success': True,
                'data': {
                    'final_score': 72.5,
                    'risk_level': 'high',
                    'risk_label': '高风险',
                    'cvss': 8.5,
                    'asset': 7.0,
                    'exploit': 8.0,
                    'exposure': 6.0,
                    'ai_confidence': 8.0
                }
            }
        },
        'execution_log': [
            {'tool': 'dashboard', 'success': True, 'elapsed_ms': 45, 'summary': '态势数据获取成功'},
            {'tool': 'scanner', 'success': True, 'elapsed_ms': 230, 'summary': '扫描完成: 3 个开放端口'},
            {'tool': 'knowledge', 'success': True, 'elapsed_ms': 180, 'summary': '发现 2 个高危漏洞'},
            {'tool': 'risk', 'success': True, 'elapsed_ms': 95, 'summary': '综合评分 72.5 (高风险)'}
        ],
        'total_ms': 550,
        'summary': '**风险等级**: 高风险 (72.5/100)\n- 发现 2 个高危漏洞\n- 开放端口: 22(ssh), 80(http), 443(https)'
    }


class TestMCPExportAuth:
    """导出接口访问控制"""

    def test_export_requires_login(self, client):
        for endpoint in ['/mcp/export-pdf', '/mcp/export-md', '/mcp/export-json']:
            resp = client.post(endpoint, data=json.dumps({}), content_type='application/json')
            assert resp.status_code in (301, 302), f'{endpoint} 应重定向到登录页'

    def test_export_needs_json_body(self, client, test_user):
        login_user(client, 'testuser', 'test123456')
        resp = client.post('/mcp/export-md', data='not json', content_type='text/plain')
        assert resp.status_code == 400


class TestMCPExportMD:
    """Markdown 导出"""

    def test_export_md_returns_report_link(self, client, test_user, mcp_plan_data, app):
        login_user(client, 'testuser', 'test123456')
        resp = client.post('/mcp/export-md',
                           data=json.dumps(mcp_plan_data),
                           content_type='application/json')
        assert resp.status_code == 200
        assert 'application/json' in resp.content_type
        j = json.loads(resp.data)
        assert j['success'] is True
        assert j['report_id']
        assert '/report/' in j['report_url']
        # 不再直接下载到本地 (无附件头部)
        assert 'attachment' not in resp.headers.get('Content-Disposition', '')

    def test_exported_report_appears_in_report_list(self, client, test_user, mcp_plan_data):
        login_user(client, 'testuser', 'test123456')
        resp = client.post('/mcp/export-md',
                           data=json.dumps(mcp_plan_data),
                           content_type='application/json')
        j = json.loads(resp.data)
        assert j['success'] is True
        # 报告列表可见该记录
        resp = client.get('/report')
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert 'MCP 分析报告' in body or str(j['report_id']) in body

    def test_export_md_creates_report_record(self, client, test_user, mcp_plan_data, app):
        from app.models.report import Report
        login_user(client, 'testuser', 'test123456')
        client.post('/mcp/export-md', data=json.dumps(mcp_plan_data), content_type='application/json')
        with app.app_context():
            r = Report.query.filter_by(user_id=test_user.id, report_type='mcp_md').first()
            assert r is not None
            assert r.status == 'generated'
            assert r.file_path.endswith('.md')


class TestMCPExportJSON:
    """JSON 导出"""

    def test_export_json_returns_report_link(self, client, test_user, mcp_plan_data):
        login_user(client, 'testuser', 'test123456')
        resp = client.post('/mcp/export-json',
                           data=json.dumps(mcp_plan_data),
                           content_type='application/json')
        assert resp.status_code == 200
        assert 'application/json' in resp.content_type
        j = json.loads(resp.data)
        assert j['success'] is True
        assert j['report_id']
        assert '/report/' in j['report_url']

    def test_export_json_creates_report_record(self, client, test_user, mcp_plan_data, app):
        from app.models.report import Report
        login_user(client, 'testuser', 'test123456')
        client.post('/mcp/export-json', data=json.dumps(mcp_plan_data), content_type='application/json')
        with app.app_context():
            r = Report.query.filter_by(user_id=test_user.id, report_type='mcp_json').first()
            assert r is not None
            assert r.status == 'generated'


class TestMCPExportPDF:
    """PDF 导出"""

    def test_export_pdf_returns_report_link(self, client, test_user, mcp_plan_data, app):
        from app.models.report import Report
        login_user(client, 'testuser', 'test123456')
        resp = client.post('/mcp/export-pdf',
                           data=json.dumps(mcp_plan_data),
                           content_type='application/json')
        # 返回 JSON (含报告链接), 而非文件流
        assert 'application/json' in resp.content_type
        j = json.loads(resp.data)
        with app.app_context():
            r = Report.query.filter_by(user_id=test_user.id, report_type='mcp_pdf').first()
            if j['success']:
                assert j['report_id'] == r.id
                assert r.status == 'generated'
            else:
                # PDF 生成失败时仍创建 failed 记录
                if r:
                    assert r.status == 'failed'


class TestMCPPlanResultTemplate:
    """_plan_result.html 模板验证"""

    def test_plan_result_contains_export_buttons(self, client, test_user, mcp_plan_data, app):
        login_user(client, 'testuser', 'test123456')
        # 模拟 HTMX 请求获取 plan result 片段
        resp = client.post('/mcp/analysis',
                           data={'target': '192.168.1.1'},
                           headers={'HX-Request': 'true'})
        html = resp.get_data(as_text=True)
        # 应包含导出按钮和 ai-plan-data 数据容器
        assert 'aiExportPDF' in html or 'export-pdf' in html or 'ai-dl-btn' in html
        assert 'ai-plan-data' in html

    def test_plan_result_contains_data_script(self, client, test_user, mcp_plan_data, app):
        login_user(client, 'testuser', 'test123456')
        resp = client.post('/mcp/analysis',
                           data={'target': '192.168.1.1'},
                           headers={'HX-Request': 'true'})
        html = resp.get_data(as_text=True)
        # 数据容器必须在 HTML 中(供 panel.js 全局函数读取)
        assert 'id="ai-plan-data"' in html
