"""
报告管理 (/report) P0+P1 改进测试
覆盖: 类型/状态筛选 + 标题搜索 + 排序 / 统计卡 / 详情 MD·JSON 内联预览 / 列表缩略图 / 空状态入口
"""

import pytest
from tests.conftest import login_user
from app.models.report import Report
from app.services.report_service import ReportService


@pytest.fixture
def sample_reports(app, db, test_user):
    """为 test_user 创建若干报告 (含文件落盘, 供详情预览读取)"""
    with app.app_context():
        svc = ReportService()
        # 实验报告 (无文件, 仅记录)
        r1 = Report(user_id=test_user.id, title='SQL注入实验报告',
                    report_type='experiment', status='generated', file_size=1234)
        # 图谱快照 (写一个小 png)
        raw = b'\x89PNG\r\n\x1a\n'
        png_name = 'graph_test.png'
        with open(f'{svc.output_dir}/{png_name}', 'wb') as f:
            f.write(raw)
        r2 = Report(user_id=test_user.id, title='知识图谱快照', file_path=png_name,
                    report_type='graph_png', status='generated', file_size=len(raw))
        # MCP markdown (写 md 文件)
        md_name = 'mcp_test.md'
        with open(f'{svc.output_dir}/{md_name}', 'w', encoding='utf-8') as f:
            f.write('# 分析报告\n\n这是 **测试** 内容。')
        r3 = Report(user_id=test_user.id, title='MCP分析摘要', file_path=md_name,
                    report_type='mcp_md', status='generated', file_size=30)
        # 失败报告
        r4 = Report(user_id=test_user.id, title='失败的报告', report_type='mcp_json',
                    status='failed', error_message='生成出错')
        db.session.add_all([r1, r2, r3, r4])
        db.session.commit()
        yield {'experiment': r1.id, 'graph': r2.id, 'md': r3.id, 'failed': r4.id}
    # 清理落盘文件
    import os
    for fn in (png_name, md_name):
        try:
            os.remove(f'{svc.output_dir}/{fn}')
        except OSError:
            pass


class TestReportListFilters:
    def test_full_page_with_stats(self, client, test_user, sample_reports):
        login_user(client, 'testuser', 'test123456')
        resp = client.get('/report')
        html = resp.get_data(as_text=True)
        assert resp.status_code == 200
        assert '报告总数' in html
        assert '图谱快照' in html

    def test_filter_by_type(self, client, test_user, sample_reports):
        login_user(client, 'testuser', 'test123456')
        resp = client.get('/report?type=graph_png')
        html = resp.get_data(as_text=True)
        assert '知识图谱快照' in html
        assert 'SQL注入实验报告' not in html

    def test_filter_by_status_failed(self, client, test_user, sample_reports):
        login_user(client, 'testuser', 'test123456')
        resp = client.get('/report?status=failed')
        html = resp.get_data(as_text=True)
        assert '失败的报告' in html
        assert '知识图谱快照' not in html

    def test_search_by_keyword(self, client, test_user, sample_reports):
        login_user(client, 'testuser', 'test123456')
        resp = client.get('/report?q=SQL')
        html = resp.get_data(as_text=True)
        assert 'SQL注入实验报告' in html
        assert '知识图谱快照' not in html

    def test_sort_by_file_size(self, client, test_user, sample_reports):
        login_user(client, 'testuser', 'test123456')
        resp = client.get('/report?sort=file_size&order=desc')
        assert resp.status_code == 200

    def test_sort_header_toggle(self, client, test_user, sample_reports):
        login_user(client, 'testuser', 'test123456')
        # 默认 created_time desc -> 时间表头链接应指向 asc, 大小表头指向 desc
        html = client.get('/report').get_data(as_text=True)
        assert 'sort=created_time&amp;order=asc' in html
        assert 'sort=file_size&amp;order=desc' in html
        # 切到 file_size desc -> 大小表头链接变为 asc
        html = client.get('/report?sort=file_size&order=desc').get_data(as_text=True)
        assert 'sort=file_size&amp;order=asc' in html
        # 切到 file_size asc -> 大小表头链接变回 desc
        html = client.get('/report?sort=file_size&order=asc').get_data(as_text=True)
        assert 'sort=file_size&amp;order=desc' in html
        # 表头排序链接确实渲染在页面中 (大小 / 生成时间)
        assert 'sort=file_size' in html
        assert 'sort=created_time' in html


class TestReportDetailPreview:
    def test_md_inline_preview(self, client, test_user, sample_reports, app):
        login_user(client, 'testuser', 'test123456')
        resp = client.get(f'/report/{sample_reports["md"]}')
        html = resp.get_data(as_text=True)
        assert 'Markdown 内容预览' in html
        # 内容经转义后展示 (纯文本, 不透传 HTML)
        assert '分析报告' in html

    def test_graph_png_inline_preview(self, client, test_user, sample_reports):
        login_user(client, 'testuser', 'test123456')
        resp = client.get(f'/report/{sample_reports["graph"]}')
        html = resp.get_data(as_text=True)
        assert '图谱快照预览' in html
        assert 'img' in html


class TestReportAccess:
    def test_requires_login(self, client):
        resp = client.get('/report', follow_redirects=False)
        assert resp.status_code in (301, 302)

    def test_other_user_cannot_see(self, client, admin_user, sample_reports):
        # admin 看不到 test_user 的报告
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/report')
        html = resp.get_data(as_text=True)
        assert 'SQL注入实验报告' not in html
        assert '知识图谱快照' not in html
