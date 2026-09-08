"""
知识图谱 (/knowledge-graph) P0+P1+P2 升级测试
覆盖: 服务层类型/严重程度过滤 / 节点度数 / 最短路径 / 节点邻居 / 搜索
      / 页面本地 echarts+筛选条 / rebuild 保留筛选 / 路径 API / PNG 快照同步到 /report
注意: KnowledgeGraphService 为模块级单例, 测试内用新实例以保证数据来自当前 DB。
"""

import base64
import pytest
from tests.conftest import login_user
from app.services.knowledge_graph_service import KnowledgeGraphService
from app.models.report import Report


@pytest.fixture
def kg(app, db, sample_vulns):
    """构建基于当前测试数据的图谱服务实例"""
    with app.app_context():
        svc = KnowledgeGraphService()
        svc.build()
        yield svc


class TestGraphService:
    def test_get_graph_data_structure(self, kg):
        d = kg.get_graph_data()
        assert 'nodes' in d and 'links' in d and 'categories' in d
        assert d['stats']['total_nodes'] > 0
        assert all('id' in n and 'type' in n for n in d['nodes'])

    def test_type_filter(self, kg):
        d = kg.get_graph_data(type_filter=['cve'])
        assert len(d['nodes']) > 0
        assert all(n['type'] == 'cve' for n in d['nodes'])

    def test_severity_filter_keeps_other_types(self, kg):
        d = kg.get_graph_data(severity_filter=['High'])
        # 非漏洞节点不受严重程度约束
        types = {n['type'] for n in d['nodes']}
        assert 'category' in types
        # 漏洞节点均满足 High
        vuln_nodes = [n for n in d['nodes'] if n['type'] == 'vulnerability']
        assert all(n['severity'] == 'High' for n in vuln_nodes)

    def test_severity_filter_excludes_nonmatching(self, kg):
        d_all = kg.get_graph_data()
        d_high = kg.get_graph_data(severity_filter=['High'])
        all_vuln = [n for n in d_all['nodes'] if n['type'] == 'vulnerability']
        high_vuln = [n for n in d_high['nodes'] if n['type'] == 'vulnerability']
        assert len(high_vuln) < len(all_vuln)

    def test_edges_respect_filter(self, kg):
        d = kg.get_graph_data(type_filter=['cve'])
        ids = {n['id'] for n in d['nodes']}
        for link in d['links']:
            assert link['source'] in ids and link['target'] in ids

    def test_node_neighbors(self, kg):
        d = kg.get_graph_data()
        first = d['nodes'][0]
        nb = kg.get_node_neighbors(first['id'])
        assert 'node' in nb and 'neighbors' in nb

    def test_search(self, kg):
        d = kg.get_graph_data()
        kw = d['nodes'][0]['name'][:3]
        res = kg.search_nodes(kw)
        assert any(r['id'] == d['nodes'][0]['id'] for r in res)


class TestGraphPage:
    def test_page_renders_local_echarts(self, client, admin_user, seed_data):
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/knowledge-graph')
        html = resp.get_data(as_text=True)
        assert 'static/vendor/echarts.min.js' in html   # ECharts 已本地化(去自营 CDN)
        assert 'cdn.jsdelivr.net/npm/echarts' not in html  # 不再依赖外部 echarts
        assert 'typeFilters' in html          # 类型筛选条
        assert 'severityFilter' in html       # 严重程度筛选
        assert 'csrf-token' in html           # CSRF meta 存在

    def test_api_data_type_filter(self, client, admin_user, seed_data):
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/knowledge-graph/api/data?type=cve')
        assert resp.status_code == 200
        d = resp.get_json()
        assert all(n['type'] == 'cve' for n in d['nodes'])

    def test_api_data_severity_filter(self, client, admin_user, seed_data, app):
        login_user(client, 'adminuser', 'admin123456')
        resp = client.get('/knowledge-graph/api/data?severity=Critical')
        d = resp.get_json()
        vuln_nodes = [n for n in d['nodes'] if n['type'] == 'vulnerability']
        assert all(n['severity'] == 'Critical' for n in vuln_nodes)

    def test_rebuild_returns_data_with_filter(self, client, admin_user, seed_data):
        login_user(client, 'adminuser', 'admin123456')
        resp = client.post('/knowledge-graph/rebuild?type=cve',
                          headers={'X-CSRFToken': 'x'}, follow_redirects=False)
        assert resp.status_code == 200
        d = resp.get_json()
        assert d['success'] is True
        assert 'data' in d
        assert all(n['type'] == 'cve' for n in d['data']['nodes'])


# ============ P2: 节点度数 ============
class TestGraphDegree:
    def test_degree_present(self, kg):
        d = kg.get_graph_data()
        assert all('degree' in n for n in d['nodes'])
        # 分类节点至少连接一个漏洞, 度数 >= 1
        assert all(n['degree'] >= 0 for n in d['nodes'])

    def test_degree_nonzero_for_connected(self, kg):
        d = kg.get_graph_data()
        # 至少存在有边相连的节点
        assert any(n['degree'] > 0 for n in d['nodes'])


# ============ P2: 最短路径 ============
class TestGraphPath:
    def test_path_between_connected(self, kg):
        d = kg.get_graph_data()
        vuln = next((n for n in d['nodes'] if n['type'] == 'vulnerability'), None)
        cat = next((n for n in d['nodes']
                    if n['type'] == 'category'
                    and any(e['source'] == vuln['id'] and e['target'] == n['id']
                            for e in d['links'])), None)
        if vuln and cat:
            res = kg.find_shortest_path(vuln['id'], cat['id'])
            assert res['found'] is True
            assert cat['id'] in res['path']

    def test_path_self(self, kg):
        d = kg.get_graph_data()
        nid = d['nodes'][0]['id']
        res = kg.find_shortest_path(nid, nid)
        assert res['found'] is True and res['path'] == [nid]

    def test_path_missing_node(self, kg):
        res = kg.find_shortest_path('nope:a', 'nope:b')
        assert res['found'] is False


class TestGraphPathAPI:
    def test_path_api(self, client, admin_user, seed_data):
        login_user(client, 'adminuser', 'admin123456')
        # 取两个真实节点 id
        d = client.get('/knowledge-graph/api/data').get_json()
        ids = [n['id'] for n in d['nodes']]
        if len(ids) >= 2:
            resp = client.get('/knowledge-graph/api/path/' +
                              ids[0] + '/' + ids[1])
            assert resp.status_code == 200
            body = resp.get_json()
            assert 'found' in body


# ============ P2: PNG 快照同步到 /report ============
class TestGraphSnapshot:
    def _png(self):
        # 1x1 红色 PNG 的 base64
        raw = (b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
               b'\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05'
               b'\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82')
        return 'data:image/png;base64,' + base64.b64encode(raw).decode()

    def test_snapshot_creates_report(self, client, admin_user, seed_data, app):
        login_user(client, 'adminuser', 'admin123456')
        resp = client.post('/knowledge-graph/snapshot',
                           json={'image': self._png(), 'title': '测试快照'},
                           headers={'X-CSRFToken': 'x'})
        assert resp.status_code == 200
        d = resp.get_json()
        assert d['success'] is True
        with app.app_context():
            from app.extensions import db as _db
            r = _db.session.get(Report, d['report_id'])
            assert r is not None
            assert r.report_type == 'graph_png'
            assert r.file_path and r.file_path.endswith('.png')

    def test_snapshot_appears_in_report_list(self, client, admin_user, seed_data):
        login_user(client, 'adminuser', 'admin123456')
        client.post('/knowledge-graph/snapshot',
                    json={'image': self._png()},
                    headers={'X-CSRFToken': 'x'})
        resp = client.get('/report')
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert '图谱快照' in html

    def test_snapshot_requires_image(self, client, admin_user, seed_data):
        login_user(client, 'adminuser', 'admin123456')
        resp = client.post('/knowledge-graph/snapshot',
                           json={'image': ''}, headers={'X-CSRFToken': 'x'})
        assert resp.status_code == 400
        assert resp.get_json()['success'] is False
