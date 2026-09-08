"""
安全知识图谱服务模块
基于 NetworkX 构建漏洞知识图谱

节点类型:
- Vulnerability: 漏洞记录
- Category: 漏洞分类 (SQL Injection, XSS 等)
- OWASP: OWASP Top 10 分类
- CVE: CVE 编号
- CWE: CWE 弱类型编号
- Solution: 修复方案
- AttackMethod: 攻击方式

边类型:
- belongs_to: 漏洞 → 分类
- classified_as: 漏洞 → OWASP
- has_cve: 漏洞 → CVE
- has_cwe: 漏洞 → CWE
- fixed_by: 漏洞 → 修复方案
- exploited_via: 漏洞 → 攻击方式
- related_to: 漏洞 → 关联漏洞 (同类/同CVE)

设计原则:
- 图谱从现有数据库数据自动构建
- 支持增量更新 (新漏洞入库时更新图谱)
- 提供 ECharts 可视化所需的 JSON 数据
"""

import logging
try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# 节点类型 → 分类索引 / 颜色 (ECharts 可视化共用)
_KG_TYPE_CATEGORIES = [
    {'name': '漏洞分类'},    # 0
    {'name': 'OWASP'},       # 1
    {'name': '漏洞'},        # 2
    {'name': 'CVE'},         # 3
    {'name': '修复方案'},    # 4
    {'name': '攻击方式'},    # 5
]
_KG_TYPE_COLORS = {
    0: '#198754',  # 分类: green
    1: '#0d6efd',  # OWASP: blue
    2: '#dc3545',  # 漏洞: red
    3: '#6f42c1',  # CVE: purple
    4: '#ffc107',  # 修复: yellow
    5: '#fd7e14',  # 攻击: orange
}


class KnowledgeGraphService:
    """安全知识图谱服务"""

    def __init__(self):
        self.graph = nx.DiGraph() if NETWORKX_AVAILABLE else None
        self._built = False

    def build(self):
        """
        从数据库构建完整知识图谱
        调用时机: 应用启动后首次访问图谱页面时
        """
        if not NETWORKX_AVAILABLE:
            logger.warning('NetworkX 未安装, 知识图谱功能不可用')
            self._built = True
            return

        self.graph = nx.DiGraph()

        try:
            self._add_categories()
            self._add_owasp()
            self._add_vulnerabilities()
            self._built = True

            logger.info(
                '知识图谱构建完成: %d 节点, %d 边',
                self.graph.number_of_nodes(),
                self.graph.number_of_edges()
            )
        except Exception as e:
            logger.error(f'知识图谱构建失败: {e}', exc_info=True)

    def _add_categories(self):
        """添加漏洞分类节点"""
        from app.models.vulnerability import VulnerabilityCategory
        categories = VulnerabilityCategory.query.all()
        for cat in categories:
            self.graph.add_node(
                f'cat:{cat.id}',
                label=cat.name,
                type='category',
                description=cat.description or '',
                symbol_size=40,
                category=0,
            )

    def _add_owasp(self):
        """添加 OWASP 分类节点"""
        from app.models.vulnerability import OWASPCategory
        owasp_cats = OWASPCategory.query.all()
        for owasp in owasp_cats:
            self.graph.add_node(
                f'owasp:{owasp.id}',
                label=f'{owasp.code}: {owasp.name}',
                type='owasp',
                code=owasp.code,
                description=owasp.description or '',
                symbol_size=35,
                category=1,
            )

    def _add_vulnerabilities(self):
        """添加漏洞节点和所有关联边"""
        from app.models.vulnerability import Vulnerability
        vulns = Vulnerability.query.all()

        for vuln in vulns:
            # 漏洞节点
            node_id = f'vuln:{vuln.id}'
            severity_size = {'Critical': 30, 'High': 25, 'Medium': 20, 'Low': 15}
            self.graph.add_node(
                node_id,
                label=vuln.name,
                type='vulnerability',
                severity=vuln.severity,
                cve=vuln.cve or '',
                description=(vuln.description or '')[:200],
                symbol_size=severity_size.get(vuln.severity, 18),
                category=2,
            )

            # 边: 漏洞 → 分类
            if vuln.category_id:
                self.graph.add_edge(
                    node_id, f'cat:{vuln.category_id}',
                    relation='belongs_to', label='属于'
                )

            # 边: 漏洞 → OWASP
            if vuln.owasp_id:
                self.graph.add_edge(
                    node_id, f'owasp:{vuln.owasp_id}',
                    relation='classified_as', label='归类'
                )

            # CVE 节点
            if vuln.cve and vuln.cve.strip():
                cve_ids = [c.strip() for c in vuln.cve.split(',') if c.strip()]
                for cve_id in cve_ids:
                    cve_node = f'cve:{cve_id}'
                    if not self.graph.has_node(cve_node):
                        self.graph.add_node(
                            cve_node,
                            label=cve_id,
                            type='cve',
                            symbol_size=22,
                            category=3,
                        )
                    self.graph.add_edge(
                        node_id, cve_node,
                        relation='has_cve', label='CVE'
                    )

            # 修复方案节点 (取前30字作为标签)
            if vuln.solution and len(vuln.solution.strip()) > 10:
                sol_label = vuln.solution.strip()[:30]
                sol_node = f'sol:{vuln.id}'
                self.graph.add_node(
                    sol_node,
                    label=sol_label,
                    type='solution',
                    full_text=vuln.solution,
                    symbol_size=15,
                    category=4,
                )
                self.graph.add_edge(
                    node_id, sol_node,
                    relation='fixed_by', label='修复'
                )

            # 攻击方式节点
            if vuln.attack_method and len(vuln.attack_method.strip()) > 10:
                atk_label = vuln.attack_method.strip()[:30]
                atk_node = f'atk:{vuln.id}'
                self.graph.add_node(
                    atk_node,
                    label=atk_label,
                    type='attack',
                    full_text=vuln.attack_method,
                    symbol_size=15,
                    category=5,
                )
                self.graph.add_edge(
                    node_id, atk_node,
                    relation='exploited_via', label='利用'
                )

        # 漏洞间关联: 同分类的漏洞互相连接 (限制数量避免过于密集)
        self._add_vuln_relations(vulns)

    def _add_vuln_relations(self, vulns):
        """添加漏洞间关联边 (同分类/同CVE)"""
        from collections import defaultdict

        # 按分类分组
        cat_groups = defaultdict(list)
        for v in vulns:
            if v.category_id:
                cat_groups[v.category_id].append(v.id)

        # 同分类漏洞间添加 related_to 边 (每组最多连接5对)
        for cat_id, vuln_ids in cat_groups.items():
            pairs = 0
            for i in range(len(vuln_ids)):
                for j in range(i + 1, len(vuln_ids)):
                    if pairs >= 5:
                        break
                    self.graph.add_edge(
                        f'vuln:{vuln_ids[i]}', f'vuln:{vuln_ids[j]}',
                        relation='related_to', label='同类'
                    )
                    pairs += 1

    # ==================== 查询接口 ====================

    def get_graph_data(self, type_filter: Optional[list] = None,
                       severity_filter: Optional[list] = None) -> Dict[str, Any]:
        """
        返回 ECharts 图谱可视化所需的 JSON 数据

        格式:
        {
            "nodes": [{"name": "...", "symbolSize": N, "category": N, ...}],
            "links": [{"source": "...", "target": "...", "label": "..."}],
            "categories": [{"name": "..."}]
        }

        :param type_filter: 仅包含这些节点类型 (如 ['vulnerability','cve'])；为空则全部
        :param severity_filter: 仅包含这些严重程度的漏洞节点；为空则全部(非漏洞节点不受影响)
        """
        if not self._built:
            self.build()

        type_categories = _KG_TYPE_CATEGORIES
        type_colors = _KG_TYPE_COLORS

        nodes = []
        for node_id, attrs in self.graph.nodes(data=True):
            cat_idx = attrs.get('category', 2)
            # 节点度数 (入度 + 出度), 用于前端按关联数做尺寸
            degree = int(self.graph.degree(node_id))
            nodes.append({
                'id': node_id,
                'name': attrs.get('label', node_id),
                'symbolSize': attrs.get('symbol_size', 20),
                'category': cat_idx,
                'itemStyle': {'color': type_colors.get(cat_idx, '#6c757d')},
                'value': attrs.get('description', ''),
                'type': attrs.get('type', ''),
                'severity': attrs.get('severity', ''),
                'cve': attrs.get('cve', ''),
                'degree': degree,
            })

        # 按类型 / 严重程度过滤 (前端筛选与 rebuild 共用)
        if type_filter:
            type_filter = [t for t in type_filter if t]
        if severity_filter:
            severity_filter = [s for s in severity_filter if s]
        if type_filter or severity_filter:
            for n in nodes:
                t = n.get('type', '')
                sev = n.get('severity', '')
                type_ok = (not type_filter) or (t in type_filter)
                # 非漏洞节点不受严重程度约束
                sev_ok = (not severity_filter) or (t != 'vulnerability') or (sev in severity_filter)
                n['_visible'] = type_ok and sev_ok
            visible_ids = {n['id'] for n in nodes if n.get('_visible')}
            nodes = [n for n in nodes if n.get('_visible')]
        else:
            visible_ids = {n['id'] for n in nodes}

        links = []
        for source, target, attrs in self.graph.edges(data=True):
            # 仅保留两端都可见的边
            if source in visible_ids and target in visible_ids:
                links.append({
                    'source': source,
                    'target': target,
                    'label': {'show': False, 'formatter': attrs.get('label', '')},
                    'relation': attrs.get('relation', ''),
                })

        # 统计节点类型分布
        node_type_counts = {}
        for _, attrs in self.graph.nodes(data=True):
            t = attrs.get('type', 'unknown')
            node_type_counts[t] = node_type_counts.get(t, 0) + 1

        # 统计关系类型分布
        rel_type_counts = {}
        for _, _, attrs in self.graph.edges(data=True):
            r = attrs.get('relation', 'unknown')
            rel_type_counts[r] = rel_type_counts.get(r, 0) + 1

        return {
            'nodes': nodes,
            'links': links,
            'categories': type_categories,
            'stats': {
                'total_nodes': self.graph.number_of_nodes(),
                'total_edges': self.graph.number_of_edges(),
                'vulnerability_count': sum(1 for _, a in self.graph.nodes(data=True) if a.get('type') == 'vulnerability'),
                'category_count': sum(1 for _, a in self.graph.nodes(data=True) if a.get('type') == 'category'),
                'cve_count': sum(1 for _, a in self.graph.nodes(data=True) if a.get('type') == 'cve'),
                'node_types': node_type_counts,
                'relation_types': rel_type_counts,
            }
        }

    def get_ego_subgraph(self, node_id: str, hops: int = 1) -> Dict[str, Any]:
        """
        返回以 node_id 为中心的 ego 子图 (默认 1 跳邻居), ECharts 力导向图格式。
        用于漏洞详情页内嵌「知识图谱关联」视图。

        :return: {found, center_id, nodes, links, categories}
        """
        if not self._built:
            self.build()

        if not NETWORKX_AVAILABLE:
            return {'found': False, 'center_id': node_id,
                    'nodes': [], 'links': [], 'categories': _KG_TYPE_CATEGORIES}
        if not self.graph.has_node(node_id):
            return {'found': False, 'center_id': node_id,
                    'nodes': [], 'links': [], 'categories': _KG_TYPE_CATEGORIES}

        # BFS 收集 hops 跳内的节点 (无向)
        visited = {node_id}
        frontier = {node_id}
        for _ in range(max(1, int(hops))):
            nxt = set()
            for nid in frontier:
                for nb in self.graph.successors(nid):
                    if nb not in visited:
                        visited.add(nb)
                        nxt.add(nb)
                for nb in self.graph.predecessors(nid):
                    if nb not in visited:
                        visited.add(nb)
                        nxt.add(nb)
            frontier = nxt

        nodes = []
        for nid in visited:
            attrs = self.graph.nodes[nid]
            cat_idx = attrs.get('category', 2)
            nodes.append({
                'id': nid,
                'name': attrs.get('label', nid),
                'symbolSize': attrs.get('symbol_size', 20),
                'category': cat_idx,
                'itemStyle': {'color': _KG_TYPE_COLORS.get(cat_idx, '#6c757d')},
                'value': attrs.get('description', ''),
                'type': attrs.get('type', ''),
                'severity': attrs.get('severity', ''),
                'cve': attrs.get('cve', ''),
                'degree': int(self.graph.degree(nid)),
            })

        links = []
        for source, target, attrs in self.graph.edges(data=True):
            if source in visited and target in visited:
                links.append({
                    'source': source,
                    'target': target,
                    'label': {'show': False, 'formatter': attrs.get('label', '')},
                    'relation': attrs.get('relation', ''),
                })

        return {
            'found': True,
            'center_id': node_id,
            'nodes': nodes,
            'links': links,
            'categories': _KG_TYPE_CATEGORIES,
        }

    def get_node_neighbors(self, node_id: str) -> Dict[str, Any]:
        """获取指定节点的所有邻居节点和关系"""
        if not self._built:
            self.build()

        if not self.graph.has_node(node_id):
            return {'error': '节点不存在'}

        node_attrs = dict(self.graph.nodes[node_id])
        neighbors = []

        # 出边
        for _, target, attrs in self.graph.out_edges(node_id, data=True):
            target_attrs = dict(self.graph.nodes[target])
            neighbors.append({
                'id': target,
                'label': target_attrs.get('label', target),
                'type': target_attrs.get('type', ''),
                'relation': attrs.get('relation', ''),
                'relation_label': attrs.get('label', ''),
                'direction': 'out',
            })

        # 入边
        for source, _, attrs in self.graph.in_edges(node_id, data=True):
            source_attrs = dict(self.graph.nodes[source])
            neighbors.append({
                'id': source,
                'label': source_attrs.get('label', source),
                'type': source_attrs.get('type', ''),
                'relation': attrs.get('relation', ''),
                'relation_label': attrs.get('label', ''),
                'direction': 'in',
            })

        return {
            'node': {
                'id': node_id,
                'label': node_attrs.get('label', node_id),
                'type': node_attrs.get('type', ''),
                'description': node_attrs.get('description', ''),
                'severity': node_attrs.get('severity', ''),
                'cve': node_attrs.get('cve', ''),
            },
            'neighbors': neighbors,
            'degree': self.graph.degree(node_id),
        }

    def find_shortest_path(self, node_a: str, node_b: str) -> Dict[str, Any]:
        """
        查找两个节点之间的最短关系路径 (无向 BFS, 返回经过的节点与关系)
        :return: {path: [node_id...], edges: [{source,target,relation,relation_label}], found: bool}
        """
        if not self._built:
            self.build()

        if not self.graph.has_node(node_a) or not self.graph.has_node(node_b):
            return {'found': False, 'error': '节点不存在'}

        if node_a == node_b:
            return {'found': True, 'path': [node_a], 'edges': []}

        try:
            path = nx.shortest_path(self.graph.to_undirected(), node_a, node_b)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return {'found': False, 'error': '两节点之间不存在可达路径'}

        edges = []
        for i in range(len(path) - 1):
            s, t = path[i], path[i + 1]
            # 取任一方向的首条边关系
            if self.graph.has_edge(s, t):
                attrs = self.graph.get_edge_data(s, t)
            else:
                attrs = self.graph.get_edge_data(t, s)
            edges.append({
                'source': s,
                'target': t,
                'relation': attrs.get('relation', ''),
                'relation_label': attrs.get('label', ''),
            })

        node_labels = {
            nid: dict(self.graph.nodes[nid]).get('label', nid) for nid in path
        }
        return {
            'found': True,
            'path': path,
            'edges': edges,
            'node_labels': node_labels,
        }

    def search_nodes(self, keyword: str) -> List[Dict]:
        """搜索图谱节点"""
        if not self._built:
            self.build()

        keyword_lower = keyword.lower()
        results = []

        for node_id, attrs in self.graph.nodes(data=True):
            label = attrs.get('label', '')
            if keyword_lower in label.lower() or keyword_lower in node_id.lower():
                results.append({
                    'id': node_id,
                    'label': label,
                    'type': attrs.get('type', ''),
                    'severity': attrs.get('severity', ''),
                })

        return results[:20]  # 限制返回数量

    def get_statistics(self) -> Dict[str, Any]:
        """获取图谱统计"""
        if not self._built:
            self.build()

        if not NETWORKX_AVAILABLE or self.graph.number_of_nodes() == 0:
            return {
                'total_nodes': 0, 'total_edges': 0,
                'node_types': {}, 'relation_types': {}, 'density': 0,
            }

        type_counts = {}
        for _, attrs in self.graph.nodes(data=True):
            t = attrs.get('type', 'unknown')
            type_counts[t] = type_counts.get(t, 0) + 1

        relation_counts = {}
        for _, _, attrs in self.graph.edges(data=True):
            r = attrs.get('relation', 'unknown')
            relation_counts[r] = relation_counts.get(r, 0) + 1

        return {
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'node_types': type_counts,
            'relation_types': relation_counts,
            'density': round(nx.density(self.graph), 4),
        }

    def rebuild(self):
        """强制重建图谱"""
        self._built = False
        self.build()
