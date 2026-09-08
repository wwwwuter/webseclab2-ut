"""
安全知识图谱路由模块
提供图谱可视化、节点查询、搜索等功能

路由:
  /knowledge-graph          - 图谱可视化页面 (ECharts 力导向图)
  /knowledge-graph/api/data - 图谱 JSON 数据 (供 ECharts)
  /knowledge-graph/api/node/<node_id> - 节点详情
  /knowledge-graph/api/search - 节点搜索
  /knowledge-graph/api/stats - 图谱统计
  /knowledge-graph/rebuild  - 重建图谱 (管理员)
"""

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from app.services.knowledge_graph_service import KnowledgeGraphService
from app.utils.permission import admin_required

kg_bp = Blueprint('kg', __name__)
kg_service = KnowledgeGraphService()


@kg_bp.route('/knowledge-graph')
@login_required
def graph_view():
    """知识图谱可视化页面"""
    stats = kg_service.get_statistics()
    return render_template('knowledge_graph/graph.html', stats=stats)


@kg_bp.route('/knowledge-graph/api/data')
@login_required
def api_graph_data():
    """返回 ECharts 力导向图所需的完整数据 (支持类型/严重程度筛选)"""
    types = request.args.getlist('type')
    severities = request.args.getlist('severity')
    data = kg_service.get_graph_data(type_filter=types or None,
                                     severity_filter=severities or None)
    return jsonify(data)


@kg_bp.route('/knowledge-graph/api/node/<path:node_id>')
@login_required
def api_node_detail(node_id):
    """查询节点详情和邻居关系"""
    result = kg_service.get_node_neighbors(node_id)
    return jsonify(result)


@kg_bp.route('/knowledge-graph/api/ego/<path:node_id>')
def api_ego_subgraph(node_id):
    """返回以指定节点为中心的 ego 子图 (ECharts 格式), 供漏洞详情页内嵌关联视图。

    说明: 仅暴露单个漏洞节点的 1 跳邻居 (分类/OWASP/CVE/修复/攻击/同类漏洞),
    这些数据在漏洞详情页本身即完全公开, 故无需登录即可访问。
    """
    data = kg_service.get_ego_subgraph(node_id)
    return jsonify(data)


@kg_bp.route('/knowledge-graph/api/search')
@login_required
def api_search():
    """搜索图谱节点"""
    keyword = request.args.get('q', '').strip()
    if not keyword:
        return jsonify([])
    return jsonify(kg_service.search_nodes(keyword))


@kg_bp.route('/knowledge-graph/api/stats')
@login_required
def api_stats():
    """图谱统计"""
    return jsonify(kg_service.get_statistics())


@kg_bp.route('/knowledge-graph/api/path/<path:node_a>/<path:node_b>')
@login_required
def api_path(node_a, node_b):
    """查找两节点间最短关系路径"""
    result = kg_service.find_shortest_path(node_a, node_b)
    return jsonify(result)


@kg_bp.route('/knowledge-graph/snapshot', methods=['POST'])
@login_required
def save_snapshot():
    """将知识图谱 PNG 快照保存为「图谱快照」报告, 同步到 /report 页面"""
    from app.services.report_service import ReportService
    payload = request.get_json(silent=True) or {}
    b64_png = payload.get('image', '')
    title = payload.get('title', '').strip() or None
    report, error = ReportService().save_graph_snapshot(
        user_id=current_user.id, b64_png=b64_png, title=title
    )
    if error:
        return jsonify({'success': False, 'message': error}), 400
    return jsonify({
        'success': True,
        'message': '图谱快照已保存到报告',
        'report_id': report.id,
        'report_url': '/report',
    })


@kg_bp.route('/knowledge-graph/rebuild', methods=['POST'])
@login_required
@admin_required
def rebuild_graph():
    """重建知识图谱 (管理员) — 保留当前筛选条件"""
    kg_service.rebuild()
    types = request.args.getlist('type')
    severities = request.args.getlist('severity')
    data = kg_service.get_graph_data(type_filter=types or None,
                                     severity_filter=severities or None)
    return jsonify({
        'success': True,
        'message': f'图谱重建完成: {data["stats"]["total_nodes"]} 节点, {data["stats"]["total_edges"]} 边',
        'data': data,
    })
