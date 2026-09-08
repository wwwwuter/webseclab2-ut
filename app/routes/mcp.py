"""
MCP 工具调用路由模块
提供 AI Agent 工具调用的用户界面和 API

路由:
  /mcp                  - MCP 工具调用面板
  /mcp/execute          - 执行工具 (POST)
  /mcp/plan             - 智能规划执行 (POST)
  /mcp/api/tools        - 列出所有工具 (JSON)
  /mcp/export-pdf       - 导出 PDF 报告 (POST)
  /mcp/export-md        - 导出 Markdown 报告 (POST)
  /mcp/export-json      - 导出 JSON 报告 (POST)
"""

import json
from flask import Blueprint, render_template, request, jsonify, url_for
from flask_login import login_required, current_user
from app.extensions import csrf

mcp_bp = Blueprint('mcp', __name__)


@mcp_bp.route('/mcp')
@login_required
def mcp_panel():
    """MCP 工具调用面板"""
    from app.services.mcp.mcp_manager import MCPManager
    manager = MCPManager()
    tools = manager.get_available_tools()
    return render_template('mcp/panel.html', tools=tools)


@mcp_bp.route('/mcp/execute', methods=['POST'])
@login_required
def mcp_execute():
    """执行单个工具"""
    from app.services.mcp.mcp_manager import MCPManager
    manager = MCPManager()

    tool_name = request.form.get('tool', '').strip()
    if not tool_name:
        return jsonify({'success': False, 'error': '请指定工具名称'}), 400

    # 收集参数
    params = {'user_id': current_user.id}
    for key, value in request.form.items():
        if key not in ('tool', 'csrf_token') and value.strip():
            # 尝试转换为数字
            try:
                params[key] = int(value)
            except ValueError:
                params[key] = value.strip()

    result = manager.execute_tool(tool_name, **params)

    if request.headers.get('HX-Request'):
        return render_template('mcp/_result.html', result=result, tool_name=tool_name)

    return jsonify(result.to_dict())


@mcp_bp.route('/mcp/analysis', methods=['POST'])
@login_required
def mcp_analysis():
    """执行完整的安全分析计划"""
    from app.services.mcp.mcp_manager import MCPManager
    manager = MCPManager()

    target = request.form.get('target', '').strip()
    experiment_id = request.form.get('experiment_id', type=int)
    scan_id = request.form.get('scan_id', type=int)

    result = manager.execute_analysis_plan(
        user_id=current_user.id,
        target=target,
        experiment_id=experiment_id,
        scan_id=scan_id,
    )

    if request.headers.get('HX-Request'):
        return render_template('mcp/_plan_result.html', plan=result)

    return jsonify(result)


@mcp_bp.route('/mcp/api/tools')
@login_required
def mcp_api_tools():
    """列出所有可用工具 (JSON API)"""
    from app.services.mcp.mcp_manager import MCPManager
    manager = MCPManager()
    return jsonify(manager.get_available_tools())


# ==================== 导出端点 ====================

def _get_plan_data():
    """从请求中获取分析数据"""
    plan_data = request.get_json(silent=True)
    if not plan_data:
        return None, (jsonify({'success': False, 'error': '缺少分析数据'}), 400)
    return plan_data, None


def _export_mcp_report(plan_data, report_format, mime_type, download_prefix):
    """通用的 MCP 报告导出逻辑"""
    from app.services.report_service import ReportService
    service = ReportService()

    report, error = service.create_mcp_report(
        user_id=current_user.id,
        plan_data=plan_data,
        report_format=report_format,
    )

    if error:
        return jsonify({
            'success': False,
            'error': error,
            'report_id': report.id if report else None,
        }), 400

    # 不再直接下载到本地: 报告已保存到「我的报告」(/report), 返回记录链接供前端跳转
    return jsonify({
        'success': True,
        'report_id': report.id,
        'report_url': url_for('report.report_detail', report_id=report.id),
        'format': report_format,
        'title': report.title,
    })


@mcp_bp.route('/mcp/export-pdf', methods=['POST'])
@login_required
@csrf.exempt
def mcp_export_pdf():
    """导出 MCP 分析报告为 PDF，同步到报告列表"""
    plan_data, err = _get_plan_data()
    if err:
        return err
    return _export_mcp_report(plan_data, 'pdf', 'application/pdf', 'AI安全分析')


@mcp_bp.route('/mcp/export-md', methods=['POST'])
@login_required
@csrf.exempt
def mcp_export_md():
    """导出 MCP 分析报告为 Markdown，同步到报告列表"""
    plan_data, err = _get_plan_data()
    if err:
        return err
    return _export_mcp_report(plan_data, 'md', 'text/markdown', 'AI安全分析')


@mcp_bp.route('/mcp/export-json', methods=['POST'])
@login_required
@csrf.exempt
def mcp_export_json():
    """导出 MCP 分析报告为 JSON，同步到报告列表"""
    plan_data, err = _get_plan_data()
    if err:
        return err
    return _export_mcp_report(plan_data, 'json', 'application/json', 'AI安全分析')
