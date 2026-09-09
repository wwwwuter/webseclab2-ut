"""
DVWA Hook 上报路由模块
接收 DVWA 靶场 Hook 上报的实验事件, 校验 HMAC 签名后记录并自动判定实验成功

路由:
  POST /api/dvwa/hook  - 接收 Hook 事件上报 (JSON, HMAC 签名校验)

鉴权说明:
- 使用共享密钥 HMAC-SHA256 签名 (防伪造)
- 上报体含 timestamp, 校验时间戳偏差防重放
- 该端点为外部 DVWA 靶场调用, 无登录态, 故豁免 CSRF (由 HMAC 签名替代防护)
"""

import time

from flask import Blueprint, request, jsonify, current_app
from app.extensions import csrf
from app.services.dvwa_service import DVWAService
from app.services.experiment_service import ExperimentService

dvwa_bp = Blueprint('dvwa', __name__)


@dvwa_bp.route('/api/dvwa/hook', methods=['POST'])
@csrf.exempt
def dvwa_hook():
    """
    接收 DVWA Hook 事件上报
    请求体 (JSON):
        experiment_token: 实验Token
        event_type:       事件类型 (如 sqli_success)
        payload:          事件负载 (dict, 可空)
        timestamp:        上报时间戳 (Unix秒)
        signature:        HMAC-SHA256 签名 (对 canonical_payload 签名)
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'success': False, 'error': '请求体必须为 JSON'}), 400

    experiment_token = (data.get('experiment_token') or '').strip()
    event_type = (data.get('event_type') or '').strip()
    payload = data.get('payload')
    timestamp = data.get('timestamp')
    signature = (data.get('signature') or '').strip()

    # 基本字段校验
    if not experiment_token or not event_type:
        return jsonify({'success': False, 'error': '缺少 experiment_token 或 event_type'}), 400
    if not isinstance(timestamp, (int, float)):
        return jsonify({'success': False, 'error': '缺少有效的 timestamp'}), 400

    # 时间戳偏差校验 (防重放)
    tolerance = current_app.config.get('DVWA_HOOK_TIMESTAMP_TOLERANCE', 300)
    if abs(time.time() - float(timestamp)) > tolerance:
        return jsonify({'success': False, 'error': '时间戳超出允许偏差'}), 400

    # HMAC 签名校验 (防伪造)
    canonical = DVWAService.canonical_payload(experiment_token, event_type, int(timestamp))
    if not DVWAService.verify_signature(canonical, signature):
        return jsonify({'success': False, 'error': '签名校验失败'}), 401

    # 记录事件并自动判定
    event, error = ExperimentService.record_hook_event(
        experiment_token=experiment_token,
        event_type=event_type,
        payload=payload,
        timestamp=int(timestamp),
    )
    if error:
        return jsonify({'success': False, 'error': error}), 404

    return jsonify({
        'success': True,
        'event_id': event.id,
        'triggered_success': event.triggered_success,
    })
