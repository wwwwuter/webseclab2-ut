"""
LLM 配置解析服务

统一从「用户独立配置」或「全局配置」解析 LLM 后端参数, 供 AIService 和 LLMPlanner 复用。

优先级:
  1. 用户配置了 llm_mode → 使用用户配置 (解密 API Key)
  2. 用户未配置 → 回退全局 current_app.config

返回 dict: {mode, provider, api_key, base_url, model}
"""

import logging

from flask import current_app

from app.models.user import User
from app.services.crypto_service import decrypt_api_key

logger = logging.getLogger(__name__)


def get_user_llm_config(user_id=None):
    """
    获取指定用户的 LLM 配置, 用户配置优先, 未配置回退全局。

    :param user_id: 用户ID; None 时直接返回全局配置
    :return: dict {mode, provider, api_key, base_url, model}
    """
    # 全局配置兜底
    try:
        cfg = current_app.config
    except RuntimeError:
        cfg = {}

    global_cfg = {
        'mode': cfg.get('LLM_MODE', 'ollama'),
        'provider': cfg.get('LLM_API_PROVIDER', 'deepseek'),
        'api_key': cfg.get('LLM_API_KEY', ''),
        'base_url': cfg.get('LLM_API_BASE_URL', '') or None,
        'model': cfg.get('LLM_API_MODEL', '') or None,
    }

    if user_id is None:
        return global_cfg

    user = db_get_user(user_id)
    if user is None or not user.llm_mode:
        # 用户未配置, 回退全局
        return global_cfg

    # 用户配置优先
    return {
        'mode': user.llm_mode,
        'provider': user.llm_api_provider or global_cfg['provider'],
        'api_key': decrypt_api_key(user.llm_api_key_encrypted),
        'base_url': user.llm_api_base_url or global_cfg['base_url'],
        'model': user.llm_api_model or global_cfg['model'],
    }


def db_get_user(user_id):
    """查询用户 (独立函数便于测试 mock)"""
    if user_id is None:
        return None
    return db.session.get(User, int(user_id))


# 延迟导入 db, 避免循环依赖
from app.extensions import db  # noqa: E402
