"""
LLM 配置解析服务

统一从「用户独立配置」或「全局配置」解析 LLM 后端参数, 供 AIService 和 LLMPlanner 复用。

AI 统一使用 OpenAI 兼容 API: 用户配置了任意 LLM 字段即优先使用用户配置;
否则回退全局 current_app.config。两者都没有 API Key 时视为未配置, AI 功能不可用。

返回 dict: {provider, api_key, base_url, model}
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
    :return: dict {provider, api_key, base_url, model}
    """
    # 全局配置兜底
    try:
        cfg = current_app.config
    except RuntimeError:
        cfg = {}

    global_cfg = {
        'provider': cfg.get('LLM_API_PROVIDER', 'deepseek'),
        'api_key': cfg.get('LLM_API_KEY', ''),
        'base_url': cfg.get('LLM_API_BASE_URL', '') or None,
        'model': cfg.get('LLM_API_MODEL', '') or None,
    }

    if user_id is None:
        return global_cfg

    user = db_get_user(user_id)
    if user is None or not _user_has_config(user):
        # 用户未配置, 回退全局
        return global_cfg

    # 用户配置优先
    return {
        'provider': user.llm_api_provider or global_cfg['provider'],
        'api_key': decrypt_api_key(user.llm_api_key_encrypted),
        'base_url': user.llm_api_base_url or global_cfg['base_url'],
        'model': user.llm_api_model or global_cfg['model'],
    }


def _user_has_config(user):
    """判断用户是否配置过自己的 AI 引擎 (任一字段非空即视为已配置)"""
    return bool(
        user.llm_api_key_encrypted
        or user.llm_api_provider
        or user.llm_api_base_url
        or user.llm_api_model
    )


def db_get_user(user_id):
    """查询用户 (独立函数便于测试 mock)"""
    if user_id is None:
        return None
    return db.session.get(User, int(user_id))


# 延迟导入 db, 避免循环依赖
from app.extensions import db  # noqa: E402
