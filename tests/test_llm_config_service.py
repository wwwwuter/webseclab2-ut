"""llm_config_service 单元测试: 用户配置优先、全局回退、无用户回退

AI 已统一为 OpenAI 兼容 API, 配置字典不再包含 mode 字段;
用户是否配置过引擎由「密钥/provider/base_url/model 任一非空」判定。
"""

import pytest

from app.services.llm_config_service import get_user_llm_config
from app.services.crypto_service import encrypt_api_key
from app.models.user import User


class TestGlobalFallback:
    def test_no_user_returns_global(self, app):
        """user_id=None 时返回全局配置"""
        with app.app_context():
            cfg = get_user_llm_config(None)
            assert cfg['provider'] == app.config.get('LLM_API_PROVIDER', 'deepseek')
            assert cfg['api_key'] == app.config.get('LLM_API_KEY', '')
            assert cfg['base_url'] == (app.config.get('LLM_API_BASE_URL') or None)
            assert cfg['model'] == (app.config.get('LLM_API_MODEL') or None)

    def test_user_without_config_falls_back(self, app, db, test_user):
        """用户未配置任何 LLM 字段时回退全局"""
        with app.app_context():
            cfg = get_user_llm_config(test_user.id)
            assert cfg['provider'] == app.config.get('LLM_API_PROVIDER', 'deepseek')
            assert cfg['api_key'] == app.config.get('LLM_API_KEY', '')


class TestUserConfigPriority:
    def test_user_config_overrides_global(self, app, db, test_user):
        """用户配置了 LLM 字段时优先使用用户配置"""
        with app.app_context():
            test_user.llm_api_provider = 'deepseek'
            test_user.llm_api_key_encrypted = encrypt_api_key('sk-user-key')
            test_user.llm_api_base_url = 'https://api.deepseek.com'
            test_user.llm_api_model = 'deepseek-chat'
            db.session.commit()

            cfg = get_user_llm_config(test_user.id)
            assert cfg['provider'] == 'deepseek'
            assert cfg['api_key'] == 'sk-user-key'
            assert cfg['base_url'] == 'https://api.deepseek.com'
            assert cfg['model'] == 'deepseek-chat'

    def test_user_partial_config_uses_global_defaults(self, app, db, test_user):
        """用户只配置部分字段时, 缺失字段回退全局默认"""
        with app.app_context():
            test_user.llm_api_provider = 'openai'
            # 不设置 base_url / model / api_key
            db.session.commit()

            cfg = get_user_llm_config(test_user.id)
            assert cfg['provider'] == 'openai'
            # base_url/model 回退全局 (可能为 None)
            assert cfg['base_url'] == (app.config.get('LLM_API_BASE_URL') or None)
            assert cfg['model'] == (app.config.get('LLM_API_MODEL') or None)
