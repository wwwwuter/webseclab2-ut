"""
WebSecLab 配置文件
包含三个环境配置: 开发、测试、生产
"""

import os
import secrets
import warnings

# 项目根目录
BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


def _resolve_secret_key(env_name='SECRET_KEY'):
    """
    解析 SECRET_KEY: 优先读环境变量; 缺失时运行期生成随机密钥并告警。
    不再使用任何已知的硬编码常量, 避免"公开弱默认密钥"风险。
    注意: 随机生成的密钥每次进程启动都不同, 会导致已有会话失效,
    生产环境务必通过环境变量 SECRET_KEY 提供固定的强随机值。
    """
    key = os.environ.get(env_name)
    if key:
        return key
    warnings.warn(
        'SECRET_KEY 未通过环境变量设置, 已生成临时随机密钥 (重启后失效)。'
        '生产环境请通过环境变量 SECRET_KEY 提供固定的强随机值。',
        RuntimeWarning
    )
    return secrets.token_hex(32)


class BaseConfig:
    """基础配置类"""
    SECRET_KEY = _resolve_secret_key('SECRET_KEY')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # 显式开启 CSRF 防护 (测试环境在 TestingConfig 中关闭)
    WTF_CSRF_ENABLED = True

    # Cookie 安全标记
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    # Secure 标志仅在 HTTPS / 生产环境下开启, 本地 http 开发默认关闭以免无法登录。
    # 生产部署请设置环境变量 SESSION_COOKIE_SECURE=true。
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() in ('1', 'true', 'yes', 'on')

    # LLM 配置: ollama (本地) 或 api (云端)
    LLM_MODE = os.environ.get('LLM_MODE', 'ollama')  # 'ollama' 或 'api'
    LLM_API_PROVIDER = os.environ.get('LLM_API_PROVIDER', 'deepseek')  # deepseek/dashscope/openai
    LLM_API_KEY = os.environ.get('LLM_API_KEY', '')
    LLM_API_BASE_URL = os.environ.get('LLM_API_BASE_URL', '')  # 留空则用提供商默认
    LLM_API_MODEL = os.environ.get('LLM_API_MODEL', '')  # 留空则用提供商默认

    # ==================== 系统状态探测 (首页"系统状态"卡) ====================
    # 各组件真实连通性探测地址, 支持环境变量覆盖以便部署时指向真实服务。
    DVWA_BASE_URL = os.environ.get('DVWA_BASE_URL', 'http://localhost/dvwa')
    METASPLOIT_RPC_HOST = os.environ.get('METASPLOIT_RPC_HOST', '127.0.0.1')
    METASPLOIT_RPC_PORT = int(os.environ.get('METASPLOIT_RPC_PORT', '55553'))
    # 系统状态探测结果缓存秒数; 设为 0 关闭缓存 (测试环境使用)
    SYSTEM_STATUS_TTL = int(os.environ.get('SYSTEM_STATUS_TTL', '30'))


class DevelopmentConfig(BaseConfig):
    """开发环境配置"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'database', 'webseclab.db')


class TestingConfig(BaseConfig):
    """测试环境配置"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    # 关闭系统状态缓存, 保证测试确定性 (避免跨用例命中缓存)
    SYSTEM_STATUS_TTL = 0


class ProductionConfig(BaseConfig):
    """生产环境配置"""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'database', 'webseclab.db')


# 配置映射字典
config_map = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
