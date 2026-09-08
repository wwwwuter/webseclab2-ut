"""
WebSecLab 结构化日志配置模块

提供统一的日志管理:
- 控制台输出: 彩色简洁格式 (开发环境 DEBUG 级别)
- 文件输出: 日志轮转 (RotatingFileHandler, 5MB × 3 备份)
- 按模块分级: 每个 Python 模块通过 get_logger(__name__) 获取独立 logger

用法:
    from app.logging_config import get_logger
    logger = get_logger(__name__)
    logger.info('操作成功')
    logger.error('失败: %s', detail)

在 create_app() 中调用 setup_logging(app) 完成初始化。
"""

import os
import sys
import logging
from logging.handlers import RotatingFileHandler

# 日志格式: 时间 | 级别 | 模块名 | 消息
LOG_FORMAT = '%(asctime)s [%(levelname)-7s] %(name)-24s | %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# 降低第三方库的日志噪音
NOISY_LOGGERS = [
    'werkzeug',        # Flask 开发服务器
    'urllib3',         # HTTP 客户端
    'requests',        # requests 库
    'chromadb',        # ChromaDB 向量库
    'sentence_transformers',  # 嵌入模型
]


def setup_logging(app):
    """
    初始化应用日志系统
    在 create_app() 中调用, 根据配置自动调整日志级别和输出方式

    :param app: Flask 应用实例
    """
    # 日志目录: 项目根目录/logs/
    log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
    os.makedirs(log_dir, exist_ok=True)

    # 根据环境确定日志级别
    is_debug = app.config.get('DEBUG', False)
    is_testing = app.config.get('TESTING', False)

    root_level = logging.DEBUG if is_debug else logging.INFO
    file_level = logging.DEBUG  # 文件始终记录 DEBUG
    console_level = logging.DEBUG if is_debug else logging.INFO

    # ---- 根日志器 ----
    root_logger = logging.getLogger()
    root_logger.setLevel(root_level)

    # 清除已有 handler (防止重复添加)
    root_logger.handlers.clear()

    # ---- 控制台 Handler ----
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
    root_logger.addHandler(console_handler)

    # ---- 文件 Handler (轮转) ----
    if not is_testing:
        log_file = os.path.join(log_dir, 'webseclab.log')
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=3,
            encoding='utf-8'
        )
        file_handler.setLevel(file_level)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
        root_logger.addHandler(file_handler)

    # ---- 降低第三方库噪音 ----
    for name in NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)

    # ---- 错误日志单独文件 (仅非测试环境) ----
    if not is_testing:
        error_file = os.path.join(log_dir, 'webseclab_error.log')
        error_handler = RotatingFileHandler(
            error_file,
            maxBytes=5 * 1024 * 1024,
            backupCount=2,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
        root_logger.addHandler(error_handler)

    # 记录启动信息
    app_logger = get_logger('app')
    env_name = 'TESTING' if is_testing else ('DEBUG' if is_debug else 'PRODUCTION')
    app_logger.info('WebSecLab 日志系统已初始化 [环境=%s, 级别=%s]',
                     env_name, logging.getLevelName(root_level))
    if not is_testing:
        app_logger.info('日志文件: %s', os.path.join(log_dir, 'webseclab.log'))


def get_logger(name):
    """
    获取模块级 logger

    :param name: 通常传入 __name__, 如 'app.services.scanner_service'
    :return: logging.Logger 实例
    """
    return logging.getLogger(name)
