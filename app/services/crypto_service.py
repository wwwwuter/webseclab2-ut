"""
加密服务模块

用 SECRET_KEY 派生 Fernet 密钥，对用户 API Key 做对称加密存储。
- 加密: encrypt_api_key(plaintext) -> ciphertext
- 解密: decrypt_api_key(ciphertext) -> plaintext (失败返回空串, 不抛异常)
- 掩码: mask_api_key(plaintext) -> 'sk-****abcd' (供前端展示)

设计原则:
  - 不引入新依赖 (cryptography 已可用)。
  - 解密失败 (如 SECRET_KEY 变更) 时返回空串, 保证上层优雅降级。
  - API Key 永不返回明文给前端, 只返回掩码。
"""

import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)


def _get_fernet():
    """从 SECRET_KEY 派生 Fernet 密钥 (确定性, 同一 SECRET_KEY 得到同一密钥)"""
    from flask import current_app
    try:
        secret = current_app.config.get('SECRET_KEY', '')
    except RuntimeError:
        secret = ''
    if not secret:
        # 无 SECRET_KEY 时用固定派生, 保证测试环境可用 (生产必须配置 SECRET_KEY)
        secret = 'webseclab-fallback-secret'
    digest = hashlib.sha256(secret.encode('utf-8')).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt_api_key(plaintext):
    """加密 API Key, 返回密文 (str)"""
    if not plaintext:
        return ''
    try:
        return _get_fernet().encrypt(plaintext.encode('utf-8')).decode('utf-8')
    except Exception as e:
        logger.error('API Key 加密失败: %s', e)
        return ''


def decrypt_api_key(ciphertext):
    """解密 API Key, 返回明文 (str); 解密失败返回空串"""
    if not ciphertext:
        return ''
    try:
        return _get_fernet().decrypt(ciphertext.encode('utf-8')).decode('utf-8')
    except (InvalidToken, Exception) as e:
        logger.warning('API Key 解密失败 (可能 SECRET_KEY 已变更): %s', e)
        return ''


def mask_api_key(plaintext):
    """生成 API Key 掩码, 如 'sk-****abcd'; 空值返回空串"""
    if not plaintext:
        return ''
    if len(plaintext) <= 8:
        return '****'
    return plaintext[:4] + '****' + plaintext[-4:]
