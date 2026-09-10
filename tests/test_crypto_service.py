"""crypto_service 单元测试: 加密/解密往返、掩码、解密失败容错"""

import pytest

from app.services.crypto_service import (
    encrypt_api_key, decrypt_api_key, mask_api_key,
)


class TestEncryptDecrypt:
    def test_roundtrip(self, app):
        """加密后能解密回原文"""
        with app.app_context():
            plain = 'sk-abcdef1234567890'
            cipher = encrypt_api_key(plain)
            assert cipher != plain
            assert decrypt_api_key(cipher) == plain

    def test_empty_plaintext(self, app):
        """空明文加密返回空串"""
        with app.app_context():
            assert encrypt_api_key('') == ''
            assert encrypt_api_key(None) == ''

    def test_empty_ciphertext(self, app):
        """空密文解密返回空串"""
        with app.app_context():
            assert decrypt_api_key('') == ''
            assert decrypt_api_key(None) == ''

    def test_key_derivation_is_deterministic(self, app):
        """密钥派生确定性: 同一 SECRET_KEY 加密的密文可被解密回原文 (Fernet 每次加密带随机 IV, 密文不同但可解)"""
        with app.app_context():
            plain = 'sk-test-key'
            cipher1 = encrypt_api_key(plain)
            cipher2 = encrypt_api_key(plain)
            # Fernet 每次加密随机 IV, 密文不同
            assert cipher1 != cipher2
            # 但都能解密回原文
            assert decrypt_api_key(cipher1) == plain
            assert decrypt_api_key(cipher2) == plain

    def test_invalid_ciphertext_returns_empty(self, app):
        """非法密文解密返回空串, 不抛异常"""
        with app.app_context():
            assert decrypt_api_key('not-a-valid-token') == ''


class TestMask:
    def test_mask_long_key(self):
        """长 key 掩码保留首尾 4 位"""
        assert mask_api_key('sk-abcdef1234567890') == 'sk-a****7890'

    def test_mask_short_key(self):
        """短 key 掩码为 ****"""
        assert mask_api_key('short') == '****'

    def test_mask_empty(self):
        """空值掩码返回空串"""
        assert mask_api_key('') == ''
        assert mask_api_key(None) == ''
