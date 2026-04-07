# tests/test_crypto_utils.py
"""Unit tests for crypto_utils.py — AES-GCM, HMAC, SHA-256, PBKDF2"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from crypto_utils import CryptoUtils


class TestKeyGeneration:
    def test_generate_key_returns_32_bytes(self):
        key = CryptoUtils.generate_key()
        assert len(key) == 32

    def test_generate_key_is_random(self):
        key1 = CryptoUtils.generate_key()
        key2 = CryptoUtils.generate_key()
        assert key1 != key2

    def test_generate_iv_returns_16_bytes(self):
        iv = CryptoUtils.generate_iv()
        assert len(iv) == 16


class TestAESGCMEncryption:
    def setup_method(self):
        self.key = CryptoUtils.generate_key()
        self.message = "Secret message: transfer 100 credits to bob"

    def test_encrypt_returns_string(self):
        result = CryptoUtils.encrypt_aes_gcm(self.message, self.key)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_decrypt_roundtrip(self):
        encrypted = CryptoUtils.encrypt_aes_gcm(self.message, self.key)
        decrypted = CryptoUtils.decrypt_aes_gcm(encrypted, self.key)
        assert decrypted == self.message

    def test_encrypt_bytes_input(self):
        msg_bytes = self.message.encode("utf-8")
        encrypted = CryptoUtils.encrypt_aes_gcm(msg_bytes, self.key)
        decrypted = CryptoUtils.decrypt_aes_gcm(encrypted, self.key)
        assert decrypted == self.message

    def test_ciphertext_differs_from_plaintext(self):
        encrypted = CryptoUtils.encrypt_aes_gcm(self.message, self.key)
        assert encrypted != self.message

    def test_same_plaintext_different_ciphertext_per_call(self):
        enc1 = CryptoUtils.encrypt_aes_gcm(self.message, self.key)
        enc2 = CryptoUtils.encrypt_aes_gcm(self.message, self.key)
        assert enc1 != enc2  # Fresh nonce per call

    def test_wrong_key_fails_decryption(self):
        encrypted = CryptoUtils.encrypt_aes_gcm(self.message, self.key)
        wrong_key = CryptoUtils.generate_key()
        with pytest.raises(Exception):
            CryptoUtils.decrypt_aes_gcm(encrypted, wrong_key)

    def test_tampered_ciphertext_fails(self):
        encrypted = CryptoUtils.encrypt_aes_gcm(self.message, self.key)
        # Corrupt one char in the base64 ciphertext payload
        chars = list(encrypted)
        chars[-5] = 'Z' if chars[-5] != 'Z' else 'A'
        tampered = ''.join(chars)
        with pytest.raises(Exception):
            CryptoUtils.decrypt_aes_gcm(tampered, self.key)


class TestHMAC:
    def setup_method(self):
        self.key = CryptoUtils.generate_key()
        self.data = b"Important transaction: 500 credits"

    def test_compute_hmac_returns_bytes(self):
        tag = CryptoUtils.compute_hmac_sha256(self.data, self.key)
        assert isinstance(tag, bytes)
        assert len(tag) == 32  # SHA-256 = 32 bytes

    def test_verify_valid_hmac(self):
        tag = CryptoUtils.compute_hmac_sha256(self.data, self.key)
        assert CryptoUtils.verify_hmac_sha256(self.data, tag, self.key) is True

    def test_reject_tampered_data(self):
        tag = CryptoUtils.compute_hmac_sha256(self.data, self.key)
        tampered = b"Important transaction: 5000 credits"
        assert CryptoUtils.verify_hmac_sha256(tampered, tag, self.key) is False

    def test_reject_wrong_key(self):
        tag = CryptoUtils.compute_hmac_sha256(self.data, self.key)
        wrong_key = CryptoUtils.generate_key()
        assert CryptoUtils.verify_hmac_sha256(self.data, tag, wrong_key) is False

    def test_different_keys_produce_different_tags(self):
        k1, k2 = CryptoUtils.generate_key(), CryptoUtils.generate_key()
        t1 = CryptoUtils.compute_hmac_sha256(self.data, k1)
        t2 = CryptoUtils.compute_hmac_sha256(self.data, k2)
        assert t1 != t2


class TestSHA256:
    def test_hash_is_deterministic(self):
        h1 = CryptoUtils.hash_sha256_hex("alice")
        h2 = CryptoUtils.hash_sha256_hex("alice")
        assert h1 == h2

    def test_different_inputs_produce_different_hashes(self):
        h1 = CryptoUtils.hash_sha256_hex("alice")
        h2 = CryptoUtils.hash_sha256_hex("alice123")
        assert h1 != h2

    def test_hash_returns_64_char_hex(self):
        h = CryptoUtils.hash_sha256_hex("test")
        assert isinstance(h, str)
        assert len(h) == 64

    def test_hash_bytes_input(self):
        h = CryptoUtils.hash_sha256_hex(b"test")
        assert len(h) == 64


class TestPBKDF2:
    def test_derive_returns_key_and_salt(self):
        key, salt = CryptoUtils.derive_key_from_password("my_password")
        assert len(key) == 32
        assert len(salt) == 16

    def test_same_password_different_salt_gives_different_key(self):
        key1, _ = CryptoUtils.derive_key_from_password("password")
        key2, _ = CryptoUtils.derive_key_from_password("password")
        assert key1 != key2  # Different random salts

    def test_same_password_same_salt_gives_same_key(self):
        key1, salt = CryptoUtils.derive_key_from_password("password")
        key2, _ = CryptoUtils.derive_key_from_password("password", salt=salt)
        assert key1 == key2

    def test_wrong_password_with_same_salt_gives_different_key(self):
        key1, salt = CryptoUtils.derive_key_from_password("correct_horse")
        key2, _ = CryptoUtils.derive_key_from_password("wrong_password", salt=salt)
        assert key1 != key2
