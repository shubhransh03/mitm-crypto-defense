# tests/test_rsa.py
"""Unit tests for rsa_crypto.py — RSA key gen, encrypt/decrypt, sign/verify"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from rsa_crypto import RSACrypto


class TestRSAKeyGeneration:
    def test_generate_keypair_creates_keys(self):
        rsa = RSACrypto(key_size=2048)
        rsa.generate_keypair()
        assert rsa.private_key is not None
        assert rsa.public_key is not None

    def test_key_size_is_correct(self):
        rsa = RSACrypto(key_size=2048)
        rsa.generate_keypair()
        assert rsa.private_key.key_size == 2048

    def test_different_instances_get_different_keys(self):
        rsa1 = RSACrypto(key_size=2048)
        rsa1.generate_keypair()
        rsa2 = RSACrypto(key_size=2048)
        rsa2.generate_keypair()
        pub1 = rsa1.export_public_key()
        pub2 = rsa2.export_public_key()
        assert pub1 != pub2


class TestRSAEncryptDecrypt:
    def setup_method(self):
        self.rsa = RSACrypto(key_size=2048)
        self.rsa.generate_keypair()
        self.message = "Encrypt this secret: AES session key = abc123"

    def test_encrypt_returns_bytes(self):
        ciphertext = self.rsa.encrypt(self.message)
        assert isinstance(ciphertext, bytes)
        assert len(ciphertext) > 0

    def test_decrypt_roundtrip(self):
        ciphertext = self.rsa.encrypt(self.message)
        plaintext = self.rsa.decrypt(ciphertext)
        assert plaintext == self.message

    def test_ciphertext_is_not_plaintext(self):
        ciphertext = self.rsa.encrypt(self.message)
        assert ciphertext != self.message.encode("utf-8")

    def test_same_plaintext_gives_different_ciphertext(self):
        # OAEP uses random padding — same input → different output each time
        ct1 = self.rsa.encrypt(self.message)
        ct2 = self.rsa.encrypt(self.message)
        assert ct1 != ct2

    def test_wrong_private_key_cannot_decrypt(self):
        ciphertext = self.rsa.encrypt(self.message)
        other_rsa = RSACrypto(key_size=2048)
        other_rsa.generate_keypair()
        with pytest.raises(Exception):
            other_rsa.decrypt(ciphertext)


class TestRSADigitalSignatures:
    def setup_method(self):
        self.rsa = RSACrypto(key_size=2048)
        self.rsa.generate_keypair()
        self.message = "Authorise transfer of 500 credits from alice to bob"

    def test_sign_returns_bytes(self):
        sig = self.rsa.create_signature(self.message)
        assert isinstance(sig, bytes)
        assert len(sig) == 256  # RSA-2048 signature is always 256 bytes

    def test_verify_valid_signature(self):
        sig = self.rsa.create_signature(self.message)
        assert self.rsa.verify_signature(self.message, sig) is True

    def test_reject_tampered_message(self):
        sig = self.rsa.create_signature(self.message)
        tampered = "Authorise transfer of 5000 credits from alice to attacker"
        assert self.rsa.verify_signature(tampered, sig) is False

    def test_reject_wrong_public_key(self):
        sig = self.rsa.create_signature(self.message)
        other_rsa = RSACrypto(key_size=2048)
        other_rsa.generate_keypair()
        # Load correct public key into other_rsa
        assert other_rsa.verify_signature(self.message, sig) is False

    def test_bytes_message_sign_verify(self):
        msg_bytes = self.message.encode("utf-8")
        sig = self.rsa.create_signature(msg_bytes)
        assert self.rsa.verify_signature(msg_bytes, sig) is True


class TestRSAKeyExport:
    def setup_method(self):
        self.rsa = RSACrypto(key_size=2048)
        self.rsa.generate_keypair()

    def test_export_public_key_is_pem(self):
        pem = self.rsa.export_public_key()
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_export_private_key_is_pem(self):
        pem = self.rsa.export_private_key()
        assert b"PRIVATE KEY" in pem

    def test_public_key_pem_len_reasonable(self):
        pem = self.rsa.export_public_key()
        assert len(pem) > 100
