# crypto_utils.py
"""
Cryptographic Utilities for Secure Communication
Implements AES encryption, HMAC, hashing, and key derivation
"""

import os
import sys
import hashlib
import hmac
from base64 import b64encode, b64decode

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("ERROR: cryptography library not installed")
    sys.exit(1)


class CryptoUtils:
    """Cryptographic utility functions"""

    BLOCK_SIZE = 128  # AES block size in bits
    KEY_SIZE = 256    # AES key size in bits

    @staticmethod
    def generate_key(length=32):
        """Generate random cryptographic key"""
        return os.urandom(length)

    @staticmethod
    def generate_iv(length=16):
        """Generate random initialization vector"""
        return os.urandom(length)

    @staticmethod
    def encrypt_aes_gcm(plaintext, key):
        """
        Encrypt data using AES-256-GCM
        Returns: IV + ciphertext + tag (base64 encoded)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        iv = os.urandom(12)  # 96-bit IV for GCM
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Combine IV + ciphertext + tag
        encrypted_data = iv + ciphertext + encryptor.tag

        return b64encode(encrypted_data).decode('utf-8')

    @staticmethod
    def decrypt_aes_gcm(encrypted_data_b64, key):
        """
        Decrypt data encrypted with AES-256-GCM
        Expected format: IV (12 bytes) + ciphertext + tag (16 bytes)
        """
        encrypted_data = b64decode(encrypted_data_b64)

        iv = encrypted_data[:12]
        ciphertext = encrypted_data[12:-16]
        tag = encrypted_data[-16:]

        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext.decode('utf-8')

    @staticmethod
    def compute_hmac_sha256(data, key):
        """Compute HMAC-SHA256 for data integrity"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')

        return hmac.new(key, data, hashlib.sha256).digest()

    @staticmethod
    def verify_hmac_sha256(data, signature, key):
        """Verify HMAC-SHA256 signature"""
        expected_signature = CryptoUtils.compute_hmac_sha256(data, key)
        return hmac.compare_digest(signature, expected_signature)

    @staticmethod
    def hash_sha256(data):
        """Compute SHA-256 hash"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).digest()

    @staticmethod
    def hash_sha256_hex(data):
        """Compute SHA-256 hash and return hex"""
        return CryptoUtils.hash_sha256(data).hex()

    @staticmethod
    def derive_key_from_password(password, salt=None, iterations=100000, length=32):
        """Derive encryption key from password using PBKDF2"""
        if isinstance(password, str):
            password = password.encode('utf-8')

        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password)
        return key, salt

    @staticmethod
    def encode_base64(data):
        """Encode bytes to base64 string"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return b64encode(data).decode('utf-8')

    @staticmethod
    def decode_base64(data):
        """Decode base64 string to bytes"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return b64decode(data)


class SymmetricCrypto:
    """Symmetric encryption/decryption wrapper"""

    def __init__(self, password=None, key=None):
        """Initialize with password or key"""
        if key:
            self.key = key
        elif password:
            self.key, self.salt = CryptoUtils.derive_key_from_password(password)
        else:
            self.key = CryptoUtils.generate_key()

    def encrypt(self, plaintext):
        """Encrypt plaintext"""
        return CryptoUtils.encrypt_aes_gcm(plaintext, self.key)

    def decrypt(self, ciphertext_b64):
        """Decrypt ciphertext"""
        return CryptoUtils.decrypt_aes_gcm(ciphertext_b64, self.key)


class IntegrityChecker:
    """Ensure data integrity with HMAC"""

    def __init__(self, key=None):
        """Initialize with HMAC key"""
        self.key = key or CryptoUtils.generate_key()

    def sign(self, data):
        """Sign data with HMAC"""
        signature = CryptoUtils.compute_hmac_sha256(data, self.key)
        return b64encode(signature).decode('utf-8')

    def verify(self, data, signature_b64):
        """Verify HMAC signature"""
        try:
            signature = b64decode(signature_b64)
            return CryptoUtils.verify_hmac_sha256(data, signature, self.key)
        except Exception:
            return False


# Example usage and demonstration
if __name__ == "__main__":
    print("[*] Cryptographic Utils Demonstration\n")

    # Test 1: AES-GCM Encryption
    print("[Test 1] AES-256-GCM Encryption")
    print("-" * 50)
    key = CryptoUtils.generate_key()
    plaintext = "This is a secret message"
    encrypted = CryptoUtils.encrypt_aes_gcm(plaintext, key)
    decrypted = CryptoUtils.decrypt_aes_gcm(encrypted, key)

    print(f"Original: {plaintext}")
    print(f"Encrypted: {encrypted[:50]}...")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {plaintext == decrypted}\n")

    # Test 2: HMAC Verification
    print("[Test 2] HMAC-SHA256 Integrity")
    print("-" * 50)
    data = "Important data"
    hmac_key = CryptoUtils.generate_key()
    signature = CryptoUtils.compute_hmac_sha256(data, hmac_key)

    print(f"Data: {data}")
    print(f"Signature: {signature.hex()[:32]}...")
    print(f"Verified: {CryptoUtils.verify_hmac_sha256(data, signature, hmac_key)}\n")

    # Test 3: Password-Based Key Derivation
    print("[Test 3] PBKDF2 Key Derivation")
    print("-" * 50)
    password = "MySecurePassword123!"
    derived_key, salt = CryptoUtils.derive_key_from_password(password)

    print(f"Password: {password}")
    print(f"Salt: {salt.hex()[:32]}...")
    print(f"Derived Key: {derived_key.hex()[:32]}...")
    print(f"Key Length: {len(derived_key)} bytes\n")

    # Test 4: SHA-256 Hashing
    print("[Test 4] SHA-256 Hashing")
    print("-" * 50)
    data = "Hash me"
    hash_value = CryptoUtils.hash_sha256_hex(data)

    print(f"Data: {data}")
    print(f"Hash: {hash_value}\n")

    print("[✓] All cryptographic tests completed successfully!")
