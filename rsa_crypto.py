# rsa_crypto.py
"""
RSA Encryption and Digital Signatures
Implements asymmetric cryptography for authentication
"""

import sys

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("ERROR: cryptography library not installed")
    sys.exit(1)

from base64 import b64encode, b64decode


class RSACrypto:
    """RSA encryption and signing operations"""

    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.backend = default_backend()
        self.private_key = None
        self.public_key = None

    def generate_keypair(self):
        """Generate RSA key pair"""
        print(f"[*] Generating RSA key pair ({self.key_size}-bit)...")

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=self.backend
        )
        self.public_key = self.private_key.public_key()

        print("[✓] RSA key pair generated")
        return self.public_key

    def encrypt(self, plaintext, public_key=None):
        """
        Encrypt plaintext with RSA public key
        Uses OAEP padding with SHA-256
        """
        if public_key is None:
            public_key = self.public_key

        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt(self, ciphertext):
        """Decrypt ciphertext with RSA private key"""
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')

    def create_signature(self, data):
        """Create digital signature of data"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, data, signature, public_key=None):
        """Verify digital signature"""
        if public_key is None:
            public_key = self.public_key

        if isinstance(data, str):
            data = data.encode('utf-8')

        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def export_public_key(self):
        """Export public key in PEM format"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def export_private_key(self):
        """Export private key in PEM format"""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def import_public_key(self, public_key_pem):
        """Import public key from PEM format"""
        self.public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=self.backend
        )


class RSASimulation:
    """Simulate RSA encryption and signature verification"""

    def run_encryption_demo(self):
        """Demonstrate RSA encryption"""
        print("=" * 70)
        print("RSA ENCRYPTION DEMONSTRATION")
        print("=" * 70)

        # Generate key pair
        rsa_crypto = RSACrypto(key_size=2048)
        rsa_crypto.generate_keypair()

        # Encrypt message
        plaintext = "Confidential: User Password is SecurePass123!"
        print(f"\n[Original Message] {plaintext}")

        ciphertext = rsa_crypto.encrypt(plaintext)
        print(f"[Encrypted] {ciphertext.hex()[:64]}... (total: {len(ciphertext)} bytes)")

        # Decrypt message
        decrypted = rsa_crypto.decrypt(ciphertext)
        print(f"[Decrypted] {decrypted}")
        print(f"[Match] {plaintext == decrypted}")

        return plaintext == decrypted

    def run_signature_demo(self):
        """Demonstrate digital signatures"""
        print("\n" + "=" * 70)
        print("DIGITAL SIGNATURE DEMONSTRATION")
        print("=" * 70)

        # Generate key pair
        rsa_crypto = RSACrypto(key_size=2048)
        rsa_crypto.generate_keypair()

        # Create signature
        message = "Official Server Message"
        print(f"\n[Original Message] {message}")

        signature = rsa_crypto.create_signature(message)
        print(f"[Signature] {signature.hex()[:64]}... (total: {len(signature)} bytes)")

        # Verify signature
        is_valid = rsa_crypto.verify_signature(message, signature)
        print(f"[Signature Valid] {is_valid}")

        # Try to verify with tampered message
        tampered_message = "Malicious Message"
        is_valid_tampered = rsa_crypto.verify_signature(tampered_message, signature)
        print(f"\n[Tampered Message] {tampered_message}")
        print(f"[Signature Valid for Tampered] {is_valid_tampered}")

        print("\n[Key Insight] Digital signature detects even single bit changes!")

        return is_valid and not is_valid_tampered

    def run_key_exchange_demo(self):
        """Demonstrate RSA for key exchange"""
        print("\n" + "=" * 70)
        print("RSA FOR SYMMETRIC KEY EXCHANGE")
        print("=" * 70)

        # Server generates key pair
        print("\n[SERVER] Generating RSA key pair...")
        server_rsa = RSACrypto(key_size=2048)
        server_rsa.generate_keypair()
        server_public_key = server_rsa.export_public_key()

        # Client gets server's public key and encrypts session key
        print("[CLIENT] Received server's public key")
        client_rsa = RSACrypto()
        client_rsa.import_public_key(server_public_key)

        # Generate symmetric key for session
        import os
        session_key = os.urandom(32)
        print(f"\n[CLIENT] Generated session key: {session_key.hex()[:32]}...")

        # Encrypt session key with server's public key
        encrypted_session_key = client_rsa.encrypt(session_key)
        print(f"[CLIENT] Encrypted session key: {encrypted_session_key.hex()[:32]}...")

        # Server decrypts session key
        print("\n[SERVER] Received encrypted session key")
        decrypted_session_key = server_rsa.decrypt(encrypted_session_key)

        # Verify
        match = session_key == decrypted_session_key
        print(f"[Verification] Session keys match: {match}")
        print(f"[Security] Only server can decrypt (has private key)")

        return match


# Example usage and demonstration
if __name__ == "__main__":
    sim = RSASimulation()

    # Run demonstrations
    enc_success = sim.run_encryption_demo()
    sig_success = sim.run_signature_demo()
    key_success = sim.run_key_exchange_demo()

    print("\n" + "=" * 70)
    if enc_success and sig_success and key_success:
        print("[✓] All RSA demonstrations completed successfully!")
    else:
        print("[✗] Some demonstrations failed!")
    print("=" * 70)
