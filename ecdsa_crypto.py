# ecdsa_crypto.py
"""
ECDSA (Elliptic Curve Digital Signatures) Implementation
More efficient than RSA: smaller keys, faster operations, same security level.

Key Comparison:
  RSA-2048  ≈ 112-bit security | 2048-bit key | ~256-byte signature
  ECDSA-256 ≈ 128-bit security |  256-bit key |  ~72-byte signature  ← 8x smaller!
  ECDSA-384 ≈ 192-bit security |  384-bit key |  ~96-byte signature
"""

import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1, SECP384R1, generate_private_key, ECDSA
    )
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("ERROR: cryptography library not installed")
    sys.exit(1)

from base64 import b64encode, b64decode


class ECDSACrypto:
    """ECDSA key generation, signing, and verification (P-256 curve by default)"""

    def __init__(self, curve=None):
        self.curve = curve or SECP256R1()
        self.backend = default_backend()
        self.private_key = None
        self.public_key = None

    def generate_keypair(self):
        """Generate ECDSA private/public key pair"""
        curve_name = type(self.curve).__name__
        print(f"[*] Generating ECDSA key pair ({curve_name})...")

        self.private_key = generate_private_key(self.curve, self.backend)
        self.public_key = self.private_key.public_key()

        key_size = self.private_key.key_size
        print(f"[✓] ECDSA key pair generated ({key_size}-bit)")
        print(f"    Security equivalent: RSA-{key_size * 12}-bit (approx.)")
        return self.public_key

    def sign(self, data):
        """Sign data with the ECDSA private key (SHA-256 hash)"""
        if self.private_key is None:
            raise ValueError("No private key. Call generate_keypair() first.")
        if isinstance(data, str):
            data = data.encode('utf-8')

        signature = self.private_key.sign(data, ECDSA(hashes.SHA256()))
        return signature

    def verify(self, data, signature, public_key=None):
        """Verify an ECDSA signature — returns True if valid, False if tampered"""
        if public_key is None:
            public_key = self.public_key
        if isinstance(data, str):
            data = data.encode('utf-8')

        try:
            public_key.verify(signature, data, ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    def export_public_key_pem(self):
        """Export public key in PEM format for sharing"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def export_private_key_pem(self):
        """Export private key in PEM format (keep secret!)"""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def import_public_key(self, public_key_pem: bytes):
        """Import a public key from PEM bytes"""
        self.public_key = serialization.load_pem_public_key(
            public_key_pem, backend=self.backend
        )


class ECDSASimulation:
    """Demonstrate ECDSA signatures and compare with RSA"""

    def run_signature_demo(self):
        """Full ECDSA sign + verify + tamper detection demo"""
        print("=" * 70)
        print("ECDSA DIGITAL SIGNATURE DEMONSTRATION")
        print("=" * 70)

        ec = ECDSACrypto(curve=SECP256R1())
        ec.generate_keypair()

        message = "Secure bank transfer: 500 credits from alice to bob"
        print(f"\n[Original Message] {message}")

        # Sign
        signature = ec.sign(message)
        print(f"[Signature] {signature.hex()[:64]}... ({len(signature)} bytes)")

        # Verify original
        valid = ec.verify(message, signature)
        print(f"[Signature Valid] {valid}")

        # Tampered message
        tampered = "Secure bank transfer: 5000 credits from alice to attacker"
        valid_tampered = ec.verify(tampered, signature)
        print(f"\n[Tampered Message] {tampered}")
        print(f"[Signature Valid for Tampered] {valid_tampered}")
        print("[Key Insight] Even a single character change makes signature invalid!")

        return valid and not valid_tampered

    def run_comparison_demo(self):
        """Show ECDSA vs RSA efficiency comparison"""
        import time

        print("\n" + "=" * 70)
        print("ECDSA vs RSA PERFORMANCE COMPARISON")
        print("=" * 70)

        # ECDSA P-256
        t0 = time.time()
        ec = ECDSACrypto(SECP256R1())
        ec.generate_keypair()
        sig = ec.sign("test message for benchmarking")
        ec.verify("test message for benchmarking", sig)
        ecdsa_time = time.time() - t0

        # RSA-2048
        from rsa_crypto import RSACrypto
        t0 = time.time()
        rsa = RSACrypto(key_size=2048)
        rsa.generate_keypair()
        rsa_sig = rsa.create_signature("test message for benchmarking")
        rsa.verify_signature("test message for benchmarking", rsa_sig)
        rsa_time = time.time() - t0

        print(f"\n  Algorithm       | Key Bits | Sig Size | Time (keygen+sign+verify)")
        print(f"  ----------------+----------+----------+--------------------------")
        print(f"  ECDSA (P-256)   |  256-bit |{len(sig):5} bytes | {ecdsa_time:.3f}s")
        print(f"  RSA             | 2048-bit |{len(rsa_sig):5} bytes | {rsa_time:.3f}s")
        print(f"\n  ECDSA is {rsa_time/ecdsa_time:.1f}x faster with {len(rsa_sig)//len(sig)}x smaller signatures!")
        print("  ECDSA is standard in TLS 1.3, JWT (ES256), and modern PKI.")

    def run_key_exchange_demo(self):
        """Demonstrate public key sharing between parties"""
        print("\n" + "=" * 70)
        print("ECDSA PUBLIC KEY SHARING (Server Authentication)")
        print("=" * 70)

        # Server generates key pair
        print("\n[SERVER] Generating ECDSA key pair...")
        server_ec = ECDSACrypto()
        server_ec.generate_keypair()
        server_pub_pem = server_ec.export_public_key_pem()
        print(f"[SERVER] Public key exported ({len(server_pub_pem)} bytes PEM)")

        # Client imports server public key
        print("\n[CLIENT] Received server public key")
        client_ec = ECDSACrypto()
        client_ec.import_public_key(server_pub_pem)

        # Server signs a challenge
        challenge = "timestamp:2026-04-07:nonce:abc123"
        signature = server_ec.sign(challenge)
        print(f"[SERVER] Signed challenge: {challenge}")

        # Client verifies
        is_valid = client_ec.verify(challenge, signature)
        print(f"[CLIENT] Signature verified: {is_valid}")
        print("[Key Insight] Client can verify server identity without sharing the private key!")

        return is_valid


# Example usage and demonstration
if __name__ == "__main__":
    sim = ECDSASimulation()

    sig_ok = sim.run_signature_demo()
    sim.run_comparison_demo()
    key_ok = sim.run_key_exchange_demo()

    print("\n" + "=" * 70)
    if sig_ok and key_ok:
        print("[✓] All ECDSA demonstrations completed successfully!")
    else:
        print("[✗] Some demonstrations failed!")
    print("=" * 70)
