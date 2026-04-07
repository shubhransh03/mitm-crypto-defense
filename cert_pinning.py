# cert_pinning.py
"""
Certificate Pinning Demonstration
Shows how to prevent MITM attacks even when an attacker controls a rogue CA.

WHY PINNING MATTERS:
  Standard TLS trusts ANY certificate signed by ANY trusted CA (100+ CAs in browser store).
  An attacker who compromises a CA can issue a valid cert for any domain.

  Certificate Pinning: the client remembers (pins) the server's specific certificate
  or public key fingerprint. Even a CA-signed rogue cert is REJECTED if it doesn't match.

TWO APPROACHES:
  1. Certificate Pinning  — pin the full cert SHA-256 fingerprint
     ✗ Must update pin when certificate is renewed (e.g., every 90 days with Let's Encrypt)

  2. Public Key Pinning   — pin the public key fingerprint (SPKI hash)
     ✓ Better: the public key survives certificate renewal, only changes on key rotation
"""

import hashlib
import tempfile
import sys
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("ERROR: cryptography library not installed")
    sys.exit(1)


class CertificatePinning:
    """Implement and demonstrate certificate pinning"""

    def __init__(self):
        self._pinned_cert_fps: set = set()       # SHA-256 of full DER cert
        self._pinned_key_fps: set = set()        # SHA-256 of DER-encoded public key (SPKI)

    # ── Fingerprint Helpers ───────────────────────────────────────────────────

    def get_cert_fingerprint(self, cert_pem: bytes) -> str:
        """SHA-256 fingerprint of the full DER-encoded certificate"""
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        der = cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(der).hexdigest()

    def get_public_key_fingerprint(self, cert_pem: bytes) -> str:
        """SHA-256 fingerprint of the SubjectPublicKeyInfo (SPKI) DER bytes.
        This is the same value browsers use for HTTP Public Key Pinning (HPKP)."""
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        spki = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(spki).hexdigest()

    # ── Pinning ───────────────────────────────────────────────────────────────

    def pin_certificate(self, cert_pem: bytes) -> str:
        """Store the certificate fingerprint. Must be done on first trusted connection."""
        fp = self.get_cert_fingerprint(cert_pem)
        self._pinned_cert_fps.add(fp)
        print(f"[✓] Certificate pinned:  {fp[:48]}...")
        return fp

    def pin_public_key(self, cert_pem: bytes) -> str:
        """Store the public key fingerprint (preferred: survives cert renewal)."""
        fp = self.get_public_key_fingerprint(cert_pem)
        self._pinned_key_fps.add(fp)
        print(f"[✓] Public key pinned:   {fp[:48]}...")
        return fp

    # ── Validation ────────────────────────────────────────────────────────────

    def validate(self, cert_pem: bytes) -> tuple[bool, str]:
        """
        Check incoming certificate against all pins.
        Returns (is_trusted, reason)
        """
        cert_fp = self.get_cert_fingerprint(cert_pem)
        key_fp = self.get_public_key_fingerprint(cert_pem)

        if cert_fp in self._pinned_cert_fps:
            return True, "Matched certificate pin"
        if key_fp in self._pinned_key_fps:
            return True, "Matched public key pin"
        return False, "No matching pin — connection BLOCKED"

    # ── Full Demo ─────────────────────────────────────────────────────────────

    def run_demo(self, cert_path: str = 'certs/server_cert.pem'):
        """Full demonstration of certificate pinning vs rogue CA attack"""
        print("=" * 70)
        print("CERTIFICATE PINNING DEMONSTRATION")
        print("=" * 70)

        cert_file = Path(cert_path)
        if not cert_file.exists():
            print(f"\n[!] Certificate not found: {cert_path}")
            print("    Run cert_generator.py first to generate certificates.")
            return False

        cert_pem = cert_file.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        print(f"\n[INFO] Server certificate subject: {cert.subject}")
        print(f"[INFO]   Valid until: {cert.not_valid_after_utc}")

        # Step 1: First connection (Trust On First Use — TOFU)
        print("\n[STEP 1] First connection — pin the server's certificate & public key")
        self.pin_certificate(cert_pem)
        self.pin_public_key(cert_pem)

        # Step 2: Second connection with the SAME cert → trusted
        print("\n[STEP 2] Second connection with same certificate")
        trusted, reason = self.validate(cert_pem)
        status = "[✓] TRUSTED" if trusted else "[✗] BLOCKED"
        print(f"  Result: {status} — {reason}")

        # Step 3: Attacker uses a DIFFERENT (rogue) certificate
        print("\n[STEP 3] Attacker presents a ROGUE certificate (different CA)")
        sys.path.insert(0, str(Path(__file__).parent))
        from cert_generator import CertificateGenerator

        tmp_dir = tempfile.mkdtemp()
        rogue_gen = CertificateGenerator(cert_dir=tmp_dir)
        rogue_ca_cert, rogue_ca_key = rogue_gen.create_ca_certificate()
        rogue_cert, _ = rogue_gen.create_server_certificate(
            rogue_ca_cert, rogue_ca_key, hostname="localhost"
        )
        rogue_pem = rogue_cert.public_bytes(serialization.Encoding.PEM)

        rogue_trusted, rogue_reason = self.validate(rogue_pem)
        rogue_status = "[✓] TRUSTED" if rogue_trusted else "[✗] BLOCKED"
        print(f"  Result: {rogue_status} — {rogue_reason}")

        # Summary
        print("\n" + "=" * 70)
        print("SECURITY ANALYSIS")
        print("=" * 70)
        if trusted and not rogue_trusted:
            print("\n[✓] Pinning works correctly!")
            print("  Legitimate cert:  TRUSTED  ✓")
            print("  Rogue CA cert:    BLOCKED  ✓")
            print("\n[Key Insight]")
            print("  Without pinning: A compromised CA can issue valid certs for any domain.")
            print("  With pinning:    Only YOUR specific key is trusted — rogue CA is useless.")
            print("\n[Best Practice]")
            print("  Pin the PUBLIC KEY (not the full cert) so pins survive certificate renewal.")
            print("  Used by: Google Chrome, Apple App Store, banking apps worldwide.")

        return trusted and not rogue_trusted


# Example usage
if __name__ == "__main__":
    pinner = CertificatePinning()
    success = pinner.run_demo()
    print()
    if success:
        print("[✓] Certificate pinning demonstration completed successfully!")
    else:
        print("[!] Run cert_generator.py first, then retry.")
