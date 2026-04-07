# cert_generator.py
"""
Certificate Generation Utility
Generates self-signed certificates for MITM attack simulation
"""

import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    print("ERROR: cryptography library not installed")
    print("Install: pip install cryptography")
    sys.exit(1)


class CertificateGenerator:
    """Generate self-signed certificates for testing"""

    def __init__(self, cert_dir="certs"):
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(exist_ok=True)
        self.backend = default_backend()

    def generate_private_key(self, key_size=2048):
        """Generate RSA private key"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )

    def create_ca_certificate(self):
        """Create Certificate Authority certificate"""
        print("[*] Generating CA private key (RSA-2048)...")
        ca_key = self.generate_private_key()

        print("[*] Creating CA certificate...")
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tamil Nadu"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Chennai"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MITM Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"MITM-CA"),
        ])

        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256(), self.backend)
        )

        # Save CA certificate
        ca_cert_path = self.cert_dir / "ca_cert.pem"
        with open(ca_cert_path, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        print(f"[✓] CA certificate saved: {ca_cert_path}")

        # Save CA private key
        ca_key_path = self.cert_dir / "ca_key.pem"
        with open(ca_key_path, "wb") as f:
            f.write(ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print(f"[✓] CA private key saved: {ca_key_path}")

        return ca_cert, ca_key

    def create_server_certificate(self, ca_cert, ca_key, hostname="localhost"):
        """Create server certificate signed by CA"""
        print(f"\n[*] Generating server private key (RSA-2048)...")
        server_key = self.generate_private_key()

        print(f"[*] Creating server certificate for {hostname}...")
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tamil Nadu"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Chennai"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MITM Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])

        server_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.issuer)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(hostname),
                    x509.DNSName(f"*.{hostname}"),
                ]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256(), self.backend)
        )

        # Save server certificate
        server_cert_path = self.cert_dir / "server_cert.pem"
        with open(server_cert_path, "wb") as f:
            f.write(server_cert.public_bytes(serialization.Encoding.PEM))
        print(f"[✓] Server certificate saved: {server_cert_path}")

        # Save server private key
        server_key_path = self.cert_dir / "server_key.pem"
        with open(server_key_path, "wb") as f:
            f.write(server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print(f"[✓] Server private key saved: {server_key_path}")

        return server_cert, server_key

    def create_client_certificate(self, ca_cert, ca_key, client_name="client"):
        """Create client certificate signed by CA"""
        print(f"\n[*] Generating client private key (RSA-2048)...")
        client_key = self.generate_private_key()

        print(f"[*] Creating client certificate for {client_name}...")
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tamil Nadu"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Chennai"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MITM Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, client_name),
        ])

        client_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.issuer)
            .public_key(client_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256(), self.backend)
        )

        # Save client certificate
        client_cert_path = self.cert_dir / "client_cert.pem"
        with open(client_cert_path, "wb") as f:
            f.write(client_cert.public_bytes(serialization.Encoding.PEM))
        print(f"[✓] Client certificate saved: {client_cert_path}")

        # Save client private key
        client_key_path = self.cert_dir / "client_key.pem"
        with open(client_key_path, "wb") as f:
            f.write(client_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print(f"[✓] Client private key saved: {client_key_path}")

        return client_cert, client_key

    def generate_all_certificates(self):
        """Generate complete certificate chain"""
        print("=" * 60)
        print("CERTIFICATE GENERATION FOR MITM SIMULATOR")
        print("=" * 60)

        # Create CA
        ca_cert, ca_key = self.create_ca_certificate()

        # Create Server Certificate
        server_cert, server_key = self.create_server_certificate(
            ca_cert, ca_key, hostname="localhost"
        )

        # Create Client Certificate
        client_cert, client_key = self.create_client_certificate(
            ca_cert, ca_key, client_name="client"
        )

        print("\n" + "=" * 60)
        print("[✓] All certificates generated successfully!")
        print("=" * 60)
        print(f"\nCertificates location: {self.cert_dir.absolute()}")
        print("\nGenerated files:")
        print("  - ca_cert.pem (Certificate Authority)")
        print("  - ca_key.pem (CA Private Key)")
        print("  - server_cert.pem (Server Certificate)")
        print("  - server_key.pem (Server Private Key)")
        print("  - client_cert.pem (Client Certificate)")
        print("  - client_key.pem (Client Private Key)")


def main():
    """Main execution"""
    gen = CertificateGenerator()
    gen.generate_all_certificates()


if __name__ == "__main__":
    main()
