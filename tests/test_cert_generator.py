# tests/test_cert_generator.py
"""Unit tests for cert_generator.py — X.509 certificate generation"""

import pytest
import tempfile
import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))
from cert_generator import CertificateGenerator

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
except ImportError:
    pytest.skip("cryptography not installed", allow_module_level=True)


@pytest.fixture(scope="module")
def tmp_cert_gen():
    """Shared CertificateGenerator using a temp directory"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield CertificateGenerator(cert_dir=tmpdir)


class TestCAGeneration:
    def test_create_ca_returns_cert_and_key(self, tmp_cert_gen):
        ca_cert, ca_key = tmp_cert_gen.create_ca_certificate()
        assert ca_cert is not None
        assert ca_key is not None

    def test_ca_is_x509_certificate(self, tmp_cert_gen):
        ca_cert, _ = tmp_cert_gen.create_ca_certificate()
        assert isinstance(ca_cert, x509.Certificate)

    def test_ca_is_ca(self, tmp_cert_gen):
        """CA certificate must have BasicConstraints is_ca=True"""
        ca_cert, _ = tmp_cert_gen.create_ca_certificate()
        bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True

    def test_ca_key_is_rsa(self, tmp_cert_gen):
        _, ca_key = tmp_cert_gen.create_ca_certificate()
        assert isinstance(ca_key, rsa.RSAPrivateKey)

    def test_ca_key_size_is_2048(self, tmp_cert_gen):
        _, ca_key = tmp_cert_gen.create_ca_certificate()
        assert ca_key.key_size == 2048

    def test_ca_not_expired(self, tmp_cert_gen):
        ca_cert, _ = tmp_cert_gen.create_ca_certificate()
        now = datetime.now(timezone.utc)
        assert ca_cert.not_valid_after_utc > now


class TestServerCertGeneration:
    def test_create_server_cert_returns_cert_and_key(self, tmp_cert_gen):
        ca_cert, ca_key = tmp_cert_gen.create_ca_certificate()
        server_cert, server_key = tmp_cert_gen.create_server_certificate(
            ca_cert, ca_key, hostname="localhost"
        )
        assert server_cert is not None
        assert server_key is not None

    def test_server_cert_is_x509(self, tmp_cert_gen):
        ca_cert, ca_key = tmp_cert_gen.create_ca_certificate()
        server_cert, _ = tmp_cert_gen.create_server_certificate(
            ca_cert, ca_key, hostname="localhost"
        )
        assert isinstance(server_cert, x509.Certificate)

    def test_server_cert_is_not_ca(self, tmp_cert_gen):
        ca_cert, ca_key = tmp_cert_gen.create_ca_certificate()
        server_cert, _ = tmp_cert_gen.create_server_certificate(
            ca_cert, ca_key, hostname="localhost"
        )
        bc = server_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_server_cert_not_expired(self, tmp_cert_gen):
        ca_cert, ca_key = tmp_cert_gen.create_ca_certificate()
        server_cert, _ = tmp_cert_gen.create_server_certificate(
            ca_cert, ca_key, hostname="localhost"
        )
        assert server_cert.not_valid_after_utc > datetime.now(timezone.utc)


class TestClientCertGeneration:
    def test_create_client_cert_returns_cert_and_key(self, tmp_cert_gen):
        ca_cert, ca_key = tmp_cert_gen.create_ca_certificate()
        client_cert, client_key = tmp_cert_gen.create_client_certificate(
            ca_cert, ca_key
        )
        assert client_cert is not None
        assert client_key is not None


class TestGenerateAllCertificates:
    def test_generate_all_creates_files(self):
        """generate_all_certificates should write PEM files to disk"""
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = CertificateGenerator(cert_dir=tmpdir)
            gen.generate_all_certificates()

            expected_files = [
                "ca_cert.pem", "ca_key.pem",
                "server_cert.pem", "server_key.pem",
                "client_cert.pem", "client_key.pem",
            ]
            for fname in expected_files:
                fpath = Path(tmpdir) / fname
                assert fpath.exists(), f"Missing: {fname}"
                assert fpath.stat().st_size > 0, f"Empty: {fname}"
