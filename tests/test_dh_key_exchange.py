# tests/test_dh_key_exchange.py
"""Unit tests for dh_key_exchange.py — Diffie-Hellman key exchange"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from dh_key_exchange import DiffieHellmanKeyExchange, DHSimulation

# Cache DH parameters so they aren't generated 10 times, saving 3+ minutes
_SHARED_PARAMS = DiffieHellmanKeyExchange().generate_parameters()

class TestDHKeyExchange:
    def setup_method(self):
        """Use shared DH parameters for speed"""
        self.alice = DiffieHellmanKeyExchange()
        self.bob = DiffieHellmanKeyExchange()

    def test_generate_parameters_creates_params(self):
        # Already done globally, just asserting it's true
        assert _SHARED_PARAMS is not None

    def test_generate_keypair_creates_keys(self):
        self.alice.generate_keypair(_SHARED_PARAMS)
        assert self.alice.private_key is not None
        assert self.alice.public_key is not None

    def test_shared_secrets_match(self):
        """Core DH property: both parties must derive the SAME shared secret"""
        self.alice.generate_keypair(_SHARED_PARAMS)
        self.bob.generate_keypair(_SHARED_PARAMS)

        alice_secret = self.alice.compute_shared_secret(self.bob.public_key)
        bob_secret   = self.bob.compute_shared_secret(self.alice.public_key)

        assert alice_secret == bob_secret

    def test_shared_secret_is_bytes(self):
        self.alice.generate_keypair(_SHARED_PARAMS)
        self.bob.generate_keypair(_SHARED_PARAMS)
        secret = self.alice.compute_shared_secret(self.bob.public_key)
        assert isinstance(secret, bytes)

    def test_session_keys_match(self):
        """Derived session keys must also match for both parties"""
        self.alice.generate_keypair(_SHARED_PARAMS)
        self.bob.generate_keypair(_SHARED_PARAMS)

        alice_secret = self.alice.compute_shared_secret(self.bob.public_key)
        bob_secret   = self.bob.compute_shared_secret(self.alice.public_key)

        alice_key = self.alice.derive_session_key(alice_secret)
        bob_key   = self.bob.derive_session_key(bob_secret)

        assert alice_key == bob_key

    def test_session_key_is_32_bytes(self):
        """Session key must be 32 bytes for AES-256"""
        self.alice.generate_keypair(_SHARED_PARAMS)
        self.bob.generate_keypair(_SHARED_PARAMS)
        secret = self.alice.compute_shared_secret(self.bob.public_key)
        session_key = self.alice.derive_session_key(secret)
        assert len(session_key) == 32

    def test_public_key_bytes_is_pem(self):
        self.alice.generate_keypair(_SHARED_PARAMS)
        pub_bytes = self.alice.get_public_key_bytes()
        assert pub_bytes.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_different_keypairs_give_different_secrets(self):
        """Fresh key pairs should produce different secrets"""
        self.alice.generate_keypair(_SHARED_PARAMS)
        
        b1 = DiffieHellmanKeyExchange()
        b1.generate_keypair(_SHARED_PARAMS)
        
        b2 = DiffieHellmanKeyExchange()
        b2.generate_keypair(_SHARED_PARAMS)

        secret1 = self.alice.compute_shared_secret(b1.public_key)
        secret2 = self.alice.compute_shared_secret(b2.public_key)
        assert secret1 != secret2


class TestDHSimulation:
    def test_simulation_runs_without_error(self):
        """Full DH simulation should complete and return True"""
        sim = DHSimulation()
        result = sim.run_simulation()
        assert result is True
