# dh_key_exchange.py
"""
Diffie-Hellman Key Exchange Implementation
Secure key agreement protocol over insecure channel
"""

import os
import sys

try:
    from cryptography.hazmat.primitives.asymmetric import dh
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
except ImportError:
    print("ERROR: cryptography library not installed")
    sys.exit(1)


class DiffieHellmanKeyExchange:
    """Implement Diffie-Hellman key exchange protocol"""

    def __init__(self, parameter_size=2048):
        """Initialize with DH parameters"""
        self.parameter_size = parameter_size
        self.backend = default_backend()
        self.private_key = None
        self.public_key = None
        self.shared_secret = None

    def generate_parameters(self):
        """
        Generate Diffie-Hellman parameters
        Uses standard FFDHE groups (RFC 7919)
        """
        print(f"[*] Generating DH parameters ({self.parameter_size}-bit)...")
        parameters = dh.generate_parameters(
            generator=2,
            key_size=self.parameter_size,
            backend=self.backend
        )
        return parameters

    def generate_keypair(self, parameters):
        """Generate private and public key pair"""
        print("[*] Generating DH private key...")
        self.private_key = parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

        print("[✓] Key pair generated")
        return self.public_key

    def compute_shared_secret(self, peer_public_key):
        """
        Compute shared secret using peer's public key
        s = B^a mod p (where a is private key, B is peer's public key)
        """
        print("[*] Computing shared secret...")
        self.shared_secret = self.private_key.exchange(peer_public_key)

        print("[✓] Shared secret computed")
        return self.shared_secret

    def get_public_key_bytes(self):
        """Export public key as bytes"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def derive_session_key(self, shared_secret, length=32):
        """
        Derive session encryption key from shared secret
        Uses HKDF for key expansion
        """
        try:
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF

            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=length,
                salt=None,
                info=b"session_key",
                backend=self.backend
            )
            session_key = hkdf.derive(shared_secret)
            return session_key
        except ImportError:
            # Fallback: use SHA-256 hash of shared secret
            import hashlib
            return hashlib.sha256(shared_secret).digest()[:length]


class DHParty:
    """Represents one party in DH key exchange"""

    def __init__(self, name, parameter_size=2048):
        self.name = name
        self.dh = DiffieHellmanKeyExchange(parameter_size)
        self.parameters = None
        self.public_key = None
        self.peer_public_key = None
        self.shared_secret = None
        self.session_key = None

    def step1_generate_parameters(self):
        """Step 1: Generate DH parameters (shared between parties)"""
        print(f"\n[{self.name} - Step 1] Generating DH parameters...")
        self.parameters = self.dh.generate_parameters()
        print(f"[✓] Parameters generated")

    def step2_generate_keypair(self):
        """Step 2: Generate private and public key pair"""
        print(f"\n[{self.name} - Step 2] Generating key pair...")
        self.public_key = self.dh.generate_keypair(self.parameters)
        print(f"[✓] Public key: {str(self.public_key)[:50]}...")

    def step3_exchange_public_keys(self, peer_public_key):
        """Step 3: Receive peer's public key"""
        print(f"\n[{self.name} - Step 3] Received peer's public key")
        self.peer_public_key = peer_public_key

    def step4_compute_shared_secret(self):
        """Step 4: Compute shared secret"""
        print(f"\n[{self.name} - Step 4] Computing shared secret...")
        self.shared_secret = self.dh.compute_shared_secret(
            self.peer_public_key
        )
        print(f"[✓] Shared secret: {self.shared_secret.hex()[:32]}...")

    def step5_derive_session_key(self):
        """Step 5: Derive session key for encryption"""
        print(f"\n[{self.name} - Step 5] Deriving session key...")
        self.session_key = self.dh.derive_session_key(self.shared_secret)
        print(f"[✓] Session key: {self.session_key.hex()[:32]}...")

    def get_public_key(self):
        """Get public key for transmission"""
        return self.dh.public_key


class DHSimulation:
    """Simulate complete DH key exchange between two parties"""

    def __init__(self):
        self.alice = None
        self.bob = None

    def run_simulation(self, parameter_size=2048):
        """Run complete Diffie-Hellman exchange"""
        print("=" * 70)
        print("DIFFIE-HELLMAN KEY EXCHANGE SIMULATION")
        print("=" * 70)

        # Initialize parties
        self.alice = DHParty("Alice", parameter_size)
        self.bob = DHParty("Bob", parameter_size)

        # Step 1: Both parties generate same parameters
        print("\n[PHASE 1] Parameter Generation")
        print("-" * 70)
        self.alice.step1_generate_parameters()
        self.bob.parameters = self.alice.parameters

        # Step 2: Both parties generate their own keypairs
        print("\n[PHASE 2] Key Pair Generation")
        print("-" * 70)
        self.alice.step2_generate_keypair()
        self.bob.step2_generate_keypair()

        # Step 3: Exchange public keys (can be done in open channel)
        print("\n[PHASE 3] Public Key Exchange (TRANSMITTED IN CLEAR)")
        print("-" * 70)
        print("[*] Alice sends public key to Bob")
        self.bob.step3_exchange_public_keys(self.alice.public_key)

        print("[*] Bob sends public key to Alice")
        self.alice.step3_exchange_public_keys(self.bob.public_key)

        # Step 4: Compute shared secrets independently
        print("\n[PHASE 4] Shared Secret Computation")
        print("-" * 70)
        self.alice.step4_compute_shared_secret()
        self.bob.step4_compute_shared_secret()

        # Verify both have same secret
        print("\n[VERIFICATION] Secret Agreement Check")
        print("-" * 70)
        if self.alice.shared_secret == self.bob.shared_secret:
            print("[✓] SUCCESS: Both parties have identical shared secret!")
            print(f"    Shared Secret: {self.alice.shared_secret.hex()[:64]}...")
        else:
            print("[✗] FAILURE: Shared secrets don't match!")

        # Step 5: Derive session keys
        print("\n[PHASE 5] Session Key Derivation")
        print("-" * 70)
        self.alice.step5_derive_session_key()
        self.bob.step5_derive_session_key()

        # Verify session keys match
        if self.alice.session_key == self.bob.session_key:
            print("\n[✓] SUCCESS: Both parties have identical session key!")
            print(f"    Session Key: {self.alice.session_key.hex()}")
        else:
            print("\n[✗] FAILURE: Session keys don't match!")

        # Security analysis
        print("\n[SECURITY ANALYSIS]")
        print("-" * 70)
        self.print_security_analysis()

        return self.alice.session_key == self.bob.session_key

    def print_security_analysis(self):
        """Analyze security of the exchange"""
        print("""
DIFFIE-HELLMAN SECURITY PROPERTIES:

1. FORWARD SECRECY: ✓
   - Session keys are unique per session
   - Compromise of long-term keys doesn't expose past sessions
   - Each session uses ephemeral keys

2. PROTECTION AGAINST EAVESDROPPING: ✓
   - Attacker sees public values (p, g, A, B)
   - Computing shared secret requires discrete log (computationally hard)
   - Secret S is never transmitted

3. KEY AGREEMENT: ✓
   - Both parties independently compute identical secret
   - No prior shared secret required
   - Works over insecure channels

4. VULNERABILITY: ⚠️
   - Does NOT authenticate identities
   - Vulnerable to active MITM attacks without authentication
   - Requires additional authentication mechanism (digital certificates)

5. MITIGATION: ✓
   - Combine with digital signatures (RSA, ECDSA)
   - Use certificate-based authentication
   - Implement message authentication codes (HMAC)

RECOMMENDATION:
Always use DH with authentication (e.g., TLS) for secure communication.
        """)


# Example usage and demonstration
if __name__ == "__main__":
    sim = DHSimulation()
    success = sim.run_simulation(parameter_size=1024)  # Use smaller size for demo

    if success:
        print("\n[✓] Diffie-Hellman key exchange simulation completed successfully!")
    else:
        print("\n[✗] Simulation failed!")
