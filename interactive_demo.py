# interactive_demo.py
"""
Interactive MITM Attack Simulator Demo
Demonstrates complete attack and defense workflow
"""

import time
import subprocess
import os
import sys
from pathlib import Path
from colorama import Fore, Style, init

init(autoreset=True)

sys.path.insert(0, str(Path(__file__).parent))

try:
    from cert_generator import CertificateGenerator
    from crypto_utils import CryptoUtils
    from dh_key_exchange import DHSimulation
    from rsa_crypto import RSASimulation
    from http_https_client import HTTPClient, HTTPSClient
    from http_https_server import start_http_server, start_https_server
except ImportError as e:
    print(f"Import error: {e}")


class InteractiveDemo:
    """Interactive demonstration of MITM attacks and defenses"""

    def __init__(self):
        self.demo_running = True

    def print_banner(self):
        """Print project banner"""
        banner = """
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║          MAN-IN-THE-MIDDLE (MITM) ATTACK SIMULATOR & DEFENSE             ║
║                         Cryptography in Action                            ║
║                                                                            ║
║  This project demonstrates:                                               ║
║  • How MITM attacks compromise unencrypted communication                 ║
║  • How TLS/HTTPS protects against attacks                                 ║
║  • Cryptographic mechanisms (RSA, DH, AES, HMAC)                         ║
║  • Digital certificates and authentication                                 ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)

    def print_menu(self):
        """Print interactive menu"""
        print("\n" + "=" * 70)
        print("SELECT DEMONSTRATION")
        print("=" * 70)
        print("\n[1] Generate Digital Certificates")
        print("[2] Diffie-Hellman Key Exchange")
        print("[3] RSA Encryption & Digital Signatures")
        print("[4] Symmetric Encryption (AES-GCM)")
        print("[5] HTTP Attack Simulation (Vulnerable)")
        print("[6] HTTPS Defense Demonstration (Secure)")
        print("[7] Packet Sniffing Demo")
        print("[8] View Captured Data Log")
        print("[9] Run All Demonstrations")
        print("[0] Exit")
        print("\n" + "=" * 70)

    def demo_certificates(self):
        """Generate digital certificates"""
        print("\n" + Fore.CYAN + "[DEMO 1] DIGITAL CERTIFICATE GENERATION" + Style.RESET_ALL)
        print("-" * 70)

        gen = CertificateGenerator()
        gen.generate_all_certificates()

        print("\n[✓] Certificates generated successfully!")
        print("    These certificates establish trust and enable TLS communication")

    def demo_diffie_hellman(self):
        """Demonstrate Diffie-Hellman key exchange"""
        print("\n" + Fore.CYAN + "[DEMO 2] DIFFIE-HELLMAN KEY EXCHANGE" + Style.RESET_ALL)
        print("-" * 70)

        sim = DHSimulation()
        success = sim.run_simulation(parameter_size=1024)

        if success:
            print("\n" + Fore.GREEN + "[✓] Key exchange successful!" + Style.RESET_ALL)
            print("    Both parties now share identical secret key")
            print("    Attacker cannot derive key despite seeing public values")

    def demo_rsa_crypto(self):
        """Demonstrate RSA encryption and signatures"""
        print("\n" + Fore.CYAN + "[DEMO 3] RSA ENCRYPTION & DIGITAL SIGNATURES" + Style.RESET_ALL)
        print("-" * 70)

        sim = RSASimulation()
        enc_ok = sim.run_encryption_demo()
        sig_ok = sim.run_signature_demo()

        if enc_ok and sig_ok:
            print("\n" + Fore.GREEN + "[✓] RSA demonstrations successful!" + Style.RESET_ALL)
            print("    - Only key holder can decrypt data")
            print("    - Signatures detect tampering")

    def demo_symmetric_crypto(self):
        """Demonstrate AES-GCM encryption"""
        print("\n" + Fore.CYAN + "[DEMO 4] SYMMETRIC ENCRYPTION (AES-GCM)" + Style.RESET_ALL)
        print("-" * 70)

        # Generate key
        key = CryptoUtils.generate_key()
        plaintext = "Secret message transmitted securely"

        print(f"\n[Original] {plaintext}")

        # Encrypt
        encrypted = CryptoUtils.encrypt_aes_gcm(plaintext, key)
        print(f"[Encrypted] {encrypted[:60]}...")

        # Decrypt
        decrypted = CryptoUtils.decrypt_aes_gcm(encrypted, key)
        print(f"[Decrypted] {decrypted}")

        if plaintext == decrypted:
            print(f"\n{Fore.GREEN}[✓] Encryption/Decryption successful!{Style.RESET_ALL}")
            print("    - Data confidentiality ensured with AES-256")
            print("    - Authentication tag prevents tampering (AEAD)")

    def demo_http_attack(self):
        """Demonstrate HTTP vulnerability"""
        print("\n" + Fore.CYAN + "[DEMO 5] HTTP ATTACK SIMULATION" + Style.RESET_ALL)
        print("-" * 70)
        print("\n⚠️  WARNING: This demonstrates vulnerable communication!")
        print("    Data transmitted in PLAINTEXT - visible to attackers\n")

        print("[*] To run this demo:")
        print("    Terminal 1: python src/http_server.py --host 127.0.0.1 --port 8000")
        print("    Terminal 2: sudo python src/network_sniffer.py -p 8000")
        print("    Terminal 3: python src/http_client.py --server 127.0.0.1 --port 8000")
        print("\n[*] Observe:")
        print("    - Credentials captured in plaintext by sniffer")
        print("    - No encryption protects the data")
        print("    - Attacker can modify requests/responses in transit")

    def demo_https_defense(self):
        """Demonstrate HTTPS security"""
        print("\n" + Fore.CYAN + "[DEMO 6] HTTPS DEFENSE DEMONSTRATION" + Style.RESET_ALL)
        print("-" * 70)
        print("\n✓ SECURE HTTPS Communication\n")

        print("[*] To run this demo:")
        print("    Terminal 1: python src/https_server.py --host 127.0.0.1 --port 8443")
        print("    Terminal 2: sudo python src/network_sniffer.py -p 8443")
        print("    Terminal 3: python src/https_client.py --server 127.0.0.1 --port 8443")
        print("\n[*] Observe:")
        print("    - Data encrypted in TLS record layer")
        print("    - Credentials NOT visible to sniffer")
        print("    - Certificate validates server identity")
        print("    - HMAC prevents tampering")
        print("    - Perfect forward secrecy with DHE")

    def demo_packet_sniffing(self):
        """Demonstrate packet sniffing"""
        print("\n" + Fore.CYAN + "[DEMO 7] PACKET SNIFFING DEMONSTRATION" + Style.RESET_ALL)
        print("-" * 70)

        print("\n[*] To run packet sniffer:")
        print("    # On Linux/macOS:")
        print("    sudo python src/network_sniffer.py --interface eth0 --port 8000")
        print("\n    # Find your interface:")
        print("    ifconfig          # macOS/Linux")
        print("    ipconfig          # Windows")
        print("\n[*] What the sniffer captures:")
        print("    - HTTP requests with full headers and body")
        print("    - Credentials in plaintext")
        print("    - Sensitive data transmitted unencrypted")
        print("    - Response data from servers")

    def view_logs(self):
        """View captured data logs"""
        print("\n" + Fore.CYAN + "[DEMO 8] CAPTURED DATA LOG" + Style.RESET_ALL)
        print("-" * 70)

        log_file = Path('logs/captured_credentials_http.log')

        if log_file.exists():
            print(f"\n[File] {log_file.absolute()}\n")
            with open(log_file, 'r') as f:
                content = f.read()
                if content:
                    print(Fore.RED + content + Style.RESET_ALL)
                else:
                    print("[*] Log file is empty")
                    print("    Run HTTP attack demo to capture credentials")
        else:
            print("[*] No logs found")
            print("    Run demonstrations first to generate logs")

    def run_all_demos(self):
        """Run all demonstrations"""
        print("\n" + Fore.YELLOW + "[RUNNING ALL DEMONSTRATIONS]" + Style.RESET_ALL)
        print("=" * 70)

        try:
            self.demo_certificates()
            time.sleep(1)

            self.demo_diffie_hellman()
            time.sleep(1)

            self.demo_rsa_crypto()
            time.sleep(1)

            self.demo_symmetric_crypto()
            time.sleep(1)

            print("\n" + "=" * 70)
            print(Fore.GREEN + "[✓] ALL CRYPTOGRAPHIC DEMONSTRATIONS COMPLETED!" + Style.RESET_ALL)
            print("=" * 70)

            print("\n[Next Steps]")
            print("1. Run HTTP server (see demo 5)")
            print("2. Monitor with packet sniffer (see demo 7)")
            print("3. Run HTTP client to see credentials captured")
            print("4. Compare with HTTPS (demo 6) - no data visible!")

        except Exception as e:
            print(f"\n{Fore.RED}[✗] Error: {e}{Style.RESET_ALL}")

    def run_interactive(self):
        """Run interactive menu"""
        self.print_banner()

        while self.demo_running:
            self.print_menu()

            try:
                choice = input(f"\n{Fore.CYAN}Select option [0-9]: {Style.RESET_ALL}")

                if choice == '1':
                    self.demo_certificates()
                elif choice == '2':
                    self.demo_diffie_hellman()
                elif choice == '3':
                    self.demo_rsa_crypto()
                elif choice == '4':
                    self.demo_symmetric_crypto()
                elif choice == '5':
                    self.demo_http_attack()
                elif choice == '6':
                    self.demo_https_defense()
                elif choice == '7':
                    self.demo_packet_sniffing()
                elif choice == '8':
                    self.view_logs()
                elif choice == '9':
                    self.run_all_demos()
                elif choice == '0':
                    print(f"\n{Fore.YELLOW}[*] Exiting...{Style.RESET_ALL}")
                    self.demo_running = False
                else:
                    print(f"{Fore.RED}[✗] Invalid option{Style.RESET_ALL}")

                if choice != '0':
                    input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[*] Interrupted{Style.RESET_ALL}")
                self.demo_running = False
            except Exception as e:
                print(f"\n{Fore.RED}[✗] Error: {e}{Style.RESET_ALL}")


def main():
    """Main execution"""
    demo = InteractiveDemo()
    demo.run_interactive()


if __name__ == "__main__":
    main()
