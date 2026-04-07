# http_client.py and https_client.py
"""
HTTP and HTTPS Clients
Demonstrates vulnerable and secure communication
"""

import requests
import json
import ssl
import sys
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from crypto_utils import CryptoUtils
except ImportError:
    print("Warning: Could not import crypto_utils")

# Suppress SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class HTTPClient:
    """Vulnerable HTTP Client (plaintext transmission)"""

    def __init__(self, server_url='http://127.0.0.1:8000'):
        self.server_url = server_url
        self.session = requests.Session()

    def login(self, username, password):
        """Send login credentials in plaintext"""
        print("\n[HTTP CLIENT] Sending login request...")
        print(f"[⚠️  WARNING] Data will be sent in PLAINTEXT!")

        payload = {
            'username': username,
            'password': password
        }

        try:
            response = self.session.post(
                f'{self.server_url}/login',
                json=payload,
                timeout=5
            )

            print(f"[✓] Request sent to {self.server_url}/login")
            print(f"[⚠️  Credentials visible to network sniffer!]")
            print(f"[Response] Status: {response.status_code}")

            return response.json()

        except Exception as e:
            print(f"[✗] Error: {e}")
            return None

    def send_data(self, data):
        """Send data in plaintext"""
        print("\n[HTTP CLIENT] Sending data...")

        payload = {'data': data}

        try:
            response = self.session.post(
                f'{self.server_url}/data',
                json=payload,
                timeout=5
            )

            print(f"[✓] Data sent (unencrypted)")
            print(f"[Response] Status: {response.status_code}")

            return response.json()

        except Exception as e:
            print(f"[✗] Error: {e}")
            return None

    def get_message(self):
        """Retrieve sensitive message in plaintext"""
        print("\n[HTTP CLIENT] Retrieving message...")

        try:
            response = self.session.get(
                f'{self.server_url}/message',
                timeout=5
            )

            print(f"[Response] Status: {response.status_code}")
            print(f"[⚠️  Message visible to network sniffer!]")

            return response.json()

        except Exception as e:
            print(f"[✗] Error: {e}")
            return None


class HTTPSClient:
    """Secure HTTPS Client (encrypted transmission)"""

    def __init__(self, server_url='https://127.0.0.1:8443',
                 ca_cert='certs/ca_cert.pem'):
        self.server_url = server_url
        self.ca_cert = ca_cert
        self.session = requests.Session()
        self.session_key = CryptoUtils.generate_key()

        # Configure SSL context
        if Path(ca_cert).exists():
            self.session.verify = ca_cert
        else:
            self.session.verify = False  # For self-signed certificates

    def login(self, username, password):
        """Send login credentials encrypted over HTTPS"""
        print("\n[HTTPS CLIENT] Sending login request...")
        print(f"[✓] TLS encryption enabled")

        # Encrypt payload
        plaintext = json.dumps({
            'username': username,
            'password': password
        })
        encrypted_payload = CryptoUtils.encrypt_aes_gcm(plaintext, self.session_key)

        payload = {
            'encrypted_payload': encrypted_payload
        }

        try:
            response = self.session.post(
                f'{self.server_url}/login',
                json=payload,
                timeout=5
            )

            print(f"[✓] Request sent to {self.server_url}/login")
            print(f"[✓] Credentials encrypted in transit!")
            print(f"[Response] Status: {response.status_code}")

            return response.json()

        except Exception as e:
            print(f"[✗] Error: {e}")
            return None

    def send_data(self, data):
        """Send data encrypted over HTTPS"""
        print("\n[HTTPS CLIENT] Sending data...")
        print(f"[✓] TLS encryption enabled")

        # Encrypt payload
        plaintext = json.dumps({'data': data})
        encrypted_payload = CryptoUtils.encrypt_aes_gcm(plaintext, self.session_key)

        payload = {
            'encrypted_payload': encrypted_payload
        }

        try:
            response = self.session.post(
                f'{self.server_url}/data',
                json=payload,
                timeout=5
            )

            print(f"[✓] Data sent (encrypted)")
            print(f"[Response] Status: {response.status_code}")

            return response.json()

        except Exception as e:
            print(f"[✗] Error: {e}")
            return None

    def get_message(self):
        """Retrieve sensitive message encrypted over HTTPS"""
        print("\n[HTTPS CLIENT] Retrieving message...")
        print(f"[✓] TLS encryption enabled")

        try:
            response = self.session.get(
                f'{self.server_url}/message',
                timeout=5
            )

            print(f"[Response] Status: {response.status_code}")
            print(f"[✓] Message encrypted in transit!")

            return response.json()

        except Exception as e:
            print(f"[✗] Error: {e}")
            return None


def run_http_client_demo():
    """Demonstrate vulnerable HTTP communication"""
    print("=" * 70)
    print("HTTP CLIENT DEMONSTRATION (VULNERABLE)")
    print("=" * 70)

    client = HTTPClient('http://127.0.0.1:8000')

    # Login with credentials
    login_response = client.login('alice', 'SecurePassword123!')
    if login_response:
        print(f"[Server Response] {login_response}")

    # Send sensitive data
    data_response = client.send_data('Confidential financial report')
    if data_response:
        print(f"[Server Response] {data_response}")

    # Get message
    message_response = client.get_message()
    if message_response:
        print(f"[Server Response] {message_response}")


def run_https_client_demo():
    """Demonstrate secure HTTPS communication"""
    print("\n" + "=" * 70)
    print("HTTPS CLIENT DEMONSTRATION (SECURE)")
    print("=" * 70)

    client = HTTPSClient('https://127.0.0.1:8443')

    # Login with credentials
    login_response = client.login('bob', 'SecurePassword456!')
    if login_response:
        print(f"[Server Response] {login_response}")

    # Send sensitive data
    data_response = client.send_data('Encrypted financial report')
    if data_response:
        print(f"[Server Response] {data_response}")

    # Get message
    message_response = client.get_message()
    if message_response:
        print(f"[Server Response] {message_response}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='HTTP/HTTPS Client')
    parser.add_argument('--type', choices=['http', 'https'], default='http',
                       help='Client type')
    parser.add_argument('--server', default='127.0.0.1',
                       help='Server address')
    parser.add_argument('--port', type=int, help='Server port')

    args = parser.parse_args()

    if args.type == 'http':
        port = args.port or 8000
        client = HTTPClient(f'http://{args.server}:{port}')
        run_http_client_demo()
    else:
        port = args.port or 8443
        client = HTTPSClient(f'https://{args.server}:{port}')
        run_https_client_demo()
