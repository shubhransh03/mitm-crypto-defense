# http_server.py and https_server.py
"""
Vulnerable HTTP Server and Secure HTTPS Server
Demonstrates attack and defense mechanisms
"""

import ssl
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

try:
    from crypto_utils import CryptoUtils, SymmetricCrypto
except ImportError:
    print("Warning: Could not import crypto_utils")


class HTTPRequestHandler(BaseHTTPRequestHandler):
    """Handle HTTP requests (VULNERABLE - plaintext)"""

    def do_POST(self):
        """Handle POST requests"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        if self.path == '/login':
            # Receive credentials in plaintext
            try:
                data = json.loads(body.decode('utf-8'))
                username = data.get('username', '')
                password = data.get('password', '')

                # Log credentials (simulating attacker capture)
                with open('logs/captured_credentials_http.log', 'a') as f:
                    f.write(f"[CAPTURED] Username: {username}, Password: {password}\n")

                # Send response
                response = {
                    'status': 'success',
                    'message': 'Login successful',
                    'session_id': 'http_session_123'
                }
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))

                print(f"\n[HTTP SERVER] Received credentials:")
                print(f"  Username: {username}")
                print(f"  Password: {password}")
                print(f"  [⚠️  WARNING: Data transmitted in PLAINTEXT!]")

            except Exception as e:
                self.send_error(400, str(e))

        elif self.path == '/data':
            # Receive user data in plaintext
            try:
                data = json.loads(body.decode('utf-8'))
                user_data = data.get('data', '')

                response = {
                    'status': 'received',
                    'data_length': len(user_data)
                }
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))

                print(f"[HTTP SERVER] Received data: {user_data[:50]}...")

            except Exception as e:
                self.send_error(400, str(e))

    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/message':
            # Send sensitive message in plaintext
            message = {
                'message': 'Sensitive Information: Account Balance = $5000',
                'timestamp': '2024-01-11 10:00:00'
            }
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(message).encode('utf-8'))

        else:
            self.send_error(404)

    def log_message(self, format, *args):
        """Suppress default logging"""
        pass


class HTTPSRequestHandler(BaseHTTPRequestHandler):
    """Handle HTTPS requests (SECURE - encrypted)"""

    def do_POST(self):
        """Handle POST requests"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        if self.path == '/login':
            # Receive encrypted credentials
            try:
                encrypted_data = json.loads(body.decode('utf-8'))
                encrypted_payload = encrypted_data.get('encrypted_payload', '')

                # Decrypt using server's session key
                if hasattr(self.server, 'session_key'):
                    decrypted = CryptoUtils.decrypt_aes_gcm(
                        encrypted_payload,
                        self.server.session_key
                    )
                    data = json.loads(decrypted)
                    username = data.get('username', '')
                    password = data.get('password', '')

                    print(f"\n[HTTPS SERVER] Received encrypted credentials (DECRYPTED):")
                    print(f"  Username: {username}")
                    print(f"  Password: {password}")
                    print(f"  [✓ Data encrypted in transit!]")

                    response = {
                        'status': 'success',
                        'message': 'Login successful over HTTPS',
                        'session_id': 'https_session_456'
                    }
                else:
                    response = {'status': 'error', 'message': 'No session key'}

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))

            except Exception as e:
                self.send_error(400, str(e))

        elif self.path == '/data':
            try:
                encrypted_data = json.loads(body.decode('utf-8'))
                encrypted_payload = encrypted_data.get('encrypted_payload', '')

                if hasattr(self.server, 'session_key'):
                    decrypted = CryptoUtils.decrypt_aes_gcm(
                        encrypted_payload,
                        self.server.session_key
                    )
                    data = json.loads(decrypted)
                    user_data = data.get('data', '')

                    response = {
                        'status': 'received',
                        'data_length': len(user_data)
                    }

                    print(f"[HTTPS SERVER] Received encrypted data: {user_data[:30]}...")

                else:
                    response = {'status': 'error', 'message': 'No session key'}

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))

            except Exception as e:
                self.send_error(400, str(e))

    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/message':
            # Send sensitive message (encrypted by TLS)
            message = {
                'message': 'Sensitive Information: Account Balance = $5000',
                'timestamp': '2024-01-11 10:00:00'
            }
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Strict-Transport-Security', 'max-age=31536000')
            self.end_headers()
            self.wfile.write(json.dumps(message).encode('utf-8'))

        elif self.path == '/certificate':
            # Serve server certificate
            try:
                cert_path = Path('certs/server_cert.pem')
                if cert_path.exists():
                    with open(cert_path, 'rb') as f:
                        cert_data = f.read()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/x-pem-file')
                    self.end_headers()
                    self.wfile.write(cert_data)
                else:
                    self.send_error(404)
            except Exception as e:
                self.send_error(500, str(e))

        else:
            self.send_error(404)

    def log_message(self, format, *args):
        """Suppress default logging"""
        pass


def start_http_server(host='127.0.0.1', port=8000):
    """Start vulnerable HTTP server"""
    print("=" * 70)
    print("STARTING VULNERABLE HTTP SERVER")
    print("=" * 70)
    print(f"[*] Listening on http://{host}:{port}")
    print("[⚠️  WARNING: This server transmits data in PLAINTEXT!]")
    print("[⚠️  Suitable only for educational purposes on isolated networks]")
    print("=" * 70)

    Path('logs').mkdir(exist_ok=True)

    server = HTTPServer((host, port), HTTPRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] HTTP Server stopped")
        server.shutdown()


def start_https_server(host='127.0.0.1', port=8443):
    """Start secure HTTPS server"""
    print("=" * 70)
    print("STARTING SECURE HTTPS SERVER")
    print("=" * 70)
    print(f"[*] Listening on https://{host}:{port}")
    print("[✓] TLS 1.2+ required")
    print("[✓] Data transmitted ENCRYPTED")
    print("=" * 70)

    # Create HTTPS server
    server = HTTPServer((host, port), HTTPSRequestHandler)

    # Set up SSL/TLS (modern, Python 3.12+ compatible)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        certfile='certs/server_cert.pem',
        keyfile='certs/server_key.pem'
    )
    context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA')

    server.socket = context.wrap_socket(server.socket, server_side=True)

    # Generate session key for encryption
    server.session_key = CryptoUtils.generate_key()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] HTTPS Server stopped")
        server.shutdown()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='HTTP/HTTPS Server')
    parser.add_argument('--type', choices=['http', 'https'], default='http',
                       help='Server type')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind')
    parser.add_argument('--port', type=int, help='Port to bind')

    args = parser.parse_args()

    if args.type == 'http':
        port = args.port or 8000
        start_http_server(args.host, port)
    else:
        port = args.port or 8443
        start_https_server(args.host, port)
