# demo_app.py
"""
4-Window MITM Live Demo
=======================
Run: python demo_app.py
Then open 4 browser windows:
  Alice (Client)  : http://localhost:5050/client
  Hacker Console  : http://localhost:5050/attacker
  Bank Server     : http://localhost:5050/bank
  Crypto Engine   : http://localhost:5050/crypto
"""

import os, json, time, hashlib, sys
from base64 import b64encode
from pathlib import Path
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO

# ── Import the 6 crypto modules ───────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
try:
    from crypto_utils    import CryptoUtils
    from dh_key_exchange import DiffieHellmanKeyExchange, DHParty
    from rsa_crypto      import RSACrypto
    from ecdsa_crypto    import ECDSACrypto
    from cert_generator  import CertificateGenerator
    from cert_pinning    import CertificatePinning
    from cryptography    import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    CRYPTO_OK = True
except ImportError as e:
    print(f"[WARN] Crypto import error: {e}")
    CRYPTO_OK = False

app = Flask(__name__, template_folder='demo_templates')
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins='*')

# ── Shared simulation state ──────────────────────────────────────────────────
state = {
    'attack_active': False,
    'https_mode':    False,
    'multiplier':    10,
    'balances':      {'Alice': 5000, 'Bob': 3000},
    'transactions':  [],
    'packet_count':  0,
}

# ── Page routes ──────────────────────────────────────────────────────────────
@app.route('/')
def index(): 
    return render_template('index.html')

@app.route('/client')
def client(): return render_template('client.html')

@app.route('/attacker')
def attacker(): return render_template('attacker.html')

@app.route('/bank')
def bank(): return render_template('bank.html')

@app.route('/crypto')
def crypto(): return render_template('crypto_engine.html')

@app.route('/state')
def get_state():
    return jsonify({k: v for k, v in state.items() if k != 'transactions'} |
                   {'transactions': state['transactions'][-10:]})

# ── Transfer endpoint ─────────────────────────────────────────────────────────
@app.route('/transfer', methods=['POST'])
def transfer():
    data    = request.json
    sender  = data.get('sender', 'Alice')
    recip   = data.get('recipient', 'Bob')
    amount  = int(data.get('amount', 0))
    state['packet_count'] += 1
    pkt_id = state['packet_count']

    if state['https_mode']:
        # Generate a realistic-looking AES-GCM ciphertext blob
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key   = os.urandom(32)
        nonce = os.urandom(12)
        ct    = AESGCM(key).encrypt(nonce, json.dumps(data).encode(), None)
        hex_blob = (nonce + ct).hex()

        # Did the attacker ALSO have attack mode on? Mark the attempt.
        attack_attempted = state['attack_active']

        socketio.emit('intercept', {
            'pkt_id':          pkt_id,
            'mode':            'https',
            'hex':             hex_blob,
            'readable':        False,
            'attack_attempted': attack_attempted,
        })
        _do_transfer(sender, recip, amount, tampered=False, mode='HTTPS',
                     attack_attempted=attack_attempted)

    elif state['attack_active']:
        modified = amount * state['multiplier']
        socketio.emit('intercept', {
            'pkt_id':    pkt_id,
            'mode':      'attack',
            'sender':    sender,
            'recipient': recip,
            'original':  amount,
            'modified':  modified,
            'readable':  True,
        })
        _do_transfer(sender, recip, modified, tampered=True, mode='HTTP+ATTACK')

    else:
        socketio.emit('intercept', {
            'pkt_id':    pkt_id,
            'mode':      'plaintext',
            'sender':    sender,
            'recipient': recip,
            'amount':    amount,
            'readable':  True,
        })
        _do_transfer(sender, recip, amount, tampered=False, mode='HTTP')

    return jsonify({'status': 'ok'})


def _do_transfer(sender, recipient, amount, tampered, mode, attack_attempted=False):
    if amount <= 0 or amount > state['balances'].get(sender, 0):
        socketio.emit('transfer_error', {'msg': f'Transfer failed: insufficient funds for {sender}'})
        return

    # Determine original amount (before MITM tampered it)
    original_amount = amount // state['multiplier'] if tampered else amount

    state['balances'][sender]    -= amount
    state['balances'][recipient]  = state['balances'].get(recipient, 0) + amount

    tx = {
        'id':        state['packet_count'],
        'sender':    sender,
        'recipient': recipient,
        'amount':    amount,
        'time':      time.strftime('%H:%M:%S'),
        'tampered':  tampered,
        'mode':      mode,
    }
    state['transactions'].append(tx)
    socketio.emit('bank_update', {'transaction': tx, 'balances': state['balances']})

    # ── Emit live crypto computations to the Crypto Engine page ──────────────
    if CRYPTO_OK:
        try:
            crypto_data = _run_crypto_engines(
                sender=sender,
                recipient=recipient,
                original_amount=original_amount,
                final_amount=amount,
                tampered=tampered,
                mode=mode.lower().replace('+attack','').replace('http','http').strip()
            )
            crypto_data['pkt_id']          = state['packet_count']
            crypto_data['sender']          = sender
            crypto_data['recipient']       = recipient
            crypto_data['original_amount'] = original_amount
            crypto_data['final_amount']    = amount
            crypto_data['tampered']         = tampered
            crypto_data['amount']           = amount
            crypto_data['attack_attempted'] = attack_attempted
            # Normalise mode label
            if 'HTTPS' in mode:
                crypto_data['mode'] = 'https'
            elif tampered:
                crypto_data['mode'] = 'attack'
            else:
                crypto_data['mode'] = 'http'
            socketio.emit('crypto_update', crypto_data)
        except Exception as e:
            print(f"[Crypto Engine] Error: {e}")


def _run_crypto_engines(sender, recipient, original_amount, final_amount, tampered, mode):
    """Run all 6 crypto modules and return a JSON-serialisable dict."""
    payload_str = json.dumps({
        'sender': sender, 'recipient': recipient, 'amount': original_amount
    })

    # 1. AES-GCM + HMAC + SHA-256  (crypto_utils.py) ──────────────────────────
    aes_key   = CryptoUtils.generate_key()           # 32-byte random key
    nonce     = os.urandom(12)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ct_bytes  = AESGCM(aes_key).encrypt(nonce, payload_str.encode(), None)
    hmac_tag  = CryptoUtils.compute_hmac_sha256(payload_str, aes_key)
    sha256_h  = CryptoUtils.hash_sha256_hex(payload_str)
    aes_section = {
        'plaintext':      payload_str,
        'key_hex':        aes_key.hex(),
        'nonce_hex':      nonce.hex(),
        'ciphertext_b64': b64encode(nonce + ct_bytes).decode()[:80] + '…',
        'hmac_hex':       hmac_tag.hex(),
        'sha256_hex':     sha256_h,
    }

    # 2. Diffie-Hellman  (dh_key_exchange.py) ─────────────────────────────────
    dh_params = DiffieHellmanKeyExchange(parameter_size=512)  # small for speed
    params    = dh_params.generate_parameters()
    alice_dh  = DiffieHellmanKeyExchange(512); alice_dh.generate_keypair(params)
    bank_dh   = DiffieHellmanKeyExchange(512); bank_dh.generate_keypair(params)
    alice_secret = alice_dh.private_key.exchange(bank_dh.public_key)
    bank_secret  = bank_dh.private_key.exchange(alice_dh.public_key)
    session_key  = alice_dh.derive_session_key(alice_secret)
    dh_section = {
        'alice_pub_hex':    alice_dh.get_public_key_bytes().decode()[:80].replace('\n','|'),
        'bank_pub_hex':     bank_dh.get_public_key_bytes().decode()[:80].replace('\n','|'),
        'shared_secret_hex': alice_secret.hex()[:64] + '…',
        'session_key_hex':  session_key.hex(),
        'keys_match':       alice_secret == bank_secret,
    }

    # 3. RSA-2048  (rsa_crypto.py) ─────────────────────────────────────────────
    rsa         = RSACrypto(key_size=1024)   # 1024-bit for demo speed
    rsa.generate_keypair()
    rsa_sig     = rsa.create_signature(payload_str)
    tampered_payload = json.dumps({'sender': sender, 'recipient': recipient, 'amount': final_amount})
    rsa_section = {
        'message':          payload_str,
        'signature_hex':    rsa_sig.hex()[:64],
        'verify_original':  rsa.verify_signature(payload_str, rsa_sig),
        'tampered_message': tampered_payload if tampered else f'amount={original_amount} → {final_amount} (modified!)',
        'verify_tampered':  rsa.verify_signature(tampered_payload, rsa_sig),
    }

    # 4. ECDSA P-256  (ecdsa_crypto.py) ───────────────────────────────────────
    ec          = ECDSACrypto()
    ec.generate_keypair()
    ec_sig      = ec.sign(payload_str)
    ecdsa_section = {
        'message':          payload_str,
        'signature_hex':    ec_sig.hex()[:64],
        'sig_bytes':        len(ec_sig),
        'verify_original':  ec.verify(payload_str, ec_sig),
        'verify_tampered':  ec.verify(tampered_payload, ec_sig),
    }

    # 5. X.509 Certificate  (cert_generator.py) ───────────────────────────────
    cert_path = Path('certs/server_cert.pem')
    cert_section = {}
    if cert_path.exists():
        cert_pem  = cert_path.read_bytes()
        cert_obj  = x509.load_pem_x509_certificate(cert_pem, default_backend())
        pub_key   = cert_obj.public_key()
        key_desc  = f"RSA-{pub_key.key_size}-bit" if hasattr(pub_key, 'key_size') else str(type(pub_key).__name__)
        fp        = hashlib.sha256(cert_obj.public_bytes(serialization.Encoding.DER)).hexdigest()
        cert_section = {
            'subject':     str(cert_obj.subject),
            'issuer':      str(cert_obj.issuer),
            'serial':      str(cert_obj.serial_number)[:20],
            'not_before':  str(cert_obj.not_valid_before_utc)[:19] + ' UTC',
            'not_after':   str(cert_obj.not_valid_after_utc)[:19] + ' UTC',
            'key_type':    key_desc,
            'sig_algo':    cert_obj.signature_algorithm_oid.dotted_string,
            'fingerprint': fp[:32] + '…',
        }

    # 6. Certificate Pinning  (cert_pinning.py) ────────────────────────────────
    pinning_section = {}
    if cert_path.exists():
        cert_pem = cert_path.read_bytes()
        pinner   = CertificatePinning()
        cert_fp  = pinner.pin_certificate(cert_pem)
        key_fp   = pinner.pin_public_key(cert_pem)
        # generate a quick rogue cert fingerprint
        import tempfile
        from cert_generator import CertificateGenerator
        tmp = tempfile.mkdtemp()
        rgen = CertificateGenerator(cert_dir=tmp)
        rca, rca_key = rgen.create_ca_certificate()
        rcert, _ = rgen.create_server_certificate(rca, rca_key, hostname='evil.example.com')
        rogue_pem = rcert.public_bytes(serialization.Encoding.PEM)
        rogue_fp  = pinner.get_cert_fingerprint(rogue_pem)
        pinning_section = {
            'cert_fingerprint':  cert_fp[:32] + '…',
            'key_fingerprint':   key_fp[:32] + '…',
            'rogue_fingerprint': rogue_fp[:32] + '…',
        }

    return {
        'aes':     aes_section,
        'dh':      dh_section,
        'rsa':     rsa_section,
        'ecdsa':   ecdsa_section,
        'cert':    cert_section,
        'pinning': pinning_section,
    }


# ── Login endpoint ─────────────────────────────────────────────────────────────
@app.route('/login', methods=['POST'])
def login():
    data     = request.json
    username = data.get('username', '')
    password = data.get('password', '')
    state['packet_count'] += 1
    pkt_id = state['packet_count']

    if state['https_mode']:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key   = os.urandom(32)
        nonce = os.urandom(12)
        ct    = AESGCM(key).encrypt(nonce, json.dumps(data).encode(), None)
        hex_blob = (nonce + ct).hex()
        attack_attempted = state['attack_active']

        socketio.emit('credential_intercept', {
            'pkt_id':           pkt_id,  'mode': 'https',
            'hex':              hex_blob, 'readable': False,
            'attack_attempted': attack_attempted,
        })
        socketio.emit('login_result', {'success': True, 'username': username, 'mode': 'HTTPS'})
        if CRYPTO_OK:
            try:
                cdata = _run_login_crypto(username, password, 'https', attack_attempted)
                cdata.update({'pkt_id': pkt_id, 'type': 'login',
                              'username': username, 'mode': 'https',
                              'attack_attempted': attack_attempted})
                socketio.emit('login_crypto_update', cdata)
            except Exception as e:
                print(f"[Login Crypto] {e}")
    else:
        # HTTP — credentials always readable (even passive sniffing captures them)
        socketio.emit('credential_intercept', {
            'pkt_id':   pkt_id,
            'mode':     'attack' if state['attack_active'] else 'plaintext',
            'username': username, 'password': password,
            'readable': True,    'stolen':   True,
        })
        socketio.emit('login_result', {'success': True, 'username': username, 'mode': 'HTTP'})
        if CRYPTO_OK:
            try:
                cdata = _run_login_crypto(username, password, 'http', False)
                cdata.update({'pkt_id': pkt_id, 'type': 'login',
                              'username': username, 'mode': 'http',
                              'attack_attempted': False})
                socketio.emit('login_crypto_update', cdata)
            except Exception as e:
                print(f"[Login Crypto] {e}")

    socketio.emit('bank_login', {
        'id':       pkt_id,
        'username': username,
        'time':     time.strftime('%H:%M:%S'),
        'mode':     'HTTPS' if state['https_mode'] else 'HTTP',
        'attack_active': state['attack_active']
    })

    return jsonify({'status': 'ok'})


def _run_login_crypto(username, password, mode, attack_attempted):
    """Crypto analysis for login credential events."""
    payload_str = json.dumps({'username': username, 'password': password})

    # Password hashing — what the server stores
    pwd_sha256       = CryptoUtils.hash_sha256_hex(password)
    pwd_key, pwd_salt = CryptoUtils.derive_key_from_password(password, iterations=100000)

    # AES encryption — what HTTPS transmits
    aes_key  = CryptoUtils.generate_key()
    nonce    = os.urandom(12)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ct_bytes = AESGCM(aes_key).encrypt(nonce, payload_str.encode(), None)
    hmac_tag = CryptoUtils.compute_hmac_sha256(payload_str, aes_key)

    return {
        'credential': {
            'username':       username,
            'password_plain': password if mode == 'http' else '(encrypted — hidden from attacker)',
            'password_exposed': mode == 'http',
            'sha256':         pwd_sha256,
            'pbkdf2':         pwd_key.hex()[:64] + '…',
            'salt':           pwd_salt.hex(),
            'payload':        payload_str,
            'aes_key':        aes_key.hex(),
            'nonce':          nonce.hex(),
            'ciphertext':     b64encode(nonce + ct_bytes).decode()[:80] + '…',
            'hmac':           hmac_tag.hex(),
        }
    }


# ── Mode control ──────────────────────────────────────────────────────────────
@app.route('/set_mode', methods=['POST'])
def set_mode():
    data = request.json
    if 'attack'     in data: state['attack_active'] = bool(data['attack'])
    if 'https'      in data: state['https_mode']    = bool(data['https'])
    if 'multiplier' in data: state['multiplier']    = max(1, int(data['multiplier']))
    socketio.emit('mode_change', {
        'attack_active': state['attack_active'],
        'https_mode':    state['https_mode'],
        'multiplier':    state['multiplier'],
    })
    return jsonify({'ok': True})

@app.route('/reset', methods=['POST'])
def reset():
    state['balances']     = {'Alice': 5000, 'Bob': 3000}
    state['transactions'] = []
    state['packet_count'] = 0
    state['attack_active'] = False
    state['https_mode']    = False
    socketio.emit('reset_all', {})
    return jsonify({'ok': True})


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='MITM Live Demo Server')
    parser.add_argument('--port', type=int, default=5050, help='Port to run on (default: 5050)')
    args = parser.parse_args()

    print("\n" + "="*60)
    print("  🔐 MITM LIVE DEMO SERVER STARTING")
    print("="*60)
    print("  Open 4 browser windows side-by-side:\n")
    print(f"  🔵 Alice (Client)  → http://localhost:{args.port}/client")
    print(f"  🔴 Hacker Console  → http://localhost:{args.port}/attacker")
    print(f"  🟢 Bank Server     → http://localhost:{args.port}/bank")
    print(f"  🟣 Crypto Engine   → http://localhost:{args.port}/crypto")
    print("="*60 + "\n")
    socketio.run(app, host='0.0.0.0', port=args.port, debug=False,
                 allow_unsafe_werkzeug=True)
