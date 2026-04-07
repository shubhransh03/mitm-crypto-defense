# README.md
# Man-in-the-Middle (MITM) Attack Simulator & Defense Mechanism

**Educational Project for Cybersecurity & Cryptography**

[![License](https://img.shields.io/badge/License-Educational-blue)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-green)](https://github.com)

---

## 📌 Overview

This comprehensive project demonstrates:

✅ **How MITM attacks compromise unencrypted communication**
- Packet sniffing and credential interception
- HTTP protocol vulnerabilities
- Real-time traffic analysis

✅ **How TLS/HTTPS protects against attacks**
- Encryption with AES-256-GCM
- Authentication with RSA digital signatures
- Key agreement via Diffie-Hellman
- Message integrity with HMAC-SHA256

✅ **Cryptographic foundations**
- RSA (2048-bit) for asymmetric encryption
- Diffie-Hellman key exchange
- AES-256-GCM authenticated encryption
- SHA-256 hashing and HMAC

✅ **Digital certificates and PKI**
- Self-signed certificate generation
- X.509 certificate structure
- Certificate validation chains
- Public key infrastructure concepts

---

## 🎯 Learning Outcomes

After completing this project, you will understand:

| Concept | Depth |
|---------|-------|
| **Network Security** | How MITM attacks work; packet-level analysis |
| **Cryptography** | RSA, DH, AES, HMAC; how they protect data |
| **TLS/HTTPS** | Complete handshake process; cipher suites |
| **Certificates** | Digital signatures; trust chains; validation |
| **Best Practices** | Secure communication patterns; vulnerability remediation |

---

## 📂 Project Structure

```
MITM-Attack-Simulator/
├── README.md                          # This file
├── MITM_Project_Guide.md              # Comprehensive project guide
├── QUICK_START_GUIDE.md               # Quick start instructions
├── ARCHITECTURE.md                    # System architecture diagrams
├── PROJECT_SUMMARY.md                 # Project deliverables summary
├── requirements.txt                   # Python dependencies
│
├── certs/                             # Digital certificates (auto-generated)
│   ├── ca_cert.pem                   # Certificate Authority
│   ├── ca_key.pem                    # CA private key
│   ├── server_cert.pem               # Server certificate
│   ├── server_key.pem                # Server private key
│   ├── client_cert.pem               # Client certificate
│   └── client_key.pem                # Client private key
│
├── bank_app/                          # Flask mock bank — realistic MITM target
│   ├── __init__.py                   # Flask app factory
│   ├── config.py                     # Flask configuration
│   ├── models.py                     # User/balance data (PBKDF2 hashing)
│   ├── routes.py                     # Login, register, transfer endpoints
│   └── templates/                    # HTML templates
│       ├── base.html
│       └── index.html
│
├── logs/                              # Captured data logs
│   └── captured_credentials_http.log # Intercepted credentials
│
├── cert_generator.py                  # Generate X.509 certificate chain
├── crypto_utils.py                    # AES-GCM, HMAC, SHA-256, PBKDF2
├── dh_key_exchange.py                 # Diffie-Hellman key exchange
├── rsa_crypto.py                      # RSA encryption & digital signatures
├── http_https_server.py               # Vulnerable HTTP + Secure HTTPS servers
├── http_https_client.py               # HTTP + HTTPS clients
├── network_sniffer.py                 # Passive packet sniffer (Scapy)
├── mitm_proxy.py                      # Active MITM TCP proxy (modifies traffic!)
└── interactive_demo.py                # Interactive menu-driven demo [11 demos]
```

---

## 🚀 Quick Start (5 minutes)

### 1. Install Dependencies

```bash
# Clone repository
cd MITM-Attack-Simulator

# Create virtual environment
python3 -m venv mitm_env
source mitm_env/bin/activate

# Install packages
pip install -r requirements.txt
```

### 2. Generate Certificates

```bash
python src/cert_generator.py
```

### 3. Run Interactive Demo

```bash
python examples/interactive_demo.py

# Select option 9 to run all cryptographic demonstrations
```

### 4. Full Attack-Defense Demo

**Terminal 1** - Vulnerable HTTP Server:
```bash
python src/http_https_server.py --type http --port 8000
```

**Terminal 2** - Packet Sniffer (Monitor):
```bash
sudo python src/network_sniffer.py --port 8000
```

**Terminal 3** - HTTP Client (Send credentials):
```bash
python src/http_https_client.py --type http --port 8000
```

👉 **Observe**: Credentials captured in plaintext!

---

## 🔐 Core Modules Explained

### 1. **cert_generator.py** - Digital Certificates
Generates self-signed X.509 certificates using RSA-2048:
- Certificate Authority (CA)
- Server certificate
- Client certificate

```python
from src.cert_generator import CertificateGenerator
gen = CertificateGenerator()
gen.generate_all_certificates()
```

### 2. **crypto_utils.py** - Encryption & Integrity
Implements AES-256-GCM and HMAC-SHA256:

```python
from src.crypto_utils import CryptoUtils

# Encrypt
key = CryptoUtils.generate_key()
encrypted = CryptoUtils.encrypt_aes_gcm("secret", key)

# Decrypt
decrypted = CryptoUtils.decrypt_aes_gcm(encrypted, key)
```

### 3. **dh_key_exchange.py** - Key Agreement
Implements Diffie-Hellman protocol:

```python
from src.dh_key_exchange import DHSimulation
sim = DHSimulation()
sim.run_simulation(parameter_size=2048)
```

### 4. **rsa_crypto.py** - Asymmetric Crypto
RSA encryption and digital signatures:

```python
from src.rsa_crypto import RSACrypto

rsa = RSACrypto()
rsa.generate_keypair()
encrypted = rsa.encrypt("message")
decrypted = rsa.decrypt(encrypted)
```

### 5. **network_sniffer.py** - Packet Capture
Captures and analyzes network traffic:

```bash
# Capture HTTP traffic
sudo python src/network_sniffer.py --port 80

# Capture HTTPS traffic  
sudo python src/network_sniffer.py --port 443
```

---

## 📊 Comparison: HTTP vs HTTPS

| Feature | HTTP ❌ | HTTPS ✅ |
|---------|---------|---------|
| **Encryption** | None | AES-256-GCM |
| **Data Confidentiality** | Exposed | Protected |
| **Integrity Check** | None | HMAC-SHA256 |
| **Authentication** | None | RSA Certificates |
| **Man-in-Middle Safe** | No | Yes |
| **Interception** | Easy | Impossible |
| **Performance** | Faster | Slight overhead |

---

## 🎓 Demonstrations

### Demo 1: Cryptographic Operations (2 min)
```bash
python src/crypto_utils.py
```
Shows: AES-GCM encryption, HMAC integrity, PBKDF2 key derivation

### Demo 2: Key Exchange (3 min)
```bash
python src/dh_key_exchange.py
```
Shows: How Alice and Bob establish shared secret without transmission

### Demo 3: Digital Signatures (2 min)
```bash
python src/rsa_crypto.py
```
Shows: How signatures detect tampering

### Demo 4: HTTP Vulnerability (5 min)
```bash
# Terminal 1: Server
python src/http_https_server.py --type http

# Terminal 2: Sniffer
sudo python src/network_sniffer.py --port 8000

# Terminal 3: Client
python src/http_https_client.py --type http
```
Shows: Credentials captured in plaintext

### Demo 5: HTTPS Protection (5 min)
```bash
# Terminal 1: Server
python src/http_https_server.py --type https

# Terminal 2: Sniffer
sudo python src/network_sniffer.py --port 8443

# Terminal 3: Client
python src/http_https_client.py --type https
```
Shows: Encrypted data protection

---

## 🔬 Technical Details

### TLS Handshake Flow

```
Client                                          Server

ClientHello ──────────────────────────────────→
                ← ServerHello, Certificate, ServerKeyExchange, ServerHelloDone

ClientKeyExchange ─────────────────────────────→
ChangeCipherSpec ──────────────────────────────→
Finished ──────────────────────────────────────→
                                  ChangeCipherSpec ←
                                       Finished ←

[Encrypted Application Data]
```

### Cryptographic Mechanisms

**Key Exchange**:
- Diffie-Hellman (DHE) for ephemeral keys
- Perfect Forward Secrecy (PFS) enabled

**Encryption**:
- AES-256-GCM for symmetric encryption
- 256-bit keys, 96-bit random nonce

**Authentication**:
- RSA-2048 for digital signatures
- SHA-256 for hashing

**Integrity**:
- HMAC-SHA256 for message authentication
- AEAD (authenticated encryption with associated data)

---

## 📈 Security Analysis

### HTTP Vulnerabilities

```
✗ Plaintext Transmission
  → Credentials visible to attackers
  → No confidentiality protection

✗ No Authentication
  → Cannot verify server identity
  → Vulnerable to spoofing

✗ No Integrity Protection
  → Messages can be modified in transit
  → No detection of tampering
```

### HTTPS Protections

```
✓ Encrypted Communication
  → AES-256-GCM confidentiality
  → Only parties with key can read

✓ Server Authentication
  → RSA digital signature verification
  → Certificate chain validation

✓ Integrity Verification
  → HMAC-SHA256 ensures data integrity
  → Detects any message modification
  
✓ Forward Secrecy
  → Ephemeral DH keys per session
  → Compromise doesn't expose past sessions
```

---

## 🛠️ Advanced Usage

### Custom Key Size

```python
# Generate 4096-bit RSA
rsa = RSACrypto(key_size=4096)
rsa.generate_keypair()
```

### Password-Based Encryption

```python
from src.crypto_utils import CryptoUtils

password = "MySecurePassword"
key, salt = CryptoUtils.derive_key_from_password(password)
encrypted = CryptoUtils.encrypt_aes_gcm("secret", key)
```

### Certificate Chain Validation

```python
from src.cert_generator import CertificateGenerator

gen = CertificateGenerator()
ca_cert = gen.create_ca_certificate()
server_cert = gen.create_server_certificate(ca_cert[0], ca_cert[1])
```

---

## 📚 Learning Resources

### Included Documentation
- **MITM_Project_Guide.md**: Complete project documentation
- **QUICK_START_GUIDE.md**: Step-by-step setup and usage
- Inline code comments explaining cryptographic operations

### External Resources

**Cryptography**:
- [Cryptography.io Docs](https://cryptography.io/)
- [NIST SP 800-56A](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final)

**TLS/HTTPS**:
- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [RFC 5246 - TLS 1.2](https://tools.ietf.org/html/rfc5246)

**Network Security**:
- [OWASP - MITM Prevention](https://owasp.org/www-community/attacks/)
- [PortSwigger - HTTPS](https://portswigger.net/https)

---

## 🐛 Troubleshooting

### Issue: "Permission denied" (Packet Sniffer)

**Solution**: Use sudo or add user to pcap group
```bash
sudo python src/network_sniffer.py --port 8000
```

### Issue: "Module not found"

**Solution**: Install dependencies
```bash
pip install -r requirements.txt
```

### Issue: Port already in use

**Solution**: Use different port
```bash
python src/http_https_server.py --type http --port 9000
```

### Issue: Certificate validation error

**Solution**: Regenerate certificates
```bash
rm -rf certs/
python src/cert_generator.py
```

---

## ✅ Project Checklist

- [x] Certificate generation (X.509)
- [x] AES-256-GCM encryption
- [x] HMAC-SHA256 integrity
- [x] Diffie-Hellman key exchange
- [x] RSA encryption & signatures
- [x] HTTP server (vulnerable)
- [x] HTTPS server (secure)
- [x] Network sniffer (passive packet capture)
- [x] Active MITM proxy (traffic tampering)
- [x] Flask mock bank app (realistic attack target)
- [x] PBKDF2 password hashing in bank app
- [x] Interactive demo (11 demonstrations)
- [x] Comprehensive documentation
- [x] Quick start guide

---

## 🎯 Use Cases

### Educational
- ✓ University cybersecurity courses
- ✓ Security awareness training
- ✓ Cryptography labs

### Professional
- ✓ Security team demonstrations
- ✓ Vulnerability analysis
- ✓ Protocol testing

### Research
- ✓ Cryptographic algorithm analysis
- ✓ Attack methodology research
- ✓ Defense mechanism evaluation

---

## ⚠️ Important Notice

**This project is for educational purposes only.**

- ✓ Use on isolated test networks
- ✓ Never use on production systems without permission
- ✓ Follow ethical hacking principles
- ✓ Respect privacy and legal requirements

---

## 🤝 Contributing

Contributions welcome! Potential enhancements:

- [ ] Add ECDSA signatures
- [ ] Implement HKDF key derivation
- [ ] Add certificate pinning
- [ ] Create GUI dashboard
- [ ] Add statistical analysis
- [ ] Generate security reports
- [ ] Support for TLS 1.3 features

---

## 📄 License

Educational use only - See LICENSE file for details

---

## 👨‍🏫 Author

Created for computer science students and cybersecurity professionals

**Version**: 1.0  
**Last Updated**: January 2026  
**Status**: Production Ready

---

## 🚀 Next Steps

1. **Run Quick Demo**: `python examples/interactive_demo.py`
2. **Read Guide**: Open `MITM_Project_Guide.md`
3. **Try Attacks**: Follow `QUICK_START_GUIDE.md`
4. **Study Code**: Review individual modules
5. **Extend Project**: Implement additional features

---

**Questions? Issues? Suggestions?**

Refer to QUICK_START_GUIDE.md or MITM_Project_Guide.md for comprehensive help.

---

```
 _   _ _____ _____ __  __     _____ _                 _       _           
| | | |_   _|_   _|  \/  |   / ____(_)               | |     | |          
| |_| | | |   | | | |\/| |  | (___  _ _ __ ___   ___ | | __ _| |_ ___  _ __ 
|  _  | | |   | | | |  | |   \___ \| | '_ ` _ \ / _ \| |/ _` | __/ _ \| '__|
| | | |_| |_  | | | |  | |   ____) | | | | | | | (_) | | (_| | || (_) | |   
|_| |_|_____|_|_| |_|  |_|  |_____/|_|_| |_| |_|\___/|_|\__,_|\__\___/|_|   

Educational Project for Cybersecurity & Cryptography
```
# mitm-crypto-defense
