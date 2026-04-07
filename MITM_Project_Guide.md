# Man-in-the-Middle (MITM) Attack Simulator & Defense Mechanism
## Complete Project Development Guide

---

## 📋 TABLE OF CONTENTS
1. [Project Overview](#project-overview)
2. [System Architecture](#system-architecture)
3. [Requirements & Installation](#requirements--installation)
4. [Project Structure](#project-structure)
5. [Module Descriptions](#module-descriptions)
6. [Implementation Steps](#implementation-steps)
7. [Running the Simulator](#running-the-simulator)
8. [Testing & Demonstration](#testing--demonstration)
9. [Security Analysis](#security-analysis)
10. [Future Enhancements](#future-enhancements)

---

## PROJECT OVERVIEW

### Purpose
This project demonstrates:
- How MITM attacks exploit insecure HTTP communication
- Packet interception and data manipulation techniques
- How TLS/HTTPS protects against MITM attacks
- Cryptographic mechanisms (RSA, Diffie-Hellman, digital certificates)
- Practical implementation of secure communication protocols

### Learning Outcomes
Students will understand:
- Network packet structure and interception
- Plaintext vs encrypted communication
- SSL/TLS handshake process
- Certificate authentication mechanisms
- Public key cryptography (RSA, DH)
- Hash functions and digital signatures
- How to defend against MITM attacks

### Project Scope
- **Insecure Communication Demo**: HTTP packet capture and modification
- **Secure Communication Demo**: TLS-encrypted communication
- **Key Exchange Simulation**: Diffie-Hellman key exchange implementation
- **Certificate Authority**: Self-signed certificate generation
- **Interactive GUI**: Visualization of attack flow

---

## SYSTEM ARCHITECTURE

### Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    MITM SIMULATOR SYSTEM                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐         ┌──────────────┐      ┌────────────┐ │
│  │   CLIENT    │         │   ATTACKER   │      │   SERVER   │ │
│  │  (Alice)    │◄────────►│   (MITM)     │◄────►│   (Bob)    │ │
│  └─────────────┘         └──────────────┘      └────────────┘ │
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              ATTACK DEMONSTRATION LAYERS                   │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │                                                            │ │
│  │  Layer 1: Unencrypted HTTP Communication (VULNERABLE)     │ │
│  │  - Packet sniffing and analysis                           │ │
│  │  - Credential interception                                │ │
│  │  - Data modification capabilities                         │ │
│  │                                                            │ │
│  │  Layer 2: ARP Spoofing Simulation                         │ │
│  │  - Gateway impersonation                                  │ │
│  │  - Network traffic redirection                            │ │
│  │                                                            │ │
│  │  Layer 3: DNS Spoofing Demonstration                      │ │
│  │  - Fake DNS responses                                     │ │
│  │  - Domain hijacking simulation                            │ │
│  │                                                            │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │         DEFENSE MECHANISMS & PROTECTIONS                  │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │                                                            │ │
│  │  Layer 1: TLS/HTTPS Encryption                            │ │
│  │  - Data encryption/decryption                             │ │
│  │  - Secure handshake process                               │ │
│  │                                                            │ │
│  │  Layer 2: Diffie-Hellman Key Exchange                     │ │
│  │  - Shared secret generation                               │ │
│  │  - Perfect forward secrecy                                │ │
│  │                                                            │ │
│  │  Layer 3: RSA Digital Signatures                          │ │
│  │  - Certificate verification                               │ │
│  │  - Identity authentication                                │ │
│  │                                                            │ │
│  │  Layer 4: Certificate Authority Validation                │ │
│  │  - Trust chain verification                               │ │
│  │  - Certificate pinning                                    │ │
│  │                                                            │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
ATTACK SCENARIO:
Client Request → (HTTP Plaintext) → Attacker Intercepts
Attacker reads/modifies credentials → Forwards to Server
Server Response → Attacker Intercepts → Modifies/Forwards to Client

DEFENSE SCENARIO:
Client Request → TLS Encryption (with DHE handshake) → Server
- Diffie-Hellman key exchange happens
- RSA digital signatures verify identity
- TLS record layer encrypts data
- HMAC ensures integrity
Server Response → TLS Encrypted → Client
- Decryption verification succeeds
- Data integrity confirmed
- Certificate validated
```

---

## REQUIREMENTS & INSTALLATION

### System Requirements
- **OS**: Linux/macOS/Windows (with Python 3.8+)
- **Python**: 3.8 or higher
- **Network Access**: Requires root/admin privileges for packet sniffing
- **Ports**: 8000 (HTTP), 8443 (HTTPS), 5005 (Server)

### Required Libraries

```bash
# Core networking and cryptography
pip install scapy           # Packet manipulation
pip install cryptography    # Cryptographic operations
pip install pycryptodome    # Additional crypto tools
pip install pyopenssl       # OpenSSL bindings

# GUI and visualization
pip install tkinter         # Usually pre-installed
pip install matplotlib      # Graph visualization
pip install pillow          # Image processing

# Utilities
pip install colorama        # Colored terminal output
pip install requests        # HTTP client
pip install paramiko        # SSH connections (optional)
```

### Installation Steps

```bash
# 1. Clone or download the project
git clone <repo-url>
cd MITM-Attack-Simulator

# 2. Create virtual environment
python3 -m venv mitm_env
source mitm_env/bin/activate  # On Windows: mitm_env\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Generate certificates (run once)
python cert_generator.py

# 5. Verify installation
python test_installation.py
```

### OpenSSL Installation (if needed)

**Ubuntu/Debian:**
```bash
sudo apt-get install openssl libssl-dev
```

**macOS:**
```bash
brew install openssl
```

**Windows:**
Download from https://slproweb.com/products/Win32OpenSSL.html

---

## PROJECT STRUCTURE

```
MITM-Attack-Simulator/
│
├── README.md                          # Project overview
├── requirements.txt                   # Dependencies
├── setup.py                           # Installation script
│
├── certs/                             # Certificate directory
│   ├── ca_cert.pem                   # CA certificate
│   ├── ca_key.pem                    # CA private key
│   ├── server_cert.pem               # Server certificate
│   ├── server_key.pem                # Server private key
│   ├── client_cert.pem               # Client certificate
│   └── client_key.pem                # Client private key
│
├── src/                               # Source code
│   ├── __init__.py
│   ├── cert_generator.py             # Certificate generation utility
│   ├── crypto_utils.py               # Cryptographic functions
│   ├── network_sniffer.py            # Packet sniffing module
│   ├── http_server.py                # Insecure HTTP server
│   ├── https_server.py               # Secure HTTPS server
│   ├── http_client.py                # Insecure HTTP client
│   ├── https_client.py               # Secure HTTPS client
│   ├── dh_key_exchange.py            # Diffie-Hellman implementation
│   ├── rsa_crypto.py                 # RSA encryption/signing
│   ├── arp_spoofer.py                # ARP spoofing simulation
│   ├── dns_spoofer.py                # DNS spoofing simulation
│   ├── packet_analyzer.py            # Packet analysis utility
│   └── logger.py                     # Logging utility
│
├── gui/                               # GUI components
│   ├── __init__.py
│   ├── main_gui.py                   # Main GUI window
│   ├── attack_demo.py                # Attack visualization
│   ├── defense_demo.py               # Defense visualization
│   └── dashboard.py                  # Real-time dashboard
│
├── tests/                             # Unit tests
│   ├── __init__.py
│   ├── test_crypto.py
│   ├── test_network.py
│   ├── test_server_client.py
│   └── test_integration.py
│
├── examples/                          # Example scripts
│   ├── demo_http_attack.py           # HTTP attack demonstration
│   ├── demo_https_defense.py         # HTTPS defense demonstration
│   ├── demo_dh_exchange.py           # DH key exchange demo
│   ├── demo_rsa_crypto.py            # RSA encryption demo
│   └── interactive_demo.py           # Interactive tutorial
│
├── docs/                              # Documentation
│   ├── INSTALLATION.md
│   ├── API_REFERENCE.md
│   ├── SECURITY_ANALYSIS.md
│   ├── TROUBLESHOOTING.md
│   └── THEORY.md                     # Cryptographic theory
│
└── logs/                              # Log files
    └── mitm_simulator.log
```

---

## MODULE DESCRIPTIONS

### 1. **cert_generator.py** - Certificate Generation
**Purpose**: Create self-signed certificates for testing TLS connections
- CA (Certificate Authority) creation
- Server certificate generation
- Client certificate generation
- Certificate signing requests (CSR)
- Key pair generation (RSA-2048)

**Key Functions**:
```python
- create_ca()                  # Create Certificate Authority
- create_server_cert()         # Generate server certificate
- create_client_cert()         # Generate client certificate
- verify_certificate()         # Verify certificate chain
```

### 2. **crypto_utils.py** - Cryptographic Operations
**Purpose**: Provides cryptographic primitives
- AES encryption/decryption
- HMAC-SHA256 for integrity
- SHA-256 hashing
- Base64 encoding/decoding
- Random number generation

**Key Functions**:
```python
- encrypt_aes()                # Symmetric encryption
- decrypt_aes()                # Symmetric decryption
- compute_hmac()               # Integrity verification
- hash_data()                  # Secure hashing
```

### 3. **network_sniffer.py** - Packet Sniffing
**Purpose**: Capture and analyze network packets
- Network interface enumeration
- Packet capture using Scapy
- HTTP/HTTPS packet filtering
- Payload extraction
- Protocol analysis

**Key Functions**:
```python
- start_sniffing()             # Begin packet capture
- stop_sniffing()              # Stop capture
- analyze_packet()             # Parse packet structure
- extract_credentials()        # Extract sensitive data
```

### 4. **http_server.py** - Insecure HTTP Server
**Purpose**: Vulnerable HTTP server for attack demonstrations
- Simple HTTP request handling
- Username/password transmission in plaintext
- Message exchange over unencrypted channel
- Simulates real vulnerable applications

**Endpoints**:
```
POST /login      - Accept username/password (PLAINTEXT)
GET /message     - Retrieve sensitive messages
POST /data       - Submit user data (UNENCRYPTED)
```

### 5. **https_server.py** - Secure HTTPS Server
**Purpose**: HTTPS server with TLS encryption
- TLS 1.2/1.3 protocol support
- Certificate-based authentication
- Encrypted communication channel
- HSTS (HTTP Strict Transport Security) headers
- Session management

**Endpoints**:
```
POST /login      - Accept username/password (ENCRYPTED)
GET /message     - Retrieve sensitive messages
POST /data       - Submit user data (ENCRYPTED)
GET /certificate - Serve server certificate
```

### 6. **dh_key_exchange.py** - Diffie-Hellman Key Exchange
**Purpose**: Implement secure key establishment without prior agreement
- Generate DH parameters (p, g)
- Generate private/public key pairs
- Compute shared secret
- Session key derivation
- Perfect forward secrecy implementation

**Key Functions**:
```python
- generate_dh_parameters()     # Create p and g
- generate_keypair()           # Create private/public keys
- compute_shared_secret()      # Calculate secret key
- derive_session_key()         # Derive encryption key
```

### 7. **rsa_crypto.py** - RSA Encryption & Digital Signatures
**Purpose**: Asymmetric encryption and signature verification
- RSA key pair generation (2048-bit)
- Data encryption with public key
- Data decryption with private key
- Digital signature creation
- Signature verification

**Key Functions**:
```python
- generate_rsa_keypair()       # Create RSA keys
- rsa_encrypt()                # Encrypt with public key
- rsa_decrypt()                # Decrypt with private key
- create_signature()           # Sign data
- verify_signature()           # Verify signature
```

### 8. **packet_analyzer.py** - Packet Analysis Utility
**Purpose**: Detailed analysis of captured packets
- Protocol identification
- Header parsing
- Payload extraction
- Statistics calculation
- Visualization data preparation

**Key Functions**:
```python
- parse_ip_packet()            # Extract IP headers
- parse_tcp_packet()           # Extract TCP headers
- parse_http_packet()          # Extract HTTP data
- generate_statistics()        # Calculate metrics
```

### 9. **logger.py** - Logging System
**Purpose**: Centralized logging for all modules
- File logging
- Console output
- Log levels (DEBUG, INFO, WARNING, ERROR)
- Timestamp recording
- Event tracking

---

## IMPLEMENTATION STEPS

### Step 1: Certificate Generation
```bash
python src/cert_generator.py

# Output:
# ✓ CA certificate created: certs/ca_cert.pem
# ✓ CA private key created: certs/ca_key.pem
# ✓ Server certificate created: certs/server_cert.pem
# ✓ Server private key created: certs/server_key.pem
# ✓ Client certificate created: certs/client_cert.pem
# ✓ Client private key created: certs/client_key.pem
```

### Step 2: Start HTTP Server (Vulnerable)
```bash
# Terminal 1
python src/http_server.py --host 127.0.0.1 --port 8000

# Server listening on http://127.0.0.1:8000
```

### Step 3: Start Network Sniffer (Attack Simulation)
```bash
# Terminal 2 - Run with elevated privileges
sudo python src/network_sniffer.py --interface eth0 --port 8000

# Listening for HTTP packets on eth0:8000
# Credentials captured in plaintext!
```

### Step 4: Run HTTP Client (Victim)
```bash
# Terminal 3
python src/http_client.py --server 127.0.0.1 --port 8000

# Sending credentials over HTTP...
# Username: admin
# Password: secret123
# ⚠️ WARNING: Data sent in plaintext!
```

**Result**: Sniffer intercepts credentials in cleartext

### Step 5: Start HTTPS Server (Secure)
```bash
# Terminal 1
python src/https_server.py --host 127.0.0.1 --port 8443

# HTTPS Server listening on https://127.0.0.1:8443
```

### Step 6: Run HTTPS Client (Protected)
```bash
# Terminal 3
python src/https_client.py --server 127.0.0.1 --port 8443

# Connecting via HTTPS...
# TLS Handshake initiated
# ✓ Certificate verified
# ✓ Session key established
# Data transmission encrypted
```

**Result**: Sniffer cannot read encrypted payload

---

## RUNNING THE SIMULATOR

### Option 1: Interactive GUI
```bash
python gui/main_gui.py

# Opens graphical interface with:
# - Attack simulation visualization
# - Defense mechanism demonstration
# - Real-time packet capture display
# - Statistical analysis dashboard
```

### Option 2: Command-Line Demo
```bash
# Complete attack-defense sequence
python examples/interactive_demo.py

# Demonstrates:
# 1. HTTP vulnerability
# 2. Credential interception
# 3. HTTPS protection
# 4. Encryption verification
```

### Option 3: Individual Demonstrations
```bash
# HTTP attack demo
python examples/demo_http_attack.py

# HTTPS defense demo
python examples/demo_https_defense.py

# Diffie-Hellman key exchange
python examples/demo_dh_exchange.py

# RSA encryption demo
python examples/demo_rsa_crypto.py
```

---

## TESTING & DEMONSTRATION

### Test Suite
```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test
python -m pytest tests/test_crypto.py::test_rsa_encryption -v

# Coverage report
python -m pytest tests/ --cov=src --cov-report=html
```

### Demonstration Scenarios

#### Scenario 1: Basic HTTP Interception
1. Start HTTP server
2. Start packet sniffer
3. Connect HTTP client with credentials
4. **Observe**: Credentials visible in plaintext

#### Scenario 2: HTTPS Protection
1. Start HTTPS server
2. Start packet sniffer
3. Connect HTTPS client with same credentials
4. **Observe**: Encrypted payload; credentials invisible

#### Scenario 3: Diffie-Hellman Exchange
1. Run `demo_dh_exchange.py`
2. **Observe**: Secret key derived without transmission
3. **Verify**: Both parties have identical secret key

#### Scenario 4: Digital Signature Verification
1. Run `demo_rsa_crypto.py`
2. **Observe**: Signature creation and verification process
3. **Verify**: Tampered data fails verification

#### Scenario 5: Certificate Validation
1. Start HTTPS server
2. Monitor certificate exchange
3. **Verify**: Certificate chain validation
4. **Test**: Invalid certificate rejection

---

## SECURITY ANALYSIS

### Attack Vectors Demonstrated

#### 1. **HTTP Protocol Weakness**
- **Attack**: Plaintext transmission of credentials
- **Impact**: Complete data interception
- **Detection**: Network sniffer captures readable data
- **Defense**: Use HTTPS/TLS encryption

#### 2. **ARP Spoofing**
- **Attack**: Gateway impersonation via false ARP replies
- **Impact**: Traffic redirection to attacker
- **Detection**: ARP monitoring, gratuitous ARP analysis
- **Defense**: Static ARP entries, ARP inspection

#### 3. **DNS Spoofing**
- **Attack**: Fake DNS responses redirecting to attacker server
- **Impact**: Credential theft via fake website
- **Detection**: DNS monitoring, DNSSEC verification
- **Defense**: DNSSEC, DNS filtering, certificate pinning

#### 4. **SSL Stripping**
- **Attack**: Downgrade HTTPS to HTTP
- **Impact**: Encrypted connection becomes plaintext
- **Detection**: HSTS header enforcement
- **Defense**: HSTS, certificate pinning, protocol enforcement

### Cryptographic Defenses

#### 1. **TLS/SSL Protocol**
- **Encryption**: AES-256-GCM for data confidentiality
- **Handshake**: Validates server identity via certificates
- **HMAC**: Ensures message integrity
- **Key Exchange**: Diffie-Hellman Ephemeral (DHE) for forward secrecy

#### 2. **Digital Certificates**
- **Authentication**: Proves server identity
- **Chain of Trust**: CA signature verification
- **Expiration**: Time-limited validity
- **Revocation**: CRL/OCSP status checking

#### 3. **Perfect Forward Secrecy (PFS)**
- **Session Keys**: Unique for each session
- **Ephemeral Keys**: Discarded after session
- **Security**: Compromise of long-term key doesn't expose past traffic
- **Implementation**: DHE or ECDHE key exchange

#### 4. **Hash Functions**
- **Algorithm**: SHA-256 for fingerprinting
- **Properties**: One-way, collision-resistant
- **Use**: Certificate identification, integrity verification

### Strength Assessment

| Aspect | HTTP | HTTPS |
|--------|------|-------|
| Data Confidentiality | ❌ None | ✅ AES-256 |
| Integrity Verification | ❌ No | ✅ HMAC-SHA256 |
| Server Authentication | ❌ No | ✅ Digital Certs |
| Interception Prevention | ❌ No | ✅ Encryption |
| Replay Protection | ❌ No | ✅ Sequence Numbers |
| Forward Secrecy | ❌ N/A | ✅ DHE/ECDHE |

---

## FUTURE ENHANCEMENTS

### Immediate Improvements
1. **ECDSA Support**: Elliptic curve digital signatures
2. **AES-GCM**: Authenticated encryption with associated data
3. **OCSP Stapling**: Efficient certificate status checking
4. **Session Resumption**: TLS session tickets for efficiency
5. **Perfect Forward Secrecy Stats**: Demonstrate PFS effectiveness

### Advanced Features
1. **Certificate Pinning**: Pin server certificates/public keys
2. **DANE (DNSSEC)**: DNS-based authentication
3. **Mutual TLS (mTLS)**: Client certificate authentication
4. **Hardware Security Module (HSM)**: Key storage security
5. **Post-Quantum Cryptography**: NIST PQC algorithms

### Analysis Tools
1. **Packet Dissector GUI**: Real-time packet breakdown
2. **Statistical Analysis**: Attack success metrics
3. **Comparison Charts**: HTTP vs HTTPS performance
4. **Timeline Visualization**: Attack sequence visualization
5. **Export Reports**: PDF/HTML security analysis reports

### Educational Additions
1. **Video Tutorials**: Step-by-step attack demonstrations
2. **Interactive Lessons**: Guided cryptography learning
3. **Quiz Module**: Knowledge assessment
4. **Vulnerable Code Samples**: Real-world vulnerable patterns
5. **Fix Explanations**: How to remediate vulnerabilities

---

## TROUBLESHOOTING

### Common Issues

#### 1. "Permission denied" for packet sniffing
```bash
# Solution: Run with sudo
sudo python src/network_sniffer.py

# Or: Add user to pcap group
sudo usermod -a -G pcap $USER
```

#### 2. Certificate verification errors
```bash
# Solution: Regenerate certificates
python src/cert_generator.py --force

# Verify certificates
openssl verify -CAfile certs/ca_cert.pem certs/server_cert.pem
```

#### 3. Port already in use
```bash
# Find process using port
lsof -i :8000

# Kill process
kill -9 <PID>
```

#### 4. SSL module import error
```bash
# Solution: Reinstall dependencies
pip install --upgrade cryptography pyopenssl
```

### Performance Optimization

- **Packet Buffering**: Increase buffer size for high-traffic networks
- **Thread Pool**: Use worker threads for concurrent packet processing
- **Database Indexing**: Index captured packets for faster analysis
- **Memory Management**: Implement circular buffer for log rotation

---

## REFERENCES

1. **RFC 5246**: TLS 1.2 Protocol Specification
2. **RFC 8446**: TLS 1.3 Protocol Specification
3. **RFC 2631**: Diffie-Hellman Key Agreement Method
4. **NIST SP 800-52 Rev. 2**: Guidelines for TLS Implementations
5. **OWASP**: Man-in-the-Middle Attack Prevention
6. **CWE-295**: Improper Certificate Validation

---

## CONCLUSION

This project provides a comprehensive understanding of:
- How MITM attacks compromise security
- How modern cryptography defends against attacks
- Practical implementation of secure protocols
- Real-world security implications

**Key Takeaway**: Never transmit sensitive data over unencrypted channels. Always use HTTPS/TLS with proper certificate validation.

---

**Last Updated**: January 2026
**Version**: 1.0
**License**: Educational Use Only
