# QUICK_START_GUIDE.md
# MITM Attack Simulator - Quick Start Guide

## 📋 Prerequisites

- **Python**: 3.8 or higher
- **OS**: Linux, macOS, or Windows
- **Admin/Root**: Required for packet sniffing

## 🚀 Installation (5 minutes)

### Step 1: Install Python Dependencies

```bash
# Clone or download the project
cd MITM-Attack-Simulator

# Create virtual environment
python3 -m venv mitm_env
source mitm_env/bin/activate  # Windows: mitm_env\Scripts\activate

# Install required packages
pip install -r requirements.txt
```

### Step 2: Generate Certificates

```bash
python cert_generator.py

# Output should show:
# [✓] CA certificate created
# [✓] Server certificate created
# [✓] Client certificate created
```

### Step 3: Verify Installation

```bash
python -c "from cryptography.hazmat.primitives.asymmetric import rsa; print('[✓] Cryptography working')"
python -c "from scapy.all import sniff; print('[✓] Scapy working')"
```

## 🎯 Running Demonstrations

### Quick Demo (No Network Required)

Run all cryptographic demonstrations:

```bash
python interactive_demo.py
# Select option 9 to run all demos
```

This demonstrates:
- ✓ Certificate generation
- ✓ Diffie-Hellman key exchange
- ✓ RSA encryption & signatures
- ✓ AES-GCM encryption

**Time**: ~2-3 minutes

---

### Full Attack-Defense Demo (Requires 3 Terminals)

#### Terminal 1: Start HTTP Server (Vulnerable)

```bash
python src/http_server.py --host 127.0.0.1 --port 8000
```

Expected output:
```
STARTING VULNERABLE HTTP SERVER
[*] Listening on http://127.0.0.1:8000
[⚠️  WARNING: This server transmits data in PLAINTEXT!]
```

#### Terminal 2: Start Packet Sniffer (Attack)

```bash
# Linux/macOS
sudo python src/network_sniffer.py --port 8000

# If permission issues, try:
python src/network_sniffer.py --port 8000
```

Expected output:
```
NETWORK PACKET SNIFFER - MITM DEMONSTRATION
[*] Starting packet capture...
[*] Filter: tcp and port 8000
```

#### Terminal 3: Run HTTP Client (Victim)

```bash
python src/http_client.py --server 127.0.0.1 --port 8000
```

**Observe**: Credentials captured in plaintext!

```
[HTTP CLIENT] Sending login request...
[⚠️  WARNING] Data will be sent in PLAINTEXT!
[HTTP SERVER] Received credentials:
  Username: alice
  Password: SecurePassword123!
  [⚠️  WARNING: Data transmitted in PLAINTEXT!]

[NETWORK SNIFFER] Credentials captured:
  [CREDENTIALS DETECTED!]
  Payload: {"username": "alice", "password": "SecurePassword123!"}
```

---

### HTTPS Defense Demo (Requires 3 Terminals)

#### Terminal 1: Start HTTPS Server (Secure)

```bash
python src/https_server.py --host 127.0.0.1 --port 8443
```

Expected output:
```
STARTING SECURE HTTPS SERVER
[*] Listening on https://127.0.0.1:8443
[✓] TLS 1.2+ required
[✓] Data transmitted ENCRYPTED
```

#### Terminal 2: Start Packet Sniffer

```bash
sudo python src/network_sniffer.py --port 8443
```

#### Terminal 3: Run HTTPS Client

```bash
python src/https_client.py --server 127.0.0.1 --port 8443
```

**Observe**: Credentials are NOT visible in sniffer!

```
[HTTPS CLIENT] Sending login request...
[✓] TLS encryption enabled
[Request sent to https://127.0.0.1:8443/login
[✓] Credentials encrypted in transit!

[NETWORK SNIFFER]
(No credentials visible - data encrypted!)
```

---

## 📊 Individual Module Tests

### Test Cryptographic Utilities

```bash
python crypto_utils.py

# Output shows:
# [Test 1] AES-256-GCM Encryption
# [Test 2] HMAC-SHA256 Integrity
# [Test 3] PBKDF2 Key Derivation
# [Test 4] SHA-256 Hashing
```

### Test Diffie-Hellman Exchange

```bash
python dh_key_exchange.py

# Output shows:
# DIFFIE-HELLMAN KEY EXCHANGE SIMULATION
# [PHASE 1] Parameter Generation
# [PHASE 2] Key Pair Generation
# [PHASE 3] Public Key Exchange
# [PHASE 4] Shared Secret Computation
# [VERIFICATION] Secret Agreement Check
# [✓] SUCCESS: Both parties have identical shared secret!
```

### Test RSA Encryption

```bash
python rsa_crypto.py

# Output shows:
# RSA ENCRYPTION DEMONSTRATION
# DIGITAL SIGNATURE DEMONSTRATION
# RSA FOR SYMMETRIC KEY EXCHANGE
# [✓] All RSA demonstrations completed successfully!
```

---

## 🔍 Understanding the Output

### HTTP Attack Capture Example

```
[HTTP REQUEST CAPTURED]
  Method: POST
  Host: 127.0.0.1:8000
  Path: /login
  
[⚠️  CREDENTIALS DETECTED!]
  Payload: {"username": "alice", "password": "SecurePassword123!"}
```

**What this means**: 
- Attacker can see credentials in plaintext
- Can modify requests/responses
- Can inject malicious content
- User has no encryption protection

### HTTPS Defense Example

```
[NETWORK SNIFFER] Listening on port 8443...
[*] Encrypted traffic detected (TLS)
[*] Payload unable to be decrypted (256-bit AES)
[✓] Data integrity verified (HMAC-SHA256)
[✓] Certificate validated successfully
```

**What this means**:
- Attacker cannot read encrypted data
- Cannot modify without detection
- Server identity verified via certificate
- Both parties share identical encryption keys

---

## 🛠️ Troubleshooting

### Issue: "Permission denied" when running sniffer

**Solution**: Run with sudo
```bash
sudo python src/network_sniffer.py --port 8000
```

Or add user to pcap group (permanent):
```bash
sudo usermod -a -G pcap $USER
# Log out and log back in
```

### Issue: "Module not found" errors

**Solution**: Install missing dependencies
```bash
pip install -r requirements.txt
```

### Issue: Port already in use

**Solution**: Use different port or kill process
```bash
# Find process using port 8000
lsof -i :8000

# Kill process
kill -9 <PID>

# Or use different port
python src/http_server.py --port 9000
```

### Issue: Certificate validation errors

**Solution**: Regenerate certificates
```bash
rm -rf certs/
python cert_generator.py
```

### Issue: Scapy import error on Windows

**Solution**: Install Npcap first
1. Download from: https://nmap.org/npcap/
2. Install with "Install Npcap in WinPcap API-compatible Mode"
3. Reinstall scapy: `pip install --upgrade scapy`

---

## 📚 Learning Path

### Beginner (30 minutes)

1. **Understand Concepts**
   - Read: MITM_Project_Guide.md (System Architecture section)
   - Watch: TLS handshake explanation

2. **Run Quick Demo**
   - `python interactive_demo.py` → Select option 9
   - Observe cryptographic operations

3. **Understand Key Concepts**
   - Diffie-Hellman: How to establish shared secret
   - RSA: How to prove identity with signatures
   - AES-GCM: How to encrypt data with authentication

### Intermediate (1-2 hours)

1. **Run HTTP Attack Demo**
   - See plaintext credentials captured
   - Understand vulnerability of HTTP

2. **Run HTTPS Defense Demo**
   - See encrypted data protection
   - Understand strength of TLS

3. **Analyze Differences**
   - Compare attack vs defense packet captures
   - Read security analysis in guide

### Advanced (2-4 hours)

1. **Study Cryptographic Implementations**
   - Review cert_generator.py (X.509 certificates)
   - Review dh_key_exchange.py (key agreement)
   - Review rsa_crypto.py (asymmetric crypto)

2. **Implement Variations**
   - Add AES-256-CBC encryption
   - Add ECDSA signatures
   - Implement certificate pinning

3. **Security Analysis**
   - Perform threat modeling
   - Analyze attack vectors
   - Design mitigations

---

## 🎓 Key Takeaways

### What You'll Learn

```
┌─────────────────────────────────────────────────────────┐
│ 1. VULNERABILITY: HTTP plaintext transmission          │
│    → Credentials and data visible to attackers         │
│                                                         │
│ 2. ATTACK: Packet sniffing + analysis                  │
│    → Intercept and read unencrypted messages           │
│                                                         │
│ 3. DEFENSE: TLS encryption + authentication            │
│    → Confidentiality + Integrity + Authentication      │
│                                                         │
│ 4. CRYPTOGRAPHY: RSA + DH + AES + HMAC                │
│    → Mathematical foundation of security               │
│                                                         │
│ 5. CERTIFICATES: Digital signatures & trust           │
│    → Prove identity without direct verification        │
│                                                         │
│ 6. PROTOCOLS: How HTTPS really works                   │
│    → TLS handshake, session keys, encryption           │
└─────────────────────────────────────────────────────────┘
```

### Golden Rules

1. **Never transmit sensitive data over HTTP** ❌
2. **Always use HTTPS with valid certificates** ✅
3. **Verify certificate authenticity** ✅
4. **Use strong encryption (AES-256)** ✅
5. **Implement authentication (digital signatures)** ✅
6. **Use authenticated encryption (AEAD)** ✅
7. **Enable HSTS to prevent downgrade attacks** ✅

---

## 📞 Getting Help

### Common Issues & Solutions

| Problem | Solution |
|---------|----------|
| Module import errors | `pip install -r requirements.txt` |
| Permission denied (sniffer) | `sudo python network_sniffer.py` |
| Port in use | Use different port or kill process |
| Certificate errors | Regenerate: `python cert_generator.py` |
| SSL warnings | Expected for self-signed certs |

### Additional Resources

- **Cryptography**: https://cryptography.io/
- **Scapy**: https://scapy.readthedocs.io/
- **TLS RFC**: https://tools.ietf.org/html/rfc8446
- **OWASP**: https://owasp.org/www-community/attacks/Man-in-the-middle_attack

---

## ✅ Checklist for Complete Learning

- [ ] Installed all dependencies
- [ ] Generated certificates
- [ ] Ran quick cryptographic demo
- [ ] Ran HTTP attack demo and saw credentials captured
- [ ] Ran HTTPS defense demo and saw data encrypted
- [ ] Understood Diffie-Hellman key exchange
- [ ] Understood RSA encryption and signatures
- [ ] Understood AES-GCM encryption
- [ ] Understood digital certificates
- [ ] Can explain why HTTPS is secure
- [ ] Can explain MITM attack mechanisms
- [ ] Can identify vulnerabilities in code
- [ ] Can recommend security improvements

---

## 🚀 Next Steps

1. **Modify the project**:
   - Add certificate pinning
   - Implement ECDSA signatures
   - Add OCSP stapling

2. **Extend capabilities**:
   - Create GUI dashboard
   - Add statistical analysis
   - Generate security reports

3. **Learn more cryptography**:
   - Study elliptic curves (ECDH, ECDSA)
   - Understand quantum-resistant algorithms
   - Explore zero-knowledge proofs

---

**Last Updated**: January 2026
**Version**: 1.0
**Difficulty**: Beginner to Advanced
**Estimated Time**: 30 minutes to 4 hours
