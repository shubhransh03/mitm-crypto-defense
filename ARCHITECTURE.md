# ARCHITECTURE.md
# MITM Attack Simulator - Architecture & System Design

## 🏗️ System Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│                    MITM ATTACK SIMULATOR ARCHITECTURE                   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│                          PRESENTATION LAYER                           │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐   │
│  │  Interactive     │  │   HTTP Client    │  │   HTTPS Client   │   │
│  │  Demo Menu       │  │   (Vulnerable)   │  │   (Secure)       │   │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘   │
│                                                                        │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐   │
│  │  Network         │  │   HTTP Server    │  │   HTTPS Server   │   │
│  │  Sniffer         │  │   (Vulnerable)   │  │   (Secure)       │   │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘   │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
┌───────────────────▼──────────┐ ┌─▼──────────────────────┐
│   NETWORK COMMUNICATION      │ │  CRYPTOGRAPHIC LAYER   │
├──────────────────────────────┤ ├────────────────────────┤
│                              │ │                        │
│  TCP/IP Stack                │ │ AES-256-GCM            │
│  Socket Operations           │ │   ├─ Encryption       │
│  HTTP Protocol               │ │   ├─ Decryption       │
│  HTTPS/TLS Protocol          │ │   └─ Authentication   │
│  Packet Capture (Scapy)      │ │                        │
│  Port Binding & Listening    │ │ RSA-2048               │
│                              │ │   ├─ Key Generation   │
│                              │ │   ├─ Encryption       │
│                              │ │   ├─ Decryption       │
│                              │ │   ├─ Signing          │
│                              │ │   └─ Verification     │
│                              │ │                        │
│                              │ │ Diffie-Hellman        │
│                              │ │   ├─ Key Exchange     │
│                              │ │   ├─ Secret Derivation│
│                              │ │   └─ HKDF             │
│                              │ │                        │
│                              │ │ Hashing & Integrity   │
│                              │ │   ├─ SHA-256          │
│                              │ │   ├─ HMAC-SHA256      │
│                              │ │   └─ PBKDF2           │
│                              │ │                        │
└──────────────────────────────┘ └────────────────────────┘
                    │                      │
                    └──────────┬───────────┘
                               │
┌──────────────────────────────▼───────────────────────────┐
│                  PKI & CERTIFICATE LAYER                 │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  Certificate Authority (CA)                              │
│    ├─ ca_cert.pem (Public Certificate)                   │
│    └─ ca_key.pem (Private Key)                           │
│                                                           │
│  Server Certificates                                     │
│    ├─ server_cert.pem (X.509 Certificate)                │
│    └─ server_key.pem (RSA Private Key)                   │
│                                                           │
│  Client Certificates                                     │
│    ├─ client_cert.pem (X.509 Certificate)                │
│    └─ client_key.pem (RSA Private Key)                   │
│                                                           │
│  Certificate Operations                                  │
│    ├─ Generation & Signing                               │
│    ├─ Validation & Verification                          │
│    ├─ Chain of Trust                                     │
│    └─ Expiration Management                              │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

---

## 🔄 Data Flow Architecture

### Attack Scenario (HTTP - Vulnerable)

```
CLIENT (Alice)          ATTACKER (Eve)          SERVER (Bob)
    │                        │                       │
    │  Send Credentials      │                       │
    │  (PLAINTEXT)           │                       │
    ├─────────────────────►  │                       │
    │                        │  Intercept & Read     │
    │                        │  Credentials          │
    │                        │                       │
    │                        │  Forward to Server    │
    │                        ├──────────────────────►│
    │                        │                       │
    │                        │ Server Response       │
    │                        │◄──────────────────────┤
    │                        │  (PLAINTEXT)          │
    │  Modified Response     │                       │
    │◄────────────────────────┤                       │
    │                        │                       │

RESULT: Eve can read and modify all communication
```

### Defense Scenario (HTTPS - Secure)

```
CLIENT (Alice)          ATTACKER (Eve)          SERVER (Bob)
    │                        │                       │
    │  TLS HANDSHAKE         │                       │
    ├─────────────────────────────────────────────────►
    │                        │(Encrypted)            │
    │  ◄─────────────────────────────────────────────┤
    │(Certificate, DH Key)   │                       │
    │                        │                       │
    │  [Session Key Established]                     │
    │                        │                       │
    │  Encrypted Credentials │                       │
    ├─────────────────────────────────────────────────►
    │  (AES-256-GCM)         │                       │
    │                        │ Eve cannot decrypt    │
    │                        │ (no session key)      │
    │                        │                       │
    │  ◄─────────────────────────────────────────────┤
    │  Encrypted Response    │                       │
    │  (AES-256-GCM)         │                       │
    │                        │                       │

RESULT: Eve cannot read or modify communication
```

---

## 🔐 TLS/HTTPS Handshake Flow

```
CLIENT                                      SERVER

ClientHello
(Supported protocols, cipher suites)
────────────────────────────────────────────►
                                   ServerHello
                                   (Selected protocol & cipher)
                                   Certificate
                                   (Server's public certificate)
                                   ServerKeyExchange
                                   (Diffie-Hellman parameters)
                                   ServerHelloDone
◄────────────────────────────────────────────

ClientKeyExchange
(Client's DH parameters)
────────────────────────────────────────────►

ChangeCipherSpec
(Switch to encryption)
────────────────────────────────────────────►

Finished
(Encrypted verification)
────────────────────────────────────────────►
                                   ChangeCipherSpec
                                   (Switch to encryption)
◄────────────────────────────────────────────

                                   Finished
                                   (Encrypted verification)
◄────────────────────────────────────────────

[SECURE CHANNEL ESTABLISHED]

Encrypted Application Data
────────────────────────────────────────────►
                                   Encrypted Application Data
◄────────────────────────────────────────────
```

---

## 📦 Module Dependency Graph

```
                    ┌─────────────────────┐
                    │ interactive_demo.py │
                    │  (Main Entry Point) │
                    └──────────┬──────────┘
                               │
        ┌──────────┬───────────┼───────────┬───────────┐
        │          │           │           │           │
    ┌───▼──┐   ┌──▼───┐   ┌──▼───┐   ┌──▼────┐   ┌──▼────┐
    │Crypto│   │  DH  │   │ RSA  │   │ HTTP  │   │Network│
    │ Utils│   │      │   │Crypto│   │Server │   │Sniffer│
    └───┬──┘   └──┬───┘   └──┬───┘   └──┬────┘   └───────┘
        │         │          │          │
        │         │          │      ┌───▼──────┐
        │         │          │      │HTTP      │
        │         │          │      │Client    │
        │         │          │      └──────────┘
        │         │          │
        │         └──────┬───┘
        │                │
    ┌───▼────────────────▼──────┐
    │  cert_generator.py        │
    │  (Certificate Management) │
    └───────────────────────────┘
            │
    ┌───────▼─────────┐
    │  Cryptography   │
    │  Library        │
    │ (Python pkg)    │
    └─────────────────┘
```

---

## 🔐 Cryptographic Components Architecture

```
┌────────────────────────────────────────────────────────┐
│           CRYPTOGRAPHIC OPERATIONS LAYER               │
├────────────────────────────────────────────────────────┤
│                                                        │
│  ┌──────────────────────────────────────────────────┐ │
│  │         SYMMETRIC ENCRYPTION (AES-256)          │ │
│  ├──────────────────────────────────────────────────┤ │
│  │                                                  │ │
│  │  Encryption:                                    │ │
│  │  Plaintext ──AES(256-bit key, 96-bit IV)──►    │ │
│  │             Ciphertext + Auth Tag               │ │
│  │                                                  │ │
│  │  Decryption:                                    │ │
│  │  Ciphertext ──AES(256-bit key, IV)──►          │ │
│  │             Plaintext (if tag valid)            │ │
│  │                                                  │ │
│  │  Mode: GCM (Galois/Counter Mode)                │ │
│  │  ├─ Provides: Confidentiality                   │ │
│  │  ├─ Provides: Integrity                         │ │
│  │  └─ Provides: Authentication                    │ │
│  │                                                  │ │
│  └──────────────────────────────────────────────────┘ │
│                                                        │
│  ┌──────────────────────────────────────────────────┐ │
│  │     ASYMMETRIC ENCRYPTION (RSA-2048)            │ │
│  ├──────────────────────────────────────────────────┤ │
│  │                                                  │ │
│  │  Key Generation:                                │ │
│  │  ├─ Private Key (d, n) - Keep Secret            │ │
│  │  └─ Public Key (e, n) - Share Publicly          │ │
│  │                                                  │ │
│  │  Encryption:                                    │ │
│  │  Plaintext ──RSA(Public Key)──► Ciphertext      │ │
│  │  Only holder of private key can decrypt         │ │
│  │                                                  │ │
│  │  Digital Signature:                             │ │
│  │  Message ──RSA(Private Key)──► Signature        │ │
│  │  Signature ──RSA(Public Key)──► Verified        │ │
│  │                                                  │ │
│  │  Padding: OAEP (Optimal Asymmetric)             │ │
│  │  Hash: SHA-256                                  │ │
│  │                                                  │ │
│  └──────────────────────────────────────────────────┘ │
│                                                        │
│  ┌──────────────────────────────────────────────────┐ │
│  │    KEY AGREEMENT (DIFFIE-HELLMAN)               │ │
│  ├──────────────────────────────────────────────────┤ │
│  │                                                  │ │
│  │  Alice                            Bob            │ │
│  │  ├─ Generate: p, g                └─ Generate  │ │
│  │  ├─ Secret: a                      secret: b    │ │
│  │  ├─ Compute: A = g^a mod p        Compute: B = │ │
│  │  │                                 g^b mod p    │ │
│  │  │                                              │ │
│  │  │  A ──────────────────────────► B            │ │
│  │  │                                              │ │
│  │  │ ◄────────────────────────────  B            │ │
│  │  │                                              │ │
│  │  ├─ Compute: S = B^a mod p        Compute: S = │ │
│  │  │            = g^(ab) mod p      A^b mod p    │ │
│  │  │            = g^(ab) mod p      = g^(ab) mod │ │
│  │  │                                 p           │ │
│  │  │                                              │ │
│  │  └─ S = Shared Secret              └─ S =      │ │
│  │     (Same for both)                Shared      │ │
│  │                                     Secret      │ │
│  │                                                  │ │
│  │  Security: Discrete Log Problem                │ │
│  │  Attacker cannot compute S from p, g, A, B     │ │
│  │                                                  │ │
│  └──────────────────────────────────────────────────┘ │
│                                                        │
│  ┌──────────────────────────────────────────────────┐ │
│  │     INTEGRITY & AUTHENTICATION (HMAC)           │ │
│  ├──────────────────────────────────────────────────┤ │
│  │                                                  │ │
│  │  Creation:                                      │ │
│  │  Message + Key ──HMAC-SHA256──► Tag             │ │
│  │                                                  │ │
│  │  Verification:                                  │ │
│  │  Message + Key ──HMAC-SHA256──► Expected Tag   │ │
│  │  If Received Tag == Expected Tag                │ │
│  │     ├─ Message not modified ✓                   │ │
│  │     ├─ Message is authentic ✓                   │ │
│  │     └─ No tampering detected ✓                  │ │
│  │                                                  │ │
│  └──────────────────────────────────────────────────┘ │
│                                                        │
│  ┌──────────────────────────────────────────────────┐ │
│  │     HASHING (SHA-256)                           │ │
│  ├──────────────────────────────────────────────────┤ │
│  │                                                  │ │
│  │  Input: Data (any size)                         │ │
│  │  Output: 256-bit hash (fixed size)              │ │
│  │                                                  │ │
│  │  Properties:                                    │ │
│  │  ├─ One-way: Cannot reverse                     │ │
│  │  ├─ Collision-resistant: Hard to find           │ │
│  │  │  two inputs with same hash                   │ │
│  │  ├─ Avalanche effect: Small change ──►          │ │
│  │  │  completely different hash                   │ │
│  │  └─ Deterministic: Same input ──►               │ │
│  │     same output                                 │ │
│  │                                                  │ │
│  │  Uses:                                          │ │
│  │  ├─ Certificate fingerprints                    │ │
│  │  ├─ Data integrity checks                       │ │
│  │  ├─ Proof of work                               │ │
│  │  └─ Key derivation                              │ │
│  │                                                  │ │
│  └──────────────────────────────────────────────────┘ │
│                                                        │
└────────────────────────────────────────────────────────┘
```

---

## 🎯 Attack Surface Analysis

### HTTP (Vulnerable)

```
ATTACK VECTORS:
├─ Packet Sniffing
│  └─ Capture credentials in plaintext
├─ Man-in-the-Middle
│  └─ Read and modify all traffic
├─ DNS Spoofing
│  └─ Redirect to attacker's server
├─ ARP Spoofing
│  └─ Intercept traffic via gateway
└─ SSL Stripping
   └─ Force downgrade to HTTP

PROTECTION: None
RISK LEVEL: Critical ⚠️
```

### HTTPS (Secure)

```
ATTACK VECTORS DEFEATED:
├─ Encryption Protection ✓
│  └─ AES-256-GCM blocks content reading
├─ Authentication ✓
│  └─ Digital certificates verify identity
├─ Integrity ✓
│  └─ HMAC detects tampering
├─ Forward Secrecy ✓
│  └─ Ephemeral DH keys prevent history exposure
└─ HSTS ✓
   └─ Browser enforces HTTPS

REMAINING RISKS (Minor):
├─ Certificate pinning (not by default)
├─ Side-channel attacks (timing, cache)
└─ User error (ignoring warnings)

PROTECTION LEVEL: High ✅
RISK LEVEL: Low
```

---

## 📊 Performance Characteristics

```
Operation              Time Complexity    Space Complexity
─────────────────────────────────────────────────────────
RSA Key Generation     O(k^3)             O(k)
  (2048-bit)           ~1-5 seconds       High

AES-256 Encryption     O(n)               O(n)
  (per block)          Fast (<1ms)        Low
                       (Negligible)

DH Key Exchange        O(k^3)             O(k)
  (2048-bit)           ~2-10 seconds      High

HMAC-SHA256            O(n)               O(n)
                       Fast (<1ms)        Low

SHA-256 Hash           O(n)               O(n)
                       Fast (<1ms)        Low

TLS Handshake          Total: 1-2 sec     Medium
  (Full)               Dominated by
                       RSA operations
```

---

## 🔍 Security Properties Matrix

| Property | HTTP | HTTPS |
|----------|------|-------|
| **Confidentiality** | ❌ None | ✅ AES-256 |
| **Integrity** | ❌ None | ✅ HMAC |
| **Authentication** | ❌ None | ✅ Certificates |
| **Non-Repudiation** | ❌ No | ✅ Yes |
| **Forward Secrecy** | ❌ N/A | ✅ DHE/ECDHE |
| **Protection Level** | 🔴 Critical | 🟢 Secure |

---

This architecture supports educational understanding of modern cryptography and secure communication protocols!
