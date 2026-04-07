# dns_spoofer.py
"""
DNS Spoofing Attack — Educational Simulation

HOW DNS WORKS (Normal):
  DNS (Domain Name System) translates human-readable domain names to IP addresses.
  When you visit "mybank.com" your computer asks:
    Client → DNS Resolver: "What is the IP for mybank.com?"
    DNS Resolver → Client: "mybank.com is at 93.184.216.34"

HOW DNS SPOOFING WORKS (Attack):
  DNS responses are traditionally sent over UDP with NO authentication.
  An attacker who can intercept or predict DNS queries can reply first with a FAKE answer:
    Client asks:    "What is the IP for mybank.com?"
    Attacker replies: "mybank.com is at ATTACKER_IP"  (before legitimate reply arrives)
  Client connects to attacker's server thinking it's the real bank.

VARIANTS:
  1. DNS Cache Poisoning   — corrupt a DNS resolver's cache (affects all clients using it)
  2. DNS Hijacking         — compromise the router/ISP DNS settings
  3. Rogue DNS Server      — set up malicious Wi-Fi with a spoofed DNS server

DEFENSES:
  ✓ DNSSEC  — DNS Security Extensions: cryptographic signatures on DNS records
  ✓ DoH     — DNS over HTTPS: encrypts queries so an attacker can't intercept them
  ✓ DoT     — DNS over TLS: same concept as DoH
  ✓ HTTPS   — even with wrong IP, TLS cert validation catches the deceit
  ✓ HSTS    — prevents downgrade from HTTPS to HTTP
  ✓ Certificate Pinning  — pins specific server public key

NOTE: This module SIMULATES the attack concept. No actual DNS queries are modified.
"""

import time
import sys

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = YELLOW = GREEN = CYAN = BLUE = ""
    class Style:
        RESET_ALL = ""


class DNSCache:
    """Simulates a local DNS resolver cache"""

    def __init__(self, name: str):
        self.name = name
        self._cache: dict = {}

    def add(self, domain: str, ip: str, ttl: int = 300, source: str = "DNS"):
        self._cache[domain] = {"ip": ip, "ttl": ttl, "source": source}

    def resolve(self, domain: str):
        return self._cache.get(domain)

    def display(self):
        print(f"\n  [{self.name}] DNS Cache:")
        for domain, entry in self._cache.items():
            src_color = Fore.RED if entry['source'] == "SPOOFED" else Fore.GREEN
            print(f"    {domain:<25} → {entry['ip']:<18} "
                  f"TTL:{entry['ttl']}s  {src_color}({entry['source']}){Style.RESET_ALL}")


def _dns_pkt(query_id: str, domain: str, answer_ip: str,
             is_spoofed: bool = False):
    """Format a simulated DNS response packet for display"""
    color = Fore.RED if is_spoofed else Fore.CYAN
    flag = " ← SPOOFED (attacker won the race!)" if is_spoofed else ""
    return (
        f"\n  {color}┌─ DNS Response (UDP){flag}{Style.RESET_ALL}\n"
        f"  │  Transaction ID: {query_id}\n"
        f"  │  Question:  {domain}  IN  A\n"
        f"  │  Answer:    {domain}  300  IN  A  {answer_ip}\n"
        f"  └──────────────────────────────────────────────"
    )


class DNSSpoofSimulation:
    """Educational simulation of DNS spoofing and cache poisoning"""

    REAL_BANK_IP     = "93.184.216.34"
    ATTACKER_IP      = "192.168.1.99"
    TARGET_DOMAIN    = "mybank.com"

    def run_attack_demo(self):
        """Simulate DNS spoofing via query ID prediction (Kaminsky attack style)"""
        print("=" * 70)
        print("DNS SPOOFING — MITM ATTACK SIMULATION (Educational)")
        print("=" * 70)

        client_cache = DNSCache("Client DNS Cache")
        resolver_cache = DNSCache("Resolver Cache")

        # Phase 1 — Normal resolution
        print(f"\n{Fore.GREEN}[PHASE 1] Normal DNS Resolution{Style.RESET_ALL}")
        print("-" * 50)
        print(f"\n  Client queries DNS: 'What is the IP for {self.TARGET_DOMAIN}?'")
        time.sleep(0.3)
        legit_response = _dns_pkt(
            query_id="0xA1B2", domain=self.TARGET_DOMAIN,
            answer_ip=self.REAL_BANK_IP, is_spoofed=False
        )
        print(f"  Legitimate DNS resolver replies:")
        print(legit_response)
        client_cache.add(self.TARGET_DOMAIN, self.REAL_BANK_IP, source="Legitimate DNS")
        client_cache.display()

        # Phase 2 — Attacker enters
        print(f"\n{Fore.RED}[PHASE 2] DNS Spoofing Attack{Style.RESET_ALL}")
        print("-" * 50)
        print(f"""
  Attack method: Attacker on the same network intercepts the UDP DNS query
  and races to send a forged response BEFORE the real DNS resolver replies.

  Key vulnerability:
    - Older DNS uses UDP (connectionless) with a 16-bit transaction ID
    - Attack sends {65536} spoofed responses guessing all possible transaction IDs
    - If even ONE spoofed reply arrives before the real one → cache poisoned
""")

        time.sleep(0.3)
        spoofed_response = _dns_pkt(
            query_id="0xA1B2", domain=self.TARGET_DOMAIN,
            answer_ip=self.ATTACKER_IP, is_spoofed=True
        )
        print(f"  Attacker sends flood of forged DNS responses:")
        print(spoofed_response)

        client_cache.add(
            self.TARGET_DOMAIN, self.ATTACKER_IP,
            source="SPOOFED", ttl=300
        )

        # Phase 3 — Consequence
        print(f"\n{Fore.RED}[PHASE 3] Consequence — Client Connects to Attacker{Style.RESET_ALL}")
        print("-" * 50)
        cached = client_cache.resolve(self.TARGET_DOMAIN)
        client_cache.display()

        print(f"""
  Client browser resolves {self.TARGET_DOMAIN}:
    Cached IP: {cached['ip']}  ← this is the ATTACKER'S server!

  {Fore.RED}[⚠️ ] Client connects to attacker server thinking it's mybank.com!{Style.RESET_ALL}

  HTTP scenario (no HTTPS):
    → Attacker serves a fake login page
    → Victim enters credentials
    → Credentials stolen — game over.

  HTTPS scenario (TLS certificate validation):
    → Attacker's server presents a FAKE certificate for mybank.com
    → Browser checks: "Is this cert signed by a trusted CA for mybank.com?"
    → Attacker's cert is SELF-SIGNED or from UNAUTHORIZED CA → {Fore.GREEN}WARNING shown{Style.RESET_ALL}
    → User should NOT proceed past the browser warning
""")

    def run_kaminsky_demo(self):
        """Explain the Kaminsky attack (cache poisoning at resolver level)"""
        print("\n" + "=" * 70)
        print("BONUS: THE KAMINSKY ATTACK (2008)")
        print("=" * 70)
        print(f"""
  Dan Kaminsky discovered a critical flaw: DNS cache poisoning at the RESOLVER level.
  Instead of poisoning the client cache (one victim), poison the resolver (affects ALL clients).

  Attack steps:
    1. Send many queries for random.mybank.com (forces resolver to query authoritative DNS)
    2. Simultaneously flood the resolver with forged responses for mybank.com itself
    3. If ANY forged response is accepted, the resolver caches attacker's IP for mybank.com
    4. ALL clients using this resolver now get the wrong IP for mybank.com

  Scale: A single successful poisoning can redirect millions of users.

  Fix: DNSSEC (DNS Security Extensions) — each record is cryptographically signed.
    Resolver validates the signature against the domain's public key.
    Forged responses fail the signature check and are rejected.
""")

    def run_defense_demo(self):
        """Show layered defenses against DNS spoofing"""
        print("\n" + "=" * 70)
        print("LAYERED DEFENSES AGAINST DNS SPOOFING")
        print("=" * 70)

        defenses = [
            ("DNSSEC",
             "Cryptographically signs DNS records. Resolvers validate signatures.\n"
             "     Most effective defense — prevents fake DNS responses entirely."),
            ("DNS over HTTPS (DoH)",
             "Encrypts DNS queries so on-path attackers can't intercept them.\n"
             "     Enabled by default in Firefox, Chrome."),
            ("DNS over TLS (DoT)",
             "Same protection as DoH but uses dedicated port 853."),
            ("HTTPS + Certificate Validation",
             "Even with wrong IP, browser checks TLS certificate.\n"
             "     Expired/invalid cert for domain → browser warning."),
            ("Certificate Pinning",
             "Pins specific server public key — rogue cert rejected even from trusted CA.\n"
             "     Used by banking apps, Chrome, for critical domains."),
            ("HSTS (HTTP Strict Transport Security)",
             "Browser remembers 'always use HTTPS' for a domain.\n"
             "     Prevents SSL stripping attack after first visit."),
        ]

        for name, desc in defenses:
            print(f"\n  {Fore.GREEN}[✓] {name}{Style.RESET_ALL}")
            print(f"     {desc}")

        print("\n  Defense-in-depth: DNS spoofing alone is not enough if TLS is in place!")


if __name__ == "__main__":
    sim = DNSSpoofSimulation()
    sim.run_attack_demo()
    sim.run_kaminsky_demo()
    sim.run_defense_demo()
    print("\n[✓] DNS spoofing educational demonstration complete.")
