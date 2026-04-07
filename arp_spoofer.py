# arp_spoofer.py
"""
ARP Spoofing Attack — Educational Simulation

HOW ARP WORKS (Normal):
  ARP (Address Resolution Protocol) resolves IP addresses to MAC addresses on a LAN.
  When your computer needs to reach 192.168.1.1 (gateway), it broadcasts:
    "Who has 192.168.1.1? Tell 192.168.1.100"
  The gateway replies: "192.168.1.1 is at  AA:BB:CC:DD:EE:FF"

HOW ARP SPOOFING WORKS (Attack):
  ARP has NO authentication. Any host can send a "gratuitous ARP" claiming
  any IP-to-MAC mapping. The attacker floods the victim with:
    "192.168.1.1  is at  ATTACKER_MAC"   → victim sends traffic to attacker
    "192.168.1.100 is at  ATTACKER_MAC"  → gateway sends traffic to attacker
  The attacker sits in the middle — classic MITM positioning.

DEFENSES:
  ✓ Dynamic ARP Inspection (DAI) on managed switches
  ✓ Static ARP entries for critical hosts (gateway)
  ✓ ARP spoofing detection tools (arpwatch, XArp)
  ✓ VPNs — traffic encrypted even if ARP-spoofed
  ✓ HTTPS / TLS — data unreadable even if intercepted

NOTE: This module SIMULATES the attack concept. It does NOT send actual packets.
      Real ARP spoofing requires root access and is illegal without authorization.
"""

import sys
import time

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    class Fore:
        RED = YELLOW = GREEN = CYAN = BLUE = WHITE = ""
    class Style:
        RESET_ALL = BRIGHT = ""
    HAS_COLOR = False


class ARPTable:
    """Simulates the ARP cache of a host"""

    def __init__(self, name: str):
        self.name = name
        self._table: dict = {}

    def learn(self, ip: str, mac: str, source: str = "ARP"):
        self._table[ip] = mac
        print(f"  [{self.name}] ARP cache updated: {ip} → {mac}  (via {source})")

    def lookup(self, ip: str) -> str | None:
        return self._table.get(ip)

    def display(self):
        print(f"\n  [{self.name}] ARP Cache:")
        for ip, mac in self._table.items():
            print(f"    {ip:<18} → {mac}")


class ARPSpoofSimulation:
    """
    Educational simulation of ARP spoofing enabling a MITM attack.
    Shows packet-level detail of how the attack works.
    """

    VICTIM_IP   = "192.168.1.100"
    VICTIM_MAC  = "A1:B2:C3:D4:E5:F6"
    GATEWAY_IP  = "192.168.1.1"
    GATEWAY_MAC = "11:22:33:44:55:66"
    ATTACKER_IP = "192.168.1.99"
    ATTACKER_MAC= "DE:AD:BE:EF:CA:FE"

    def _arp_pkt(self, sender_ip, sender_mac, target_ip,
                 op="reply", is_malicious=False):
        """Format a simulated ARP packet for display"""
        color = Fore.RED if is_malicious else Fore.CYAN
        op_str = "ARP Reply (Gratuitous)" if op == "reply" else "ARP Request"
        flag = " ← MALICIOUS" if is_malicious else ""
        return (
            f"\n  {color}┌─ {op_str}{flag}{Style.RESET_ALL}\n"
            f"  │  Sender IP:  {sender_ip}\n"
            f"  │  Sender MAC: {sender_mac}\n"
            f"  │  Target IP:  {target_ip}\n"
            f"  └──────────────────────────────"
        )

    def run_attack_demo(self):
        """Simulate full ARP spoofing MITM setup"""
        print("=" * 70)
        print("ARP SPOOFING — MITM ATTACK SIMULATION (Educational)")
        print("=" * 70)

        print(f"""
  Network Layout:
    Victim   IP: {self.VICTIM_IP:<18} MAC: {self.VICTIM_MAC}
    Gateway  IP: {self.GATEWAY_IP:<18} MAC: {self.GATEWAY_MAC}
    Attacker IP: {self.ATTACKER_IP:<18} MAC: {self.ATTACKER_MAC}
""")

        victim_cache  = ARPTable("Victim")
        gateway_cache = ARPTable("Gateway")

        # --- PHASE 1: Normal state ---
        print(Fore.GREEN + "[PHASE 1] Normal ARP Cache State" + Style.RESET_ALL)
        print("-" * 50)
        victim_cache.learn(self.GATEWAY_IP, self.GATEWAY_MAC, source="Legitimate ARP")
        gateway_cache.learn(self.VICTIM_IP, self.VICTIM_MAC, source="Legitimate ARP")
        victim_cache.display()
        gateway_cache.display()

        time.sleep(0.5)

        # --- PHASE 2: Attack ---
        print(f"\n{Fore.RED}[PHASE 2] ARP Spoofing Attack Begins{Style.RESET_ALL}")
        print("-" * 50)
        print("\n  Attacker sends FORGED gratuitous ARP replies — no authentication required!")

        pkt1 = self._arp_pkt(
            sender_ip=self.GATEWAY_IP, sender_mac=self.ATTACKER_MAC,
            target_ip=self.VICTIM_IP, is_malicious=True
        )
        print(f"  To Victim: (claims to be gateway)")
        print(pkt1)

        pkt2 = self._arp_pkt(
            sender_ip=self.VICTIM_IP, sender_mac=self.ATTACKER_MAC,
            target_ip=self.GATEWAY_IP, is_malicious=True
        )
        print(f"\n  To Gateway: (claims to be victim)")
        print(pkt2)

        print(f"\n  {Fore.YELLOW}Victim and Gateway update their caches with poisoned entries...{Style.RESET_ALL}")
        victim_cache.learn(self.GATEWAY_IP, self.ATTACKER_MAC, source="SPOOFED ARP")
        gateway_cache.learn(self.VICTIM_IP, self.ATTACKER_MAC, source="SPOOFED ARP")

        victim_cache.display()
        gateway_cache.display()

        # --- PHASE 3: Result ---
        print(f"\n{Fore.RED}[PHASE 3] Traffic Now Flows Through Attacker{Style.RESET_ALL}")
        print("-" * 50)
        print(f"""
  BEFORE attack:
    Victim ──────────────────────────────────► Gateway ► Internet

  AFTER ARP spoofing:
    Victim ──► Attacker (reads/modifies) ──► Gateway ► Internet

  {Fore.RED}[⚠️ ] Any unencrypted HTTP traffic is now fully visible & modifiable!{Style.RESET_ALL}
  {Fore.GREEN}[✓]  HTTPS/TLS data is encrypted — attacker sees only ciphertext.{Style.RESET_ALL}
""")

        # --- PHASE 4: Detection ---
        print(Fore.GREEN + "[PHASE 4] Detection Methods" + Style.RESET_ALL)
        print("-" * 50)
        print("""
  1. arpwatch  — monitors ARP table for unexpected changes
  2. XArp      — GUI ARP spoofing detector
  3. Managed switch with Dynamic ARP Inspection (DAI) — validates ARP vs DHCP table
  4. Static ARP entries — prevent ARP cache from being poisoned for critical hosts:
       sudo arp -s 192.168.1.1 11:22:33:44:55:66  (macOS/Linux)
""")

    def run_defense_demo(self):
        """Demonstrate why HTTPS defeats ARP spoofing"""
        print("\n" + "=" * 70)
        print("WHY HTTPS DEFEATS ARP SPOOFING")
        print("=" * 70)
        print(f"""
  ARP spoofing gives the attacker NETWORK POSITION (traffic flows through them).
  It does NOT give them DECRYPTION KEYS.

  HTTP (vulnerable):
    Victim sends:  GET /login HTTP/1.1 username=alice&password=secret123
    Attacker sees: GET /login HTTP/1.1 username=alice&password=secret123  ← plaintext!

  HTTPS (protected):
    Victim sends:  [TLS Record] 8F3A2C019DEF72B... (AES-256-GCM ciphertext)
    Attacker sees: [TLS Record] 8F3A2C019DEF72B... ← meaningless without session key

  The TLS session key is established directly between client and server
  using Diffie-Hellman — an ARP-spoofing attacker who is in the middle
  would need to also impersonate the server's TLS certificate to intercept.
  → This is exactly what CERTIFICATE VALIDATION (and PINNING) prevents!
""")


if __name__ == "__main__":
    sim = ARPSpoofSimulation()
    sim.run_attack_demo()
    sim.run_defense_demo()
    print("[✓] ARP spoofing educational demonstration complete.")
