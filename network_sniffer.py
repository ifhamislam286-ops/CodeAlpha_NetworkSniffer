#!/usr/bin/env python3

"""
Network Packet Capture & Analyzer
---------------------------------

Educational packet sniffer using Scapy.

Displays:
    - Timestamp
    - Source IP
    - Destination IP
    - Protocol
    - Source/Destination ports
    - Packet length
    - Limited printable payload preview

Use ONLY on:
    - Your own machine/network
    - A controlled cybersecurity lab
    - Networks where you have explicit authorization

Run with appropriate privileges because packet capture usually
requires root/admin permissions.
"""

from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw  # type: ignore


MAX_PAYLOAD_DISPLAY = 80


def protocol_name(packet):
    """Determine the protocol carried by the IP packet."""
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    return "IP"


def get_payload_preview(packet):
    """Extract a small, printable preview of the packet payload."""
    if not packet.haslayer(Raw):
        return "-"

    raw_data = bytes(packet[Raw].load)
    text = raw_data.decode("utf-8", errors="replace")
    text = text.replace("\n", "\\n")
    text = text.replace("\r", "\\r")
    text = text.replace("\t", "\\t")
    return text[:MAX_PAYLOAD_DISPLAY]


def analyze_packet(packet):
    """Callback executed for every captured packet."""
    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]
    source_ip = ip_layer.src
    destination_ip = ip_layer.dst
    protocol = protocol_name(packet)
    packet_length = len(packet)

    source_port = "-"
    destination_port = "-"

    if packet.haslayer(TCP):
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    payload = get_payload_preview(packet)
    timestamp = datetime.now().strftime("%H:%M:%S")

    print(
        f"[{timestamp}] "
        f"{source_ip}:{source_port} -> "
        f"{destination_ip}:{destination_port} | "
        f"{protocol:<5} | "
        f"Length: {packet_length:<5} | "
        f"Payload: {payload}"
    )


def main():
    """Start packet capture."""
    print("=" * 100)
    print("        Python Network Packet Capture & Analyzer")
    print("=" * 100)
    print("[*] Starting packet capture...")
    print("[*] Press CTRL+C to stop.")
    print("[*] Only capture traffic you are authorized to inspect.\n")

    try:
        sniff(filter="ip", prn=analyze_packet, store=False)
    except PermissionError:
        print("\n[!] Permission denied.")
        print("[!] Run the program with appropriate capture privileges.")
    except KeyboardInterrupt:
        print("\n\n[*] Capture stopped by user.")
    except Exception as error:
        print(f"\n[!] Capture error: {error}")


if __name__ == "__main__":
    main()
