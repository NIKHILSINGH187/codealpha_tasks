#!/usr/bin/env python3
"""
CodeAlpha_NetworkSniffer
-------------------------
A basic educational network sniffer built with Scapy.

WHAT THIS DOES
- Captures live network packets on a chosen interface
- Parses Ethernet / IP / TCP / UDP / ICMP headers
- Displays source & destination IP, ports, protocol, and a safe
  preview of the payload (raw bytes -> printable text)
- Optionally filters by protocol (tcp/udp/icmp) using BPF filter syntax
- Optionally writes captured packets to a .pcap file for later analysis
  in Wireshark

LEGAL / ETHICAL NOTE
Only run this on networks and devices you own or have explicit
written permission to monitor. Capturing traffic on networks you
do not control or do not have authorization for is illegal in most
jurisdictions. This tool is for learning purposes as part of the
CodeAlpha Cyber Security internship.

REQUIREMENTS
    pip install scapy
    Must be run with administrator/root privileges:
        Linux/Mac:  sudo python3 network_sniffer.py
        Windows:    run terminal "as Administrator" (Npcap must be installed)

USAGE EXAMPLES
    sudo python3 network_sniffer.py
    sudo python3 network_sniffer.py -i eth0 -c 50
    sudo python3 network_sniffer.py -f "tcp port 80"
    sudo python3 network_sniffer.py -f udp -o capture.pcap
"""

import argparse
import datetime
import sys

try:
    from scapy.all import sniff, wrpcap, conf
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
except ImportError:
    print("[!] Scapy is not installed.")
    print("    Install it with:  pip install scapy")
    sys.exit(1)


# Keep a running list if the user wants to save to a pcap file
captured_packets = []


def safe_payload_preview(raw_bytes, max_len=60):
    """
    Convert raw payload bytes into a safe, printable preview string.
    Non-printable bytes are shown as '.' so the output never breaks
    the terminal or leaks binary garbage.
    """
    if not raw_bytes:
        return ""
    snippet = raw_bytes[:max_len]
    printable = "".join(
        chr(b) if 32 <= b <= 126 else "." for b in snippet
    )
    suffix = "..." if len(raw_bytes) > max_len else ""
    return printable + suffix


def describe_packet(packet):
    """
    Build a one-line (plus optional payload line) human-readable
    description of a captured packet.
    """
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    if IP not in packet:
        # Not an IP packet (e.g. ARP) — show minimal info instead of skipping it
        summary = packet.summary()
        return f"[{timestamp}] NON-IP FRAME | {summary}"

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    proto_name = "OTHER"
    extra = ""
    payload_bytes = b""

    if TCP in packet:
        proto_name = "TCP"
        tcp_layer = packet[TCP]
        extra = f"{src_ip}:{tcp_layer.sport} -> {dst_ip}:{tcp_layer.dport} [flags={tcp_layer.flags}]"
        if packet[TCP].payload:
            payload_bytes = bytes(packet[TCP].payload)

    elif UDP in packet:
        proto_name = "UDP"
        udp_layer = packet[UDP]
        extra = f"{src_ip}:{udp_layer.sport} -> {dst_ip}:{udp_layer.dport}"
        if packet[UDP].payload:
            payload_bytes = bytes(packet[UDP].payload)

    elif ICMP in packet:
        proto_name = "ICMP"
        icmp_layer = packet[ICMP]
        extra = f"{src_ip} -> {dst_ip} [type={icmp_layer.type} code={icmp_layer.code}]"

    else:
        extra = f"{src_ip} -> {dst_ip}"

    line = f"[{timestamp}] {proto_name:5} | {extra} | len={len(packet)}"

    if payload_bytes:
        preview = safe_payload_preview(payload_bytes)
        if preview:
            line += f"\n            payload: {preview}"

    return line


def handle_packet(packet, verbose=True):
    captured_packets.append(packet)
    if verbose:
        print(describe_packet(packet))


def main():
    parser = argparse.ArgumentParser(
        description="CodeAlpha Task 1 - Basic Network Sniffer (Scapy-based)"
    )
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Network interface to sniff on (default: Scapy's default interface)"
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="Number of packets to capture (0 = capture indefinitely until Ctrl+C)"
    )
    parser.add_argument(
        "-f", "--filter", default=None,
        help="BPF filter, e.g. 'tcp', 'udp', 'icmp', 'tcp port 80', 'host 192.168.1.5'"
    )
    parser.add_argument(
        "-o", "--output", default=None,
        help="Optional path to save captured packets as a .pcap file (open later in Wireshark)"
    )
    args = parser.parse_args()

    print("=" * 70)
    print(" CodeAlpha Task 1 - Basic Network Sniffer")
    print("=" * 70)
    print(f" Interface : {args.interface or conf.iface}")
    print(f" Filter    : {args.filter or '(none - capturing all traffic)'}")
    print(f" Count     : {'unlimited (Ctrl+C to stop)' if args.count == 0 else args.count}")
    print(f" Save to   : {args.output or '(not saving)'}")
    print("=" * 70)
    print(" NOTE: Only sniff networks/devices you own or are authorized to test.")
    print("=" * 70)

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=handle_packet,
            count=args.count,
            store=False,
        )
    except PermissionError:
        print("\n[!] Permission denied. Try running with sudo (Linux/Mac) "
              "or as Administrator (Windows).")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")
    finally:
        if args.output and captured_packets:
            wrpcap(args.output, captured_packets)
            print(f"[*] Saved {len(captured_packets)} packets to {args.output}")
        print(f"[*] Total packets captured: {len(captured_packets)}")


if __name__ == "__main__":
    main()
