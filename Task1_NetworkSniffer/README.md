# CodeAlpha_NetworkSniffer

A basic network packet sniffer built in Python using **Scapy**, developed as part of the **CodeAlpha Cyber Security Internship** (Task 1).

## What it does

- Captures live packets on a chosen network interface
- Parses Ethernet / IP / TCP / UDP / ICMP headers
- Displays:
  - Timestamp
  - Protocol (TCP / UDP / ICMP / other)
  - Source IP:port → Destination IP:port
  - TCP flags (for TCP packets)
  - A safe, printable preview of the payload
- Supports BPF-style filters (e.g. `tcp`, `udp port 53`, `host 192.168.1.5`)
- Can save captured packets to a `.pcap` file for later analysis in Wireshark

## ⚠️ Legal & Ethical Notice

Only run this on networks and devices **you own or have explicit permission to monitor**. Capturing traffic on networks without authorization is illegal in most jurisdictions. This project is for educational purposes only.

## Requirements

- Python 3.8+
- [Scapy](https://scapy.net/)
- **Npcap** (Windows only) — required by Scapy for packet capture: https://npcap.com/
- Administrator/root privileges (raw packet capture requires elevated access)

Install dependencies:

```bash
pip install scapy
```

## Usage

```bash
# Capture all traffic on the default interface (Ctrl+C to stop)
sudo python3 network_sniffer.py

# Capture 50 packets on a specific interface
sudo python3 network_sniffer.py -i eth0 -c 50

# Capture only HTTP traffic
sudo python3 network_sniffer.py -f "tcp port 80"

# Capture UDP traffic and save it to a pcap file
sudo python3 network_sniffer.py -f udp -o capture.pcap
```

> On Windows, run your terminal **as Administrator** instead of using `sudo`.

## Example Output

```
[14:32:07] TCP   | 192.168.1.10:52344 -> 142.250.premise:443 [flags=PA] | len=1420
            payload: ......GET /search?q=network+sniffer HTTP/1.1..Host:...
[14:32:08] UDP   | 192.168.1.10:5353 -> 224.0.0.251:5353 | len=98
[14:32:09] ICMP  | 192.168.1.10 -> 8.8.8.8 [type=8 code=0] | len=98
```

## How it works (short explanation for the write-up / video)

1. `scapy.sniff()` opens a raw socket on the chosen interface and receives every packet that crosses it (or every packet matching the BPF filter, if one is set).
2. Each packet is passed to a callback (`handle_packet`) as it arrives.
3. The callback drills into the packet's layers — `IP`, then `TCP`/`UDP`/`ICMP` — to pull out addressing and protocol details.
4. Payload bytes are converted into a printable preview so binary data doesn't corrupt terminal output.
5. Optionally, all captured packets are written to disk in `.pcap` format, the standard format Wireshark and other tools use.

## Disclaimer

Built for the CodeAlpha Cyber Security Internship, Task 1: Basic Network Sniffer.
