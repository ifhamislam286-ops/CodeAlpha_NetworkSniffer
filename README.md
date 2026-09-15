# CodeAlpha_NetworkSniffer

A Python-based Network Packet Sniffer for monitoring and analyzing authorized network traffic in real time. Built with Scapy for cybersecurity learning, network analysis, and ethical security testing in controlled environments.

## Features

- Captures IPv4 network packets using Scapy
- Displays timestamp, source IP, destination IP, and protocol
- Shows TCP/UDP source and destination ports
- Displays packet length
- Provides a limited printable payload preview
- Handles permission errors and graceful shutdown

## Requirements

- Python 3
- Scapy
- Appropriate packet-capture privileges

Install the dependency:

```bash
pip install -r requirements.txt
```

## Usage

Run only on a machine or network you own or are explicitly authorized to monitor:

```bash
sudo python3 network_sniffer.py
```

Press `CTRL+C` to stop the capture.

## Example Output

```text
[12:30:15] 192.168.1.10:54321 -> 142.250.72.14:443 | TCP   | Length: 74    | Payload: -
[12:30:16] 192.168.1.10:- -> 8.8.8.8:- | ICMP  | Length: 98    | Payload: -
```

## Project Purpose

This project was created as part of the **CodeAlpha Cyber Security Internship – Task 1: Basic Network Sniffer**.

The project is intended for educational use, cybersecurity learning, and authorized network analysis.

## Responsible Use

Only capture traffic on systems and networks where you have permission. Network packets can contain sensitive information, so do not inspect or collect traffic belonging to others without authorization.
