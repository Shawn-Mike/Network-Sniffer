# Packet Sniffer in C

A lightweight packet capture and analysis tool written in C using **libpcap**.  
It supports **BPF filters**, protocol decoding (Ethernet, IPv4, TCP, UDP, ICMP, DNS),  
and optional `.pcap` logging for use with Wireshark or other analyzers.

---

## Features
- Capture live network traffic from a specified interface
- Apply **Berkeley Packet Filter (BPF)** expressions (like `tcp port 443`)
- Decode:
  - Ethernet headers
  - IPv4 headers
  - TCP headers (all flags including NS, CWR, ECE)
  - UDP headers
  - ICMP headers
  - DNS headers (basic parsing for port 53 traffic)
- Optional output to `.pcap` for later analysis
- Displays source/destination IPs, ports, and protocol details in real time

---

## Requirements
- **libpcap** development headers  
  On Debian/Ubuntu:
  ```bash
  sudo apt install libpcap-dev
