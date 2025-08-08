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
  `sudo apt install libpcap-dev`

## BUILD
`gcc -Wall -Wextra -O2 sniffer.c -o sniffer -lpcap`

## USAGE
`sudo ./pcap_dumper -i <interface> [-f "<filter>"] [-o <output_file.pcap>]`

### Arguments
| Flag | Description                                           |
| ---- | ----------------------------------------------------- |
| `-i` | **(Required)** Interface name (e.g., `eth0`, `wlan0`) |
| `-f` | Optional BPF filter string (e.g., `"tcp port 443"`)   |
| `-o` | Optional `.pcap` output file for saving captures      |


Examples:
1. Capture all packets on eth0:
`sudo ./pcap_dumper -i eth0`
2. Capture only TCP port 443 traffic:
`sudo ./sniffer -i eth0 -f "tcp port 443"`
3. Capture TCP port 443 and save to capture.pcap:
`sudo ./sniffer -i eth0 -f "tcp port 443" -o capture.pcap`


## Example Output
Packet captured: Length: 54 bytes
Cap Length: 54
Ether Type: 0x0800
From: 192.168.1.100
To: 142.250.190.78
Protocol: 6
TCP Src Port: 51514
TCP Dst Port: 443
Flags: ACK 



  
