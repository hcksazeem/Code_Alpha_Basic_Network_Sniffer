# Code_Alpha_Basic_Network_Sniffer
# 🔐 Advanced Python Packet Sniffer

A powerful, flexible, and beginner-friendly packet sniffer written in Python using the Scapy library. This tool is designed for students, ethical hackers, cybersecurity learners, and network engineers to analyze and monitor real-time network traffic.

---

## 📦 Features

- ✅ Captures and displays real-time network packets
- ✅ Supports TCP, UDP, and ICMP protocols
- ✅ Shows source and destination IPs and ports
- ✅ Optional payload decoding with `--show-payload`
- ✅ Saves logs to `.csv` and `.pcap` (Wireshark-compatible)
- ✅ Color-coded terminal output for better readability
- ✅ Fully command-line controlled (no hardcoded settings)

--

## 🖥️ Screenshot

> _(Add a screenshot here of the terminal showing captured packets)_

---

## 🚀 Usage

```bash
# Basic usage
sudo python3 sniffer.py

# Capture 20 TCP packets on eth0
sudo python3 sniffer.py -i eth0 -f "tcp" -c 20

# Capture UDP packets and show payloads
sudo python3 sniffer.py -f "udp" --show-payload

# Save output to custom files
sudo python3 sniffer.py -pcap traffic.pcap -csv output.csv

