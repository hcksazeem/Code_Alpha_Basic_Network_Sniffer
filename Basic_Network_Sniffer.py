import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap
from datetime import datetime
import csv
from termcolor import colored

packets = []

def process_packet(packet):
    packets.append(packet)  # For saving to pcap
    time = datetime.now().strftime('%H:%M:%S')

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        print(colored(f"\n[{time}] Packet captured:", 'green'))
        print(f"   ➤ Source IP      : {src_ip}")
        print(f"   ➤ Destination IP : {dst_ip}")

        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print("   ➤ Protocol       : TCP")
            print(f"   ➤ Src Port       : {sport}")
            print(f"   ➤ Dst Port       : {dport}")

        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print("   ➤ Protocol       : UDP")
            print(f"   ➤ Src Port       : {sport}")
            print(f"   ➤ Dst Port       : {dport}")

        elif packet.haslayer(ICMP):
            print("   ➤ Protocol       : ICMP")

        if Raw in packet and args.show_payload:
            data = packet[Raw].load
            print("   ➤ Payload:")
            try:
                print(f"      {data.decode('utf-8', errors='ignore')}")
            except:
                print("      (Binary data)")

        print("-" * 60)

        # Save to CSV
        with open(args.output_csv, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([time, src_ip, dst_ip, proto])

# Argument Parser
parser = argparse.ArgumentParser(description="Advanced Python Packet Sniffer")
parser.add_argument("-i", "--interface", help="Network interface", required=False, default=None)
parser.add_argument("-c", "--count", help="Number of packets to capture", type=int, default=0)
parser.add_argument("-f", "--filter", help="BPF Filter (e.g. 'tcp')", default="")
parser.add_argument("-pcap", "--output_pcap", help="Output PCAP file", default="capture.pcap")
parser.add_argument("-csv", "--output_csv", help="Output CSV file", default="capture.csv")
parser.add_argument("--show-payload", action="store_true", help="Show packet payload")

args = parser.parse_args()

print(colored("🔍 Starting enhanced packet sniffer... Press Ctrl+C to stop.", 'cyan'))

# CSV header init
with open(args.output_csv, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Time', 'Source IP', 'Destination IP', 'Protocol'])

# Start sniffing
sniff(
    iface=args.interface,
    prn=process_packet,
    store=False,
    count=args.count,
    filter=args.filter
)

# Save packets to PCAP
if packets:
    wrpcap(args.output_pcap, packets)
    print(colored(f"\n✅ Packets saved to {args.output_pcap}", 'yellow'))
