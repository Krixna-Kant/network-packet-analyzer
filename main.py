#Importing Libraries

from scapy.all import sniff, IP, TCP, UDP
import csv
from datetime import datetime
import os
from util import build_filter

#Setting up Log File
LOG_FILE = "data/packet_log.csv"
os.makedirs("data", exist_ok=True)

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Length"])
        
#Packet Processing Function
def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other"
        
        row = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ip_layer.src,
            ip_layer.dst,
            protocol,
            len(packet)
        ]
        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(row)
        
        print(f"[{row[0]}] {row[1]} -> {row[2]} ({row[3]}, {row[4]} bytes)")

if __name__ == "__main__":
    print("Starting packet capture... Press Ctrl+C to stop.")
    
    #Optional Filters for Users
    proto = input("Enter protocol to filter (tcp/udp) or leave blank for all: ").strip() or None
    src = input("Enter source IP to filter or leave blank for all: ").strip() or None
    dst = input("Enter destination IP to filter or leave blank for all: ").strip() or None
    port = input("Enter port to filter or leave blank for all: ").strip() or None
    port = int(port) if port else None
    
    #Filter Expression
    bpf_filter = build_filter(protocol=proto, src_ip=src, dst_ip=dst, port=port)
    if bpf_filter:
        print(f"Applying filter: {bpf_filter}")
    else:
        print("No filter applied, capturing all packets.")
        
    sniff(prn=process_packet, store=False, filter=bpf_filter) #it will not store packets in memory