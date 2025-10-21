#Importing Libraries

from scapy.all import sniff, IP, TCP, UDP
import csv
from datetime import datetime
import os

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
    sniff(prn=process_packet, store=False) #it will not store packets in memory