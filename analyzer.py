from datetime import datetime, timedelta
from collections import defaultdict
import csv
import os

SUSPICIOUS_LOG = "data/suspicious_log.csv"

os.makedirs("data", exist_ok=True)
if not os.path.exists(SUSPICIOUS_LOG):
    with open(SUSPICIOUS_LOG, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Reason"])
        
packet_history = defaultdict(list)

def analyze_packet(src_ip, dst_ip, protocol, length):
    now = datetime.now()
    packet_history[src_ip].append(now)
    
    packet_history[src_ip] = [t for t in packet_history[src_ip] if now - t < timedelta(seconds=10)]
    count_recent = len(packet_history[src_ip])
    
    #Rule1: Too many packets in 10s -> Possible DoS
    if count_recent > 50:
        log_suspicious(src_ip, dst_ip, protocol, "High packet rate(possible DoS)")
        return True
    
    #Rule2: Very Large Packet
    if length > 1500:
        log_suspicious(src_ip, dst_ip, protocol, "Large packet size")
        return True
    
    #Rule3: Excessive Connections to same dst_ip
    same_dest = sum(1 for t in packet_history[src_ip] if now - t < timedelta(seconds=10))
    if same_dest > 30:
        log_suspicious(src_ip, dst_ip, protocol, "Excessive connections to same destination")
        return True
    
    return False

def log_suspicious(src_ip, dst_ip, protocol, reason):
    with open(SUSPICIOUS_LOG, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), src_ip, dst_ip, protocol, reason])
    print(f"[SUSPICIOUS] {src_ip} -> {dst_ip} ({protocol}): {reason}")