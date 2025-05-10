from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, wrpcap, Packet
from datetime import datetime
from collections import defaultdict, Counter
from termcolor import colored
import sys
import signal

# === Global State ===
packet_count = 0
protocol_stats = Counter()
suspicious_ips = defaultdict(int)
packet_list = []
start_time = datetime.now()

# === Parameters ===
PCAP_FILE = "captured_traffic.pcap"
SUSPICIOUS_PORTS = {4444, 5555, 31337, 1337, 6666, 8081, 23, 2323}  # Common for backdoors or telnet
MAX_PACKETS_PER_IP = 100  # Trigger alert on scanning behavior

def analyze_packet(packet: Packet):
    global packet_count
    packet_count += 1
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    alert = None

    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto_name = "OTHER"
        summary = ""

        # TCP
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            proto_name = "TCP"
            summary = f"TCP | {ip_src}:{sport} -> {ip_dst}:{dport} | Flags: {flags}"
            if dport in SUSPICIOUS_PORTS:
                alert = f"⚠️ Suspicious port {dport} accessed!"

        # UDP
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            proto_name = "UDP"
            summary = f"UDP | {ip_src}:{sport} -> {ip_dst}:{dport}"

        # ICMP
        elif ICMP in packet:
            proto_name = "ICMP"
            summary = f"ICMP | {ip_src} -> {ip_dst} | Type: {packet[ICMP].type}"

        # Other IP protocols
        else:
            summary = f"IP | {ip_src} -> {ip_dst}"

        # Record statistics
        protocol_stats[proto_name] += 1
        suspicious_ips[ip_src] += 1

        # Print live output
        print(colored(f"[{timestamp}] {summary}", "green"))
        if alert:
            print(colored(f"  [!] ALERT: {alert}", "red"))

        # DNS detection
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns_qname = packet[DNSQR].qname.decode(errors='ignore')
            print(colored(f"  DNS Query: {dns_qname}", "magenta"))
            if len(dns_qname) > 50 and dns_qname.count('.') > 3:
                print(colored("  [!] Suspicious DNS length — possible tunneling!", "yellow"))

        # Raw Payload (Optional)
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            print(colored("  Payload (truncated):", "white"))
            print(raw_data[:80])  # Limit output

        print("-" * 80)

        # Save packet for export
        packet_list.append(packet)

        # Anomaly: too many packets from one IP (e.g., scanner)
        if suspicious_ips[ip_src] > MAX_PACKETS_PER_IP:
            print(colored(f"  [!] High volume from {ip_src} — Possible scanning behavior!", "red"))

def save_summary():
    print(colored("\n📦 Saving session summary...\n", "cyan"))
    print(f"Total packets captured: {packet_count}")
    print("Protocol counts:")
    for proto, count in protocol_stats.items():
        print(f"  {proto}: {count}")

    top_talkers = sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True)[:5]
    print("\nTop source IPs:")
    for ip, count in top_talkers:
        print(f"  {ip} -> {count} packets")

    print(f"\nSaving to PCAP file: {PCAP_FILE}")
    wrpcap(PCAP_FILE, packet_list)
    print(colored("✔ Capture saved successfully.\n", "green"))

def start_sniffing(interface=None, bpf_filter=None):
    def signal_handler(sig, frame):
        print(colored("\n[!] Ctrl+C detected, shutting down...", "red"))
        save_summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    print(colored("🔥 Starting packet analyzer...", "blue"))
    print(f"Started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    if interface:
        print(f"Sniffing on interface: {interface}")
    if bpf_filter:
        print(f"Using BPF Filter: {bpf_filter}")

    sniff(iface=interface, filter=bpf_filter, prn=analyze_packet, store=False)

# ====== Run Analyzer ======
# Choose an interface like 'eth0', 'wlan0', or 'en0' (Mac)
# Optional filters: 'tcp', 'udp', 'port 53', etc.
start_sniffing(interface='en0', bpf_filter=None)

