from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        if TCP in packet:
            payload = packet[TCP].payload
            proto_name = 'TCP'
        elif UDP in packet:
            payload = packet[UDP].payload
            proto_name = 'UDP'
        else:
            payload = packet[IP].payload
            proto_name = 'Other'

        print(f"Source: {ip_src}")
        print(f"Destination: {ip_dst}")
        print(f"Protocol: {proto_name}")
        print(f"Payload: {payload}")
        print("-" * 50)

def start_sniffing(interface=None):
    sniff(iface=interface, prn=packet_callback, store=False)

# Example usage:
# You can specify the network interface to sniff on, e.g., 'eth0', 'wlan0' etc.
start_sniffing(interface='en0')
