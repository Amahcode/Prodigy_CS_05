from scapy.all import sniff, TCP, IP, UDP, ICMP, Raw 
from scapy.layers.http import HTTPRequest, HTTPResponse

def packet_sniffer(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip} -> Destination IP: {dst_ip}")

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"Source Port: {src_port} -> Destination Port: {dst_port}")

    if packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        print(f"Source Port: {src_port} -> Destination Port: {dst_port}")

    if packet.haslayer(ICMP):
        print("ICMP Packet")

    if packet.haslayer(Raw):
        payload = packet[Raw].load
        print(f"Payload: {payload}")

    if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
        print("HTTP Request/Response")

    print("--------------------------------------------------------")

sniff(prn=packet_sniffer, store=False)

