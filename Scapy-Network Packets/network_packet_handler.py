from scapy.all import sniff, IP, ICMP, TCP, sr1, send

def packet_callback(packet):
    print(packet.show())

def sniff_packets():
    print("Sniffing packets...")
    sniff(prn=packet_callback, count=10)
    print("Finished sniffing.")

def send_icmp_packet(destination):
    print(f"Sending ICMP packet to {destination}...")
    packet = IP(dst=destination) / ICMP()
    response = sr1(packet, timeout=1)
    
    if response:
        print("Received response:")
        response.show()
    else:
        print("No response received.")

def send_tcp_packet(destination, port):
    print(f"Sending TCP packet to {destination} on port {port}...")
    packet = IP(dst=destination) / TCP(dport=port)
    send(packet)
    print("Packet sent.")

if __name__ == "__main__":
    sniff_packets()
    
    send_icmp_packet("8.8.8.8")

    send_tcp_packet("example.com", 80)