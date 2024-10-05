from scapy.all import sniff, IP, ICMP, TCP, sr1, send
from scapy.utils import wrpcap, rdpcap

def packet_callback(packet):
    print(packet.show())

def sniff_packets(filter=None, file_name=None):
    print("Sniffing packets...")
    packets = sniff(filter=filter, prn=packet_callback, count=10)
    if file_name:
        wrpcap(file_name, packets)
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

def analyze_packets(file_name):
    packets = rdpcap(file_name)
    for packet in packets:
        packet_callback(packet)

def main():
    while True:
        print("1. Sniff Packets")
        print("2. Send ICMP Packet")
        print("3. Send TCP Packet")
        print("4. Analyze Packets from File")
        print("5. Exit")
        choice = input("Enter your choice: ")
        
        if choice == '1':
            filter = input("Enter filter (or press enter to skip): ")
            file_name = input("Enter file name to save packets (or press enter to skip): ")
            sniff_packets(filter=filter if filter else None, file_name=file_name if file_name else None)
        elif choice == '2':
            destination = input("Enter destination IP: ")
            send_icmp_packet(destination)
        elif choice == '3':
            destination = input("Enter destination IP: ")
            port = int(input("Enter port number: "))
            send_tcp_packet(destination, port)
        elif choice == '4':
            file_name = input("Enter file name: ")
            analyze_packets(file_name)
        elif choice == '5':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()