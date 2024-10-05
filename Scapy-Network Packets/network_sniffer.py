from scapy.all import IP, ICMP, sr1

packet = IP(dst="8.8.8.8") / ICMP()

response = sr1(packet, timeout=1)

if response:
    response.show()
else:
    print("No response")