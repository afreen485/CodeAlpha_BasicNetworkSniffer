from scapy.all import sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Raw


def process_packet(packet):

    print("\n" + "="*80)

    # Ethernet Layer
    if packet.haslayer(Ether):
        print("[ETHERNET]")
        print("Source MAC      :", packet[Ether].src)
        print("Destination MAC :", packet[Ether].dst)

    # IPv4 Layer
    if packet.haslayer(IP):
        print("\n[IP]")
        print("Source IP       :", packet[IP].src)
        print("Destination IP  :", packet[IP].dst)
        print("Protocol Number :", packet[IP].proto)

    # IPv6 Layer
    if packet.haslayer(IPv6):
        print("\n[IPv6]")
        print("Source IP       :", packet[IPv6].src)
        print("Destination IP  :", packet[IPv6].dst)
        print("Next Header     :", packet[IPv6].nh)

    # TCP Layer
    if packet.haslayer(TCP):
        print("\n[TCP]")
        print("Source Port     :", packet[TCP].sport)
        print("Destination Port:", packet[TCP].dport)
        print("Flags           :", packet[TCP].flags)

    # UDP Layer
    if packet.haslayer(UDP):
        print("\n[UDP]")
        print("Source Port     :", packet[UDP].sport)
        print("Destination Port:", packet[UDP].dport)

    # DNS Query Detection
    if packet.haslayer(DNSQR):
        try:
            website = packet[DNSQR].qname.decode().rstrip('.')
            print("\n[DNS QUERY DETECTED]")
            print("Website         :", website)
        except:
            pass

    # DNS Response Detection
    if packet.haslayer(DNSRR):
        try:
            print("\n[DNS RESPONSE]")
            print("Domain          :", packet[DNSRR].rrname.decode())
            print("Resolved IP     :", packet[DNSRR].rdata)
        except:
            pass

    # Payload
    if packet.haslayer(Raw):
        print("\n[PAYLOAD]")
        try:
            print(packet[Raw].load[:100].decode('utf-8', errors='ignore'))
        except:
            print(packet[Raw].load[:100])

    print("\nPacket Length   :", len(packet), "bytes")

    print("\n[SUMMARY]")
    print(packet.summary())


print("Network Sniffer Started...")
print("Visit websites like Google, YouTube, GitHub")
print("Press CTRL+C to stop")

sniff(prn=process_packet, store=False)