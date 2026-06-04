from scapy.all import sniff, Raw
def catch(packet):
    if packet.haslayer(Raw):
        data=packet[Raw].load.decoe(
            errors="ignore"
        )

    if len(data)>10:
        print(data)

print("Sniffer Started on wifi....")

sniff(
    iface="Wi-Fi",
    filter="tcp port 80",
    prn=catch,
    store=False
)