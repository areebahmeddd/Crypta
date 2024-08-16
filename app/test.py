from scapy.all import rdpcap

packets = rdpcap(r'logs\network\evidence-defcon2010.pcap')

with open('network_log.txt', 'w') as file:
    for packet in packets:
        file.write(packet.summary() + '\n')
