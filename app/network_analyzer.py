import os
import pandas as pd
from scapy.all import rdpcap, Ether, ARP, BOOTP, DHCP, IP, TCP, UDP, ICMP, DNS, SNMP, Dot11
from scapy.layers.http import HTTPRequest

def scan_network(file_path):
    # Read pcap file and process packets to extract network traffic summary
    packets = rdpcap(file_path)
    processed_data = process_packet(packets)
    output_directory = os.path.join(os.getcwd(), f'{os.path.splitext(os.path.basename(file_path))[0]}_report')
    save_result(processed_data, output_directory)

def process_packet(packets):
    # Initialize data dictionary to store network traffic summary
    data = {
        'Management Frames': [],
        'Control Frames': [],
        'HTTP Requests': [],
        'DNS Queries': [],
        'TCP Packets': [],
        'FTP Packets': [],
        'UDP Packets': [],
        'ARP Packets': [],
        'ICMP Packets': [],
        'DHCP Packets': [],
        'SNMP Packets': []
    }

    # Process each packet in the pcap file and extract relevant information
    for packet in packets:
        # Ethernet Frames and encapsulated protocols
        if packet.haslayer(Ether):
            if packet.haslayer(ARP):
                arp_data = {
                    'Source IP': packet[ARP].psrc,
                    'Destination IP': packet[ARP].pdst,
                    'Source MAC': packet[ARP].hwsrc,
                    'Destination MAC': packet[ARP].hwdst,
                    'Operation': packet[ARP].op,
                    'Summary': packet.summary()
                }
                data['ARP Packets'].append(arp_data)
            elif packet.haslayer(DHCP):
                dhcp_data = {
                    'Source MAC': packet[Ether].src,
                    'Destination MAC': packet[Ether].dst,
                    'Transaction ID': packet[DHCP].xid,
                    'Client IP': packet[BOOTP].ciaddr,
                    'Your IP': packet[BOOTP].yiaddr,
                    'Server IP': packet[BOOTP].siaddr,
                    'Gateway IP': packet[BOOTP].giaddr,
                    'Summary': packet.summary()
                }
                data['DHCP Packets'].append(dhcp_data)

        # HTTP Requests
        if packet.haslayer(IP):
            # TCP Packets
            if packet.haslayer(TCP):
                tcp_data = {
                    'Source IP': packet[IP].src,
                    'Destination IP': packet[IP].dst,
                    'Source Port': packet[TCP].sport,
                    'Destination Port': packet[TCP].dport,
                    'Flags': packet[TCP].flags,
                    'Summary': packet.summary()
                }
                data['TCP Packets'].append(tcp_data)

                # FTP Packets
                if packet[TCP].dport == 21 or packet[TCP].sport == 21:
                    ftp_data = {
                        'Source IP': packet[IP].src,
                        'Destination IP': packet[IP].dst,
                        'Source Port': packet[TCP].sport,
                        'Destination Port': packet[TCP].dport,
                        'Flags': packet[TCP].flags,
                        'Summary': packet.summary()
                    }
                    data['FTP Packets'].append(ftp_data)

            # UDP Packets
            elif packet.haslayer(UDP):
                if not packet.haslayer(DNS):
                    udp_data = {
                        'Source IP': packet[IP].src,
                        'Destination IP': packet[IP].dst,
                        'Source Port': packet[UDP].sport,
                        'Destination Port': packet[UDP].dport,
                        'Summary': packet.summary()
                    }
                    data['UDP Packets'].append(udp_data)

                # DNS Queries
                if packet.haslayer(DNS):
                    dns_data = {
                        'Source IP': packet[IP].src,
                        'Destination IP': packet[IP].dst,
                        'Query Name': packet[DNS].qd.qname.decode() if packet[DNS].qd else None,
                        'Summary': packet.summary()
                    }
                    data['DNS Queries'].append(dns_data)

            # ICMP Packets
            elif packet.haslayer(ICMP):
                icmp_data = {
                    'Source IP': packet[IP].src,
                    'Destination IP': packet[IP].dst,
                    'Type': packet[ICMP].type,
                    'Code': packet[ICMP].code,
                    'Summary': packet.summary()
                }
                data['ICMP Packets'].append(icmp_data)

        # Dot11 Frames (Wireless Frames)
        if packet.haslayer(Dot11):
            frame_data = {
                'Frame Type': 'Data',
                'Subtype': packet.subtype if hasattr(packet, 'subtype') else 'Unknown',
                'Source MAC': packet.addr2 if hasattr(packet, 'addr2') else 'Unknown',
                'Destination MAC': packet.addr1 if hasattr(packet, 'addr1') else 'Unknown',
                'Summary': packet.summary()
            }

            # Determine frame type based on Dot11 subtype
            if packet.type == 0:
                frame_data['Frame Type'] = 'Management'
                data['Management Frames'].append(frame_data)
            elif packet.type == 1:
                frame_data['Frame Type'] = 'Control'
                data['Control Frames'].append(frame_data)

        # SNMP Packets
        if packet.haslayer(SNMP):
            snmp_data = {
                'Source IP': packet[IP].src,
                'Destination IP': packet[IP].dst,
                'Community': packet[SNMP].community.decode(),
                'PDU Type': packet[SNMP].PDU,
                'Summary': packet.summary()
            }
            data['SNMP Packets'].append(snmp_data)

    return data

def save_result(protocols, output_directory):
    # Create output directory if it doesn't exist
    os.makedirs(output_directory, exist_ok=True)
    excel_path = os.path.join(output_directory, 'network_traffic_summary.xlsx')
    with pd.ExcelWriter(excel_path) as writer:
        # Save each protocol data to separate sheets in Excel file and CSV files
        for name, entries in protocols.items():
            if entries:
                df = pd.DataFrame(entries)
                df.to_excel(writer, sheet_name=name, index=False)
                df.to_csv(os.path.join(output_directory, f'{name.lower().replace(" ", "_")}.csv'), index=False)

    print(f"[SUCCESS] Network traffic summary saved to '{os.path.basename(output_directory)}'.")
