import os
import pandas as pd
from scapy.all import rdpcap, Ether, ARP, DHCP, BOOTP, IP, TCP, UDP, ICMP, Dot11, DNS, SNMP
from scapy.layers.http import HTTPRequest
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

def scan_network(file_path):
    try:
        # Read pcap file and process packets to extract network traffic summary
        packets = rdpcap(file_path)
        processed_data = process_packet(packets)
        output_directory = os.path.join(os.getcwd(), f'{os.path.splitext(os.path.basename(file_path))[0]}_report')
        save_result(processed_data, output_directory, file_path)
    except Exception as e:
        print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Error occurred while scanning {os.path.basename(file_path)}: {e}')

def process_packet(packets):
    # Initialize data dictionary to store network traffic summary
    data = {
        'Management Frames': [],
        'Control Frames': [],
        'HTTP Requests': [],
        'DNS Queries': [],
        'ARP Packets': [],
        'DHCP Packets': [],
        'TCP Packets': [],
        'FTP Packets': [],
        'UDP Packets': [],
        'ICMP Packets': [],
        'SNMP Packets': []
    }

    # Process each packet in the pcap file and extract relevant information
    for packet in packets:
        try:
            # Ethernet Frames
            if packet.haslayer(Ether):
                # ARP Packets
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
                    # DHCP Packets
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

            # IP Layer
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
                    if packet[TCP].dport in [20, 21] or packet[TCP].sport in [20, 21]:
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
                    if packet.haslayer(DNS):
                        dns_data = {
                            'Source IP': packet[IP].src,
                            'Destination IP': packet[IP].dst,
                            'Query Name': packet[DNS].qd.qname.decode() if hasattr(packet[DNS], 'qd') and packet[DNS].qd else None,
                            'Summary': packet.summary()
                        }
                        data['DNS Queries'].append(dns_data)
                    else:
                        udp_data = {
                            'Source IP': packet[IP].src,
                            'Destination IP': packet[IP].dst,
                            'Source Port': packet[UDP].sport,
                            'Destination Port': packet[UDP].dport,
                            'Summary': packet.summary()
                        }
                        data['UDP Packets'].append(udp_data)

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

                # Determine frame type based on the type field
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

            # HTTP Requests
            if packet.haslayer(HTTPRequest):
                http_data = {
                    'Source IP': packet[IP].src,
                    'Destination IP': packet[IP].dst,
                    'Method': packet[HTTPRequest].Method.decode(),
                    'Host': packet[HTTPRequest].Host.decode(),
                    'Path': packet[HTTPRequest].Path.decode(),
                    'Summary': packet.summary()
                }
                data['HTTP Requests'].append(http_data)
        except Exception as e:
            print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Error occurred while processing {packet.summary()}: {e}')
    return data

def save_result(protocols, output_directory, file_path):
    # Create output directory if it doesn't exist
    os.makedirs(output_directory, exist_ok=True)
    excel_path = os.path.join(output_directory, 'network_traffic_summary.xlsx')
    with pd.ExcelWriter(excel_path) as writer:
        # Save each protocol data to separate sheets in Excel file and CSV files
        for name, entries in protocols.items():
            if entries:
                print(f'{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {len(entries)} {name} captured in {os.path.basename(file_path)}')
                df = pd.DataFrame(entries)
                df.to_excel(writer, sheet_name=name, index=False)
                df.to_csv(os.path.join(output_directory, f'{name.lower().replace(" ", "_")}.csv'), index=False)
            else:
                print(f'{Fore.YELLOW}[FAILURE]{Style.RESET_ALL} 0 {name} captured in {os.path.basename(file_path)}')