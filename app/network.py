import os
import json
from scapy.all import rdpcap, Ether, ARP, DHCP, BOOTP, IP, TCP, UDP, ICMP, Dot11, DNS, SNMP
from scapy.layers.http import HTTPRequest
from colorama import init, Fore, Style

# Initialize colorama for colored output in console
init(autoreset=True)

def scan_network(file_path):
    try:
        # Read the pcap file using scapy and extract packets from it
        captured_packets = rdpcap(file_path)
        # Process the packets and serialize the network traffic summary into JSON format
        network_summary = process_packet(captured_packets)
        formatted_data = serialize_network(network_summary)
        return formatted_data
    except Exception as e:
        print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Error occurred while scanning {os.path.basename(file_path)}: {e}')

def process_packet(captured_packets):
    # Initialize network_data dictionary to store network traffic summary
    network_data = {
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
    for packet in captured_packets:
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
                    network_data['ARP Packets'].append(arp_data)

                # DHCP Packets
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
                    network_data['DHCP Packets'].append(dhcp_data)

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
                    network_data['TCP Packets'].append(tcp_data)

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
                        network_data['FTP Packets'].append(ftp_data)

                # UDP Packets
                elif packet.haslayer(UDP):
                    if packet.haslayer(DNS):
                        dns_data = {
                            'Source IP': packet[IP].src,
                            'Destination IP': packet[IP].dst,
                            'Query Name': packet[DNS].qd.qname.decode()
                                if hasattr(packet[DNS], 'qd') and packet[DNS].qd else None,
                            'Summary': packet.summary()
                        }
                        network_data['DNS Queries'].append(dns_data)
                    else:
                        udp_data = {
                            'Source IP': packet[IP].src,
                            'Destination IP': packet[IP].dst,
                            'Source Port': packet[UDP].sport,
                            'Destination Port': packet[UDP].dport,
                            'Summary': packet.summary()
                        }
                        network_data['UDP Packets'].append(udp_data)

                # ICMP Packets
                elif packet.haslayer(ICMP):
                    icmp_data = {
                        'Source IP': packet[IP].src,
                        'Destination IP': packet[IP].dst,
                        'Type': packet[ICMP].type,
                        'Code': packet[ICMP].code,
                        'Summary': packet.summary()
                    }
                    network_data['ICMP Packets'].append(icmp_data)

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
                    network_data['Management Frames'].append(frame_data)
                elif packet.type == 1:
                    frame_data['Frame Type'] = 'Control'
                    network_data['Control Frames'].append(frame_data)

            # SNMP Packets
            if packet.haslayer(SNMP):
                snmp_data = {
                    'Source IP': packet[IP].src,
                    'Destination IP': packet[IP].dst,
                    'Community': packet[SNMP].community.decode(),
                    'PDU Type': packet[SNMP].PDU,
                    'Summary': packet.summary()
                }
                network_data['SNMP Packets'].append(snmp_data)

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
                network_data['HTTP Requests'].append(http_data)
        except Exception as e:
            print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Error occurred while processing {packet.summary()}: {e}')

    # Remove empty lists from the network_data dictionary
    network_data = {key: value for key, value in network_data.items() if value}
    return network_data

def serialize_network(data):
    def default_serializer(obj):
        # Convert bytes to string
        if isinstance(obj, bytes):
            return obj.decode('utf-8')
        # Convert set to list
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        # Convert other objects to string
        return str(obj)

    return json.loads(json.dumps(data, default=default_serializer))
