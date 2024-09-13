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
        print(f'{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Network scan completed for {os.path.basename(file_path)}')
        return formatted_data
    except Exception as e:
        print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Error occurred while scanning {os.path.basename(file_path)}: {e}')

def process_packet(captured_packets):
    # Initialize network data and flow tracker for toring processed data and tracking network flows
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
    flow_tracker = {}

    # Process each packet in the pcap file and extract relevant information
    for packet in captured_packets:
        try:
            # Get flow key for tracking network flows
            flow_key = start_tracking(packet, flow_tracker)
            if flow_key:
                # Update flow end time and packet count based on packet direction
                flow_tracker[flow_key]['end'] = packet.time
                if packet[IP].src == flow_tracker[flow_key]['ip_src']:
                    flow_tracker[flow_key]['forward'] += 1
                else:
                    flow_tracker[flow_key]['backward'] += 1

            # Ethernet Frames
            if packet.haslayer(Ether):
                # ARP Packets
                if packet.haslayer(ARP):
                    arp_data = {
                        'Timestamp': packet.time,
                        'Source IP': packet[ARP].psrc,
                        'Destination IP': packet[ARP].pdst,
                        'Source MAC': packet[ARP].hwsrc,
                        'Destination MAC': packet[ARP].hwdst,
                        'Flow Duration': flow_duration(flow_key, flow_tracker),
                        'Forward Packets': forward_packets(flow_key, flow_tracker),
                        'Backward Packets': backward_packets(flow_key, flow_tracker)
                    }
                    network_data['ARP Packets'].append(arp_data)

                # DHCP Packets
                elif packet.haslayer(DHCP):
                    dhcp_data = {
                        'Timestamp': packet.time,
                        'Source IP': packet[BOOTP].ciaddr,
                        'Destination IP': packet[BOOTP].yiaddr,
                        'Source MAC': packet[Ether].src,
                        'Destination MAC': packet[Ether].dst,
                        'Flow Duration': flow_duration(flow_key, flow_tracker),
                        'Forward Packets': forward_packets(flow_key, flow_tracker),
                        'Backward Packets': backward_packets(flow_key, flow_tracker)
                    }
                    network_data['DHCP Packets'].append(dhcp_data)

            # IP Layer
            if packet.haslayer(IP):
                # TCP Packets
                if packet.haslayer(TCP):
                    tcp_data = {
                        'Timestamp': packet.time,
                        'Source IP': packet[IP].src,
                        'Destination IP': packet[IP].dst,
                        'Source Port': packet[TCP].sport,
                        'Destination Port': packet[TCP].dport,
                        'Flow Duration': flow_duration(flow_key, flow_tracker),
                        'Forward Packets': forward_packets(flow_key, flow_tracker),
                        'Backward Packets': backward_packets(flow_key, flow_tracker)
                    }
                    network_data['TCP Packets'].append(tcp_data)

                    # FTP Packets
                    if packet[TCP].dport in [20, 21] or packet[TCP].sport in [20, 21]:
                        ftp_data = {
                            'Timestamp': packet.time,
                            'Source IP': packet[IP].src,
                            'Destination IP': packet[IP].dst,
                            'Source Port': packet[TCP].sport,
                            'Destination Port': packet[TCP].dport,
                            'Flow Duration': flow_duration(flow_key, flow_tracker),
                            'Forward Packets': forward_packets(flow_key, flow_tracker),
                            'Backward Packets': backward_packets(flow_key, flow_tracker)
                        }
                        network_data['FTP Packets'].append(ftp_data)

                # UDP Packets
                elif packet.haslayer(UDP):
                    if packet.haslayer(DNS):
                        dns_data = {
                            'Timestamp': packet.time,
                            'Source IP': packet[IP].src,
                            'Destination IP': packet[IP].dst,
                            'Flow Duration': flow_duration(flow_key, flow_tracker),
                            'Forward Packets': forward_packets(flow_key, flow_tracker),
                            'Backward Packets': backward_packets(flow_key, flow_tracker)
                        }
                        network_data['DNS Queries'].append(dns_data)
                    else:
                        udp_data = {
                            'Timestamp': packet.time,
                            'Source IP': packet[IP].src,
                            'Destination IP': packet[IP].dst,
                            'Source Port': packet[UDP].sport,
                            'Destination Port': packet[UDP].dport,
                            'Flow Duration': flow_duration(flow_key, flow_tracker),
                            'Forward Packets': forward_packets(flow_key, flow_tracker),
                            'Backward Packets': backward_packets(flow_key, flow_tracker)
                        }
                        network_data['UDP Packets'].append(udp_data)

                # ICMP Packets
                elif packet.haslayer(ICMP):
                    icmp_data = {
                        'Timestamp': packet.time,
                        'Source IP': packet[IP].src,
                        'Destination IP': packet[IP].dst,
                        'Flow Duration': flow_duration(flow_key, flow_tracker),
                        'Forward Packets': forward_packets(flow_key, flow_tracker),
                        'Backward Packets': backward_packets(flow_key, flow_tracker)
                    }
                    network_data['ICMP Packets'].append(icmp_data)

            # Dot11 Frames (Wireless Frames)
            if packet.haslayer(Dot11):
                frame_data = {
                    'Timestamp': packet.time,
                    'Source IP': packet.addr2 if hasattr(packet, 'addr2') else 'Unknown',
                    'Destination IP': packet.addr1 if hasattr(packet, 'addr1') else 'Unknown',
                    'Flow Duration': flow_duration(flow_key, flow_tracker),
                    'Forward Packets': forward_packets(flow_key, flow_tracker),
                    'Backward Packets': backward_packets(flow_key, flow_tracker)
                }
                if packet.type == 0:
                    network_data['Management Frames'].append(frame_data)
                elif packet.type == 1:
                    network_data['Control Frames'].append(frame_data)

            # SNMP Packets
            if packet.haslayer(SNMP):
                snmp_data = {
                    'Timestamp': packet.time,
                    'Source IP': packet[IP].src,
                    'Destination IP': packet[IP].dst,
                    'Flow Duration': flow_duration(flow_key, flow_tracker),
                    'Forward Packets': forward_packets(flow_key, flow_tracker),
                    'Backward Packets': backward_packets(flow_key, flow_tracker)
                }
                network_data['SNMP Packets'].append(snmp_data)

            # HTTP Requests
            if packet.haslayer(HTTPRequest):
                http_data = {
                    'Timestamp': packet.time,
                    'Source IP': packet[IP].src,
                    'Destination IP': packet[IP].dst,
                    'Method': packet[HTTPRequest].Method.decode('utf-8'),
                    'Host': packet[HTTPRequest].Host.decode('utf-8'),
                    'Flow Duration': flow_duration(flow_key, flow_tracker),
                    'Forward Packets': forward_packets(flow_key, flow_tracker),
                    'Backward Packets': backward_packets(flow_key, flow_tracker)
                }
                network_data['HTTP Requests'].append(http_data)
        except Exception as e:
            print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Error occurred while processing {packet.summary()}: {e}')

    # Remove empty lists from the network_data dictionary
    network_data = {key: value for key, value in network_data.items() if value}
    return network_data

def start_tracking(packet, flow_tracker):
    flow_key = None
    # Check if packet has IP layer and extract flow key for tracking network flows
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if packet.haslayer(TCP):
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
        elif packet.haslayer(UDP):
            port_src = packet[UDP].sport
            port_dst = packet[UDP].dport
        else:
            port_src = port_dst = None

        flow_key = (ip_src, ip_dst, port_src, port_dst)

    # Check if flow key is not already in flow tracker and initialize flow data
    if flow_key and flow_key not in flow_tracker:
        flow_tracker[flow_key] = {
            'start': packet.time,
            'end': packet.time,
            'forward': 0,
            'backward': 0,
            'ip_src': ip_src,
            'ip_dst': ip_dst
        }

    return flow_key

def flow_duration(flow_key, flow_tracker):
    # Calculate flow duration based on flow key in flow tracker
    if flow_key in flow_tracker:
        start_time = flow_tracker[flow_key]['start']
        end_time = flow_tracker[flow_key]['end']
        return round(end_time - start_time, 2)
    return 0

def forward_packets(flow_key, flow_tracker):
    # Get the number of packets forwarded in the network flow
    if flow_key in flow_tracker:
        return flow_tracker[flow_key]['forward']
    return 0

def backward_packets(flow_key, flow_tracker):
    # Get the number of packets received in the network flow
    if flow_key in flow_tracker:
        return flow_tracker[flow_key]['backward']
    return 0

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
