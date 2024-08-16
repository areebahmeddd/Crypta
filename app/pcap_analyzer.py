from scapy.all import rdpcap, Dot11, IP, TCP, UDP, DNS, ARP, ICMP, BOOTP, DHCP, SNMP, Ether
from scapy.layers.http import HTTPRequest
import pandas as pd
import os
from typing import List, Dict, Any

def analyze_pcap(pcap_file: str, output_dir: str) -> int:
    """
    Analyzes a PCAP file and categorizes network packets into various protocols.
    Saves the analysis results into Excel and CSV files in the specified output directory.

    Args:
        pcap_file (str): The path to the PCAP file to be analyzed.
        output_dir (str): The directory where the output files will be saved.

    Returns:
        int: The number of packets analyzed.
    """
    # Load the PCAP file
    packets = rdpcap(pcap_file)

    # Lists to store data for each protocol
    control_frames: List[Dict[str, Any]] = []
    management_frames: List[Dict[str, Any]] = []
    http_requests: List[Dict[str, Any]] = []
    dns_queries: List[Dict[str, Any]] = []
    tcp_packets: List[Dict[str, Any]] = []
    udp_packets: List[Dict[str, Any]] = []
    arp_packets: List[Dict[str, Any]] = []
    icmp_packets: List[Dict[str, Any]] = []
    dhcp_packets: List[Dict[str, Any]] = []
    snmp_packets: List[Dict[str, Any]] = []
    ftp_packets: List[Dict[str, Any]] = []

    # Loop through each packet in the pcap file
    for packet in packets:
        if packet.haslayer(Dot11):
            frame_data = {
                'Frame Type': 'Unknown',
                'Subtype': packet.subtype if hasattr(packet, 'subtype') else 'Unknown',
                'Source MAC': packet.addr2 if hasattr(packet, 'addr2') else 'Unknown',
                'Destination MAC': packet.addr1 if hasattr(packet, 'addr1') else 'Unknown',
                'Summary': packet.summary()
            }
            
            if packet.type == 0:  # Management frame
                frame_data['Frame Type'] = 'Management'
                management_frames.append(frame_data)
                
            elif packet.type == 1:  # Control frame
                frame_data['Frame Type'] = 'Control'
                control_frames.append(frame_data)
        
        if packet.haslayer(HTTPRequest):
            http_data = {
                'Source IP': packet[IP].src,
                'Destination IP': packet[IP].dst,
                'Method': packet[HTTPRequest].Method.decode(),
                'Host': packet[HTTPRequest].Host.decode(),
                'Path': packet[HTTPRequest].Path.decode(),
                'Summary': packet.summary()
            }
            http_requests.append(http_data)
        
        if packet.haslayer(DNS) and packet.haslayer(UDP):
            dns_data = {
                'Source IP': packet[IP].src,
                'Destination IP': packet[IP].dst,
                'Query Name': packet[DNS].qd.qname.decode() if packet[DNS].qd else None,
                'Summary': packet.summary()
            }
            dns_queries.append(dns_data)
        
        if packet.haslayer(TCP):
            tcp_data = {
                'Source IP': packet[IP].src,
                'Destination IP': packet[IP].dst,
                'Source Port': packet[TCP].sport,
                'Destination Port': packet[TCP].dport,
                'Flags': packet[TCP].flags,
                'Summary': packet.summary()
            }
            tcp_packets.append(tcp_data)
        
        if packet.haslayer(UDP) and not packet.haslayer(DNS):
            udp_data = {
                'Source IP': packet[IP].src,
                'Destination IP': packet[IP].dst,
                'Source Port': packet[UDP].sport,
                'Destination Port': packet[UDP].dport,
                'Summary': packet.summary()
            }
            udp_packets.append(udp_data)
        
        if packet.haslayer(ARP):
            arp_data = {
                'Source IP': packet[ARP].psrc,
                'Destination IP': packet[ARP].pdst,
                'Source MAC': packet[ARP].hwsrc,
                'Destination MAC': packet[ARP].hwdst,
                'Operation': packet[ARP].op,
                'Summary': packet.summary()
            }
            arp_packets.append(arp_data)

        if packet.haslayer(ICMP):
            icmp_data = {
                'Source IP': packet[IP].src,
                'Destination IP': packet[IP].dst,
                'Type': packet[ICMP].type,
                'Code': packet[ICMP].code,
                'Summary': packet.summary()
            }
            icmp_packets.append(icmp_data)
        
        if packet.haslayer(DHCP):
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
            dhcp_packets.append(dhcp_data)
        
        if packet.haslayer(SNMP):
            snmp_data = {
                'Source IP': packet[IP].src,
                'Destination IP': packet[IP].dst,
                'Community': packet[SNMP].community.decode(),
                'PDU Type': packet[SNMP].PDU,
                'Summary': packet.summary()
            }
            snmp_packets.append(snmp_data)
        
        if packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):
            ftp_data = {
                'Source IP': packet[IP].src,
                'Destination IP': packet[IP].dst,
                'Source Port': packet[TCP].sport,
                'Destination Port': packet[TCP].dport,
                'Flags': packet[TCP].flags,
                'Summary': packet.summary()
            }
            ftp_packets.append(ftp_data)

    # Create DataFrames for each protocol type
    df_control = pd.DataFrame(control_frames)
    df_management = pd.DataFrame(management_frames)
    df_http = pd.DataFrame(http_requests)
    df_dns = pd.DataFrame(dns_queries)
    df_tcp = pd.DataFrame(tcp_packets)
    df_udp = pd.DataFrame(udp_packets)
    df_arp = pd.DataFrame(arp_packets)
    df_icmp = pd.DataFrame(icmp_packets)
    df_dhcp = pd.DataFrame(dhcp_packets)
    df_snmp = pd.DataFrame(snmp_packets)
    df_ftp = pd.DataFrame(ftp_packets)

    # Ensure the directory 'network_logs' exists
    os.makedirs(output_dir, exist_ok=True)

    # Write DataFrames to Excel file
    excel_path = os.path.join(output_dir, 'network_protocols_analysis.xlsx')
    with pd.ExcelWriter(excel_path) as writer:
        df_control.to_excel(writer, sheet_name='Control Frames', index=False)
        df_management.to_excel(writer, sheet_name='Management Frames', index=False)
        df_http.to_excel(writer, sheet_name='HTTP Requests', index=False)
        df_dns.to_excel(writer, sheet_name='DNS Queries', index=False)
        df_tcp.to_excel(writer, sheet_name='TCP Packets', index=False)
        df_udp.to_excel(writer, sheet_name='UDP Packets', index=False)
        df_arp.to_excel(writer, sheet_name='ARP Packets', index=False)
        df_icmp.to_excel(writer, sheet_name='ICMP Packets', index=False)
        df_dhcp.to_excel(writer, sheet_name='DHCP Packets', index=False)
        df_snmp.to_excel(writer, sheet_name='SNMP Packets', index=False)
        df_ftp.to_excel(writer, sheet_name='FTP Packets', index=False)

    # Write DataFrames to CSV files in the 'network_logs' folder
    df_control.to_csv(os.path.join(output_dir, 'control_frames.csv'), index=False)
    df_management.to_csv(os.path.join(output_dir, 'management_frames.csv'), index=False)
    df_http.to_csv(os.path.join(output_dir, 'http_requests.csv'), index=False)
    df_dns.to_csv(os.path.join(output_dir, 'dns_queries.csv'), index=False)
    df_tcp.to_csv(os.path.join(output_dir, 'tcp_packets.csv'), index=False)
    df_udp.to_csv(os.path.join(output_dir, 'udp_packets.csv'), index=False)
    df_arp.to_csv(os.path.join(output_dir, 'arp_packets.csv'), index=False)
    df_icmp.to_csv(os.path.join(output_dir, 'icmp_packets.csv'), index=False)
    df_dhcp.to_csv(os.path.join(output_dir, 'dhcp_packets.csv'), index=False)
    df_snmp.to_csv(os.path.join(output_dir, 'snmp_packets.csv'), index=False)
    df_ftp.to_csv(os.path.join(output_dir, 'ftp_packets.csv'), index=False)

    print(f"Excel and CSV files created with categorized network protocols in '{output_dir}' folder!")

    return len(packets)

# Example usage
# analyze_pcap('SkypeIRC.cap', 'network_logs')
