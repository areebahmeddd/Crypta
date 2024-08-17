import os
import pandas as pd
from scapy.all import rdpcap, Dot11, IP, TCP, UDP, DNS, ARP, ICMP, BOOTP, DHCP, SNMP, Ether
from scapy.layers.http import HTTPRequest

def scan_pcap(file_path, output_directory):
    # Read packets from pcap file
    packets = rdpcap(file_path)

    # Initialize lists to store data for each protocol
    control_frames = []
    management_frames = []
    http_requests = []
    dns_queries = []
    tcp_packets = []
    udp_packets = []
    arp_packets = []
    icmp_packets = []
    dhcp_packets = []
    snmp_packets = []
    ftp_packets = []

    # Check each packet for supported protocols
    for packet in packets:
        # Check for 802.11 frame
        if packet.haslayer(Dot11):
            frame_data = {
                'Frame Type': 'Unknown',
                'Subtype': packet.subtype if hasattr(packet, 'subtype') else 'Unknown',
                'Source MAC': packet.addr2 if hasattr(packet, 'addr2') else 'Unknown',
                'Destination MAC': packet.addr1 if hasattr(packet, 'addr1') else 'Unknown',
                'Summary': packet.summary()
            }

            if packet.type == 0:
                frame_data['Frame Type'] = 'Management'
                management_frames.append(frame_data)

            elif packet.type == 1:
                frame_data['Frame Type'] = 'Control'
                control_frames.append(frame_data)

        # Check for HTTP request
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

        # Check for DNS query packet
        if packet.haslayer(DNS) and packet.haslayer(UDP):
            dns_data = {
                'Source IP': packet[IP].src,
                'Destination IP': packet[IP].dst,
                'Query Name': packet[DNS].qd.qname.decode() if packet[DNS].qd else None,
                'Summary': packet.summary()
            }
            dns_queries.append(dns_data)

        # Check for TCP packet
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

        # Check for UDP packet
        if packet.haslayer(UDP) and not packet.haslayer(DNS):
            udp_data = {
                'Source IP': packet[IP].src,
                'Destination IP': packet[IP].dst,
                'Source Port': packet[UDP].sport,
                'Destination Port': packet[UDP].dport,
                'Summary': packet.summary()
            }
            udp_packets.append(udp_data)

        # Check for ARP packet
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

        # Check for ICMP packet
        if packet.haslayer(ICMP):
            icmp_data = {
                'Source IP': packet[IP].src,
                'Destination IP': packet[IP].dst,
                'Type': packet[ICMP].type,
                'Code': packet[ICMP].code,
                'Summary': packet.summary()
            }
            icmp_packets.append(icmp_data)

        # Check for DHCP packet
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

        # Check for SNMP packet
        if packet.haslayer(SNMP):
            snmp_data = {
                'Source IP': packet[IP].src,
                'Destination IP': packet[IP].dst,
                'Community': packet[SNMP].community.decode(),
                'PDU Type': packet[SNMP].PDU,
                'Summary': packet.summary()
            }
            snmp_packets.append(snmp_data)

        # Check for FTP packet
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

    # Create dataframes from collected data
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

    # Save dataframes to Excel and CSV files
    os.makedirs(output_directory, exist_ok=True)
    excel_path = os.path.join(output_directory, 'network_protocols_analysis.xlsx')

    with pd.ExcelWriter(excel_path) as writer:
        # Write each dataframe to a separate sheet in the Excel file
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

    # Save dataframes to CSV files
    df_control.to_csv(os.path.join(output_directory, 'control_frames.csv'), index=False)
    df_management.to_csv(os.path.join(output_directory, 'management_frames.csv'), index=False)
    df_http.to_csv(os.path.join(output_directory, 'http_requests.csv'), index=False)
    df_dns.to_csv(os.path.join(output_directory, 'dns_queries.csv'), index=False)
    df_tcp.to_csv(os.path.join(output_directory, 'tcp_packets.csv'), index=False)
    df_udp.to_csv(os.path.join(output_directory, 'udp_packets.csv'), index=False)
    df_arp.to_csv(os.path.join(output_directory, 'arp_packets.csv'), index=False)
    df_icmp.to_csv(os.path.join(output_directory, 'icmp_packets.csv'), index=False)
    df_dhcp.to_csv(os.path.join(output_directory, 'dhcp_packets.csv'), index=False)
    df_snmp.to_csv(os.path.join(output_directory, 'snmp_packets.csv'), index=False)
    df_ftp.to_csv(os.path.join(output_directory, 'ftp_packets.csv'), index=False)

    print(f"Network scan complete. Results saved to '{output_directory}'.")
