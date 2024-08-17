from log_analyzer import scan_log
from pcap_analyzer import scan_pcap

if __name__ == '__main__':
    scan_log(r'yara-rules\error.yar', r'logs\system')
    scan_pcap(r'logs\network')
