from pcap_analyzer import scan_pcap
from log_analyzer import scan_logs

if __name__ == '__main__':
    # Change the log file path (windows.log or mac.log or linux.log)
    scan_logs(r'yara-rules\error.yar', r'logs\system\windows.log', 'report.csv') 

    analyze_pcap(r"logs/network/SkypeIRC.cap")
