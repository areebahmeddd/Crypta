import yara
import re
import csv

WINDOWS_LOG_PATTERN = r'(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}), (\w+)\s+(\w+)\s+(.*)'
MAC_LOG_PATTERN = r'(\w+ \d+ \d{2} \d{2}:\d{2}:\d{2}) [\w.-]+ (\w+)\[\d+\]: (.*)'
LINUX_LOG_PATTERN = r'(\w+ \d+ \d{2} \d{2}:\d{2}:\d{2}) [\w-]+ ([\w\(\)]+): (.*)'

LOG_PATTERNS = {
    'windows': WINDOWS_LOG_PATTERN,
    'mac': MAC_LOG_PATTERN,
    'linux': LINUX_LOG_PATTERN
}

def scan_logs(rules_path, file_path, output_path):
    rules = yara.compile(filepath=rules_path)

    with open(file_path, 'r') as log_file:
        sample_lines = [
            log_file.readline()
            for _ in range(10)
        ]
        detected_log_type = log_type(sample_lines)

        if detected_log_type is None:
            print(f"Unable to detect log type for file '{file_path}'.")
            return

        pattern = LOG_PATTERNS[detected_log_type]

        with open(output_path, 'w', newline='') as output_file:
            csv_writer = csv.writer(output_file)
            csv_writer.writerow(['Rule', 'Component', 'Content'])

            log_file.seek(0)
            for line in log_file:
                matches = rules.match(data=line)
                if matches:
                    component, content = parse_log(line, pattern)
                    if component and content:
                        triggered_rules = ", ".join([match.rule for match in matches])
                        csv_writer.writerow([triggered_rules, component, content])
            print(f"Scan completed. Results saved to '{output_path}'.")

def log_type(lines):
    for line in lines:
        for log_type, pattern in LOG_PATTERNS.items():
            if re.match(pattern, line):
                return log_type
    return None

def parse_log(line, pattern):
    match = re.match(pattern, line)
    if match:
        if pattern == WINDOWS_LOG_PATTERN:
            component = match.group(4)
            content = match.group(5)
        elif pattern == MAC_LOG_PATTERN:
            component = match.group(2)
            content = match.group(3)
        elif pattern == LINUX_LOG_PATTERN:
            component = match.group(2)
            content = match.group(3)
        return component, content
    return None, None

if __name__ == '__main__':
    scan_logs(r'yara-rules\error.yar', r'logs\system\windows.log', 'report.csv') # Change the log file path (windows.log or mac.log or linux.log)