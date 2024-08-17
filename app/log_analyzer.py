import yara
import re
import csv

# Define log patterns for different operating systems
WINDOWS_LOG_PATTERN = r'(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}), (\w+)\s+(\w+)\s+(.*)'
MAC_LOG_PATTERN = r'(\w+ \d+ \d{2} \d{2}:\d{2}:\d{2}) [\w.-]+ (\w+)\[\d+\]: (.*)'
LINUX_LOG_PATTERN = r'(\w+ \d+ \d{2} \d{2}:\d{2}:\d{2}) [\w-]+ ([\w\(\)]+): (.*)'

LOG_PATTERNS = {
    'windows': WINDOWS_LOG_PATTERN,
    'mac': MAC_LOG_PATTERN,
    'linux': LINUX_LOG_PATTERN
}

def scan_log(rules_path, file_path, output_path):
    # Compares log file against YARA rules
    rules = yara.compile(filepath=rules_path)

    # Read first 10 lines of log file to detect log type
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

        # Write results to CSV file with rule, component, and content columns
        with open(output_path, 'w', newline='') as file:
            csv_writer = csv.writer(file)
            csv_writer.writerow(['Rule', 'Component', 'Content'])

            # Scan log file for matches with YARA rules
            log_file.seek(0)
            for line in log_file:
                matches = rules.match(data=line)
                if matches:
                    component, content = parse_log(line, pattern)
                    if component and content:
                        triggered_rules = ", ".join([match.rule for match in matches])
                        csv_writer.writerow([triggered_rules, component, content])
            print(f"Log scan complete. Results saved to '{output_path}'.")

def log_type(lines):
    # Check if log lines match any of the known log patterns
    for line in lines:
        for log_type, pattern in LOG_PATTERNS.items():
            if re.match(pattern, line):
                return log_type
    return None

def parse_log(line, pattern):
    # Extract component and content from log line
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
