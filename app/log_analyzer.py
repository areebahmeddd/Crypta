import yara
import re
import os
import csv

# Define log patterns for different operating systems
WINDOWS_LOG_PATTERN = r'(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}), (\w+)\s+(\w+)\s+(.*)'
MAC_LOG_PATTERN = r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+[\w.-]+\s+([\w.-]+)\[\d+\]:\s+(.*)'
LINUX_LOG_PATTERN = r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+[\w.-]+\s+([\w().-]+)\[\d+\]:\s+(.*)'

LOG_PATTERNS = {
    'windows': WINDOWS_LOG_PATTERN,
    'mac': MAC_LOG_PATTERN,
    'linux': LINUX_LOG_PATTERN
}

def scan_log(rules_path, path):
    # Compare log files against YARA rules
    rules = yara.compile(filepath=rules_path)

    if os.path.isdir(path):
        # If path is a directory, process each log file in the folder
        for log_filename in os.listdir(path):
            log_filepath = os.path.join(path, log_filename)
            if os.path.isfile(log_filepath):
                process_log(rules, log_filepath)
    elif os.path.isfile(path):
        # If path is a single file, process that file
        process_log(rules, path)
    else:
        print(f"The path '{path}' is not a valid file or directory.")

def process_log(rules, log_filepath):
    with open(log_filepath, 'r') as log_file:
        # Read first 10 lines to detect log type
        sample_lines = [log_file.readline() for _ in range(10)]
        detected_log_type = log_type(sample_lines)

        if detected_log_type is None:
            print(f"Unable to detect log type for file '{log_filepath}'.")
            return

        # Define log pattern and output filename based on detected log type
        pattern = LOG_PATTERNS[detected_log_type]
        output_filename = f'{detected_log_type}_log.csv'
        output_filepath = os.path.join(os.getcwd(), output_filename)

        with open(output_filepath, 'w', newline='') as file:
            csv_writer = csv.writer(file)
            csv_writer.writerow(['Rule', 'Component', 'Content'])

            # Reset file pointer and scan log file against YARA rules
            log_file.seek(0)
            for line in log_file:
                matches = rules.match(data=line)
                # Write yara rule, component and content to csv file
                if matches:
                    component, content = parse_log(line, pattern)
                    if component and content:
                        triggered_rules = ", ".join([match.rule for match in matches])
                        csv_writer.writerow([triggered_rules, component, content])

        print(f"Log scan complete for '{os.path.basename(log_filepath)}'. Results saved to '{output_filepath}'.")

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
