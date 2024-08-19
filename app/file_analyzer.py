import yara
import json
import re
import os
import csv

with open('app/metadata.json', 'r') as file:
    metadata = json.load(file)
    patterns = metadata['log_patterns']

def scan_file(file_path, rules_path, file_type):
    try:
        # Compile YARA rules
        rules = yara.compile(filepath=rules_path)
        matches_found = []

        if file_type == 'text':
            with open(file_path, 'r', encoding='utf-8') as file:
                # If file type is text, identify file pattern based on sample lines
                sample_lines = [file.readline() for _ in range(10)]
                detected_type = identify_pattern(sample_lines, patterns)

                # Get file pattern based on detected file type
                file_pattern = patterns.get(detected_type) if detected_type else None
                file.seek(0) # Reset file pointer before scanning

                if detected_type is None:
                    # If file type cannot be detected, scan the entire file for YARA rule matches
                    data = file.read()
                    matches = rules.match(data=data)
                    if matches:
                        # Add triggered rules to matches_found list
                        triggered_rules = ", ".join([match.rule for match in matches])
                        matches_found.append([triggered_rules, 'N/A', 'N/A'])
                    return

                for line in file:
                    # If file type is detected, scan each line for YARA rule matches
                    matches = rules.match(data=line)
                    if matches:
                        # Add triggered rules, component and content to matches_found list
                        component, content = extract_info(line, file_pattern, patterns)
                        if component and content:
                            triggered_rules = ", ".join([match.rule for match in matches])
                            matches_found.append([triggered_rules, component, content])

        elif file_type in ['binary', 'script', 'database', 'config']:
            with open(file_path, 'rb') as file:
                # If file type is not text, scan the entire file for YARA rule matches
                data = file.read()
                matches = rules.match(data=data)
                if matches:
                    # Add triggered rules to matches_found list
                    triggered_rules = ", ".join([match.rule for match in matches])
                    matches_found.append([triggered_rules, 'N/A', 'N/A'])

        if matches_found:
            # Generate CSV report with YARA rule matches, components and content found
            output_filename = f'{os.path.splitext(os.path.basename(file_path))[0]}_report.csv'
            output_filepath = os.path.join(os.getcwd(), output_filename)
            with open(output_filepath, 'w', newline='') as file:
                csv_writer = csv.writer(file)
                csv_writer.writerow(['Rule', 'Component', 'Content'])
                csv_writer.writerows(matches_found)
            print(f"[SUCCESS] YARA rule matches found in '{os.path.basename(file_path)}'.")
        else:
            print(f"[FAILURE] No YARA rule matches found in '{os.path.basename(file_path)}'.")

    except Exception as e:
        print(f"[ERROR] Error occurred while scanning '{os.path.basename(file_path)}': {e}")

def identify_pattern(lines, patterns):
    # Check if sample lines match any file pattern
    for line in lines:
        for file_type, pattern in patterns.items():
            if re.match(pattern, line):
                return file_type
    return None

def extract_info(line, pattern, patterns):
    # Extract component and content from log line
    match = re.match(pattern, line)
    if match:
        if pattern == patterns.get('android'):
            component = match.group(5)
            content = match.group(6)
        elif pattern == patterns.get('apache'):
            component = match.group(2)
            content = match.group(3)
        elif pattern == patterns.get('hadoop'):
            component = match.group(3)
            content = match.group(4)
        elif pattern == patterns.get('hdfs'):
            component = match.group(3)
            content = match.group(4)
        elif pattern == patterns.get('hpc'):
            component = match.group(6)
            content = match.group(7)
        elif pattern == patterns.get('linux'):
            component = match.group(2)
            content = match.group(3)
        elif pattern == patterns.get('mac'):
            component = match.group(3)
            content = match.group(4)
        elif pattern == patterns.get('openssh'):
            component = match.group(2)
            content = match.group(3)
        elif pattern == patterns.get('spark'):
            component = match.group(3)
            content = match.group(4)
        elif pattern == patterns.get('windows'):
            component = match.group(4)
            content = match.group(5)
        return component, content
    return None, None
