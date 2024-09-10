import yara
import json
import os
import re
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

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
                        for match in matches:
                            matches_found.append({
                                'rule': match.rule,
                                'component': 'N/A',
                                'content': 'N/A'
                            })
                    return matches_found

                for line in file:
                    # If file type is detected, scan each line for YARA rule matches
                    matches = rules.match(data=line)
                    if matches:
                        # Add triggered rules, component and content to matches_found list
                        component, content = extract_info(line, file_pattern, patterns)
                        if component and content:
                            for match in matches:
                                matches_found.append({
                                    'rule': match.rule,
                                    'component': component,
                                    'content': content
                                })

        elif file_type in ['binary', 'script', 'database', 'config']:
            with open(file_path, 'rb') as file:
                # If file type is not text, scan the entire file for YARA rule matches
                data = file.read()
                matches = rules.match(data=data)
                if matches:
                    # Add triggered rules to matches_found list
                    for match in matches:
                        matches_found.append({
                            'rule': match.rule,
                            'component': 'N/A',
                            'content': 'N/A'
                        })

        if matches_found:
            print(f'{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {len(matches_found)} YARA rules matched in {os.path.basename(file_path)}')
        else:
            print(f'{Fore.YELLOW}[FAILURE]{Style.RESET_ALL} 0 YARA rules matched in {os.path.basename(file_path)}')

        return matches_found

    except Exception as e:
        print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Error occurred while scanning {os.path.basename(file_path)}: {e}')
        return []

def identify_pattern(lines, patterns):
    # Check if sample lines match any file pattern
    for line in lines:
        for file_type, pattern in patterns.items():
            if re.match(pattern, line):
                return file_type
    return None

def extract_info(line, pattern, patterns):
    # Define a mapping of patterns to their respective group indices
    group_indices = {
        'android': (5, 6),
        'apache': (2, 3),
        'hadoop': (3, 4),
        'hdfs': (3, 4),
        'hpc': (6, 7),
        'linux': (2, 3),
        'mac': (3, 4),
        'openssh': (2, 3),
        'spark': (3, 4),
        'windows': (4, 5)
    }

    # Extract component and content from log line
    match = re.match(pattern, line)
    if match:
        for key, (comp_idx, cont_idx) in group_indices.items():
            if pattern == patterns.get(key):
                try:
                    component = match.group(comp_idx)
                    content = match.group(cont_idx)
                    return component, content
                except IndexError:
                    return None, None
    return None, None
