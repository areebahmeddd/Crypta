import yara
import json
import re
import os
from colorama import init, Fore, Style

# Initialize colorama for colored output in console
init(autoreset=True)

with open('metadata/schema.json', 'r') as file:
    metadata = json.load(file)
    patterns = metadata['log_patterns']

def scan_file(file_path, rules_path, file_type):
    try:
        # Compile YARA rules
        yara_rules = yara.compile(filepath=rules_path)
        yara_results = []

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
                    file_data = file.read()
                    yara_matches = yara_rules.match(data=file_data)
                    if yara_matches:
                        # Add triggered YARA rules to results list
                        for match in yara_matches:
                            add_result(yara_results, match.rule)
                    return yara_results

                for line in file:
                    # If file type is detected, scan each line for YARA rule matches
                    yara_matches = yara_rules.match(data=line)
                    if yara_matches:
                        # Add triggered rules, component and content to results list
                        component, content = extract_info(line, file_pattern, patterns)
                        if component and content:
                            for match in yara_matches:
                                add_result(yara_results, match.rule, component, content)

        elif file_type in ['binary', 'script', 'database', 'config']:
            with open(file_path, 'rb') as file:
                # If file type is not text, scan the entire file for YARA rule matches
                file_data = file.read()
                yara_matches = yara_rules.match(data=file_data)
                if yara_matches:
                    # Add triggered YARA rules to results list
                    for match in yara_matches:
                        add_result(yara_results, match.rule)

        if yara_results:
            print(f'{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {len(yara_results)} YARA rules matched in {os.path.basename(file_path)}')
        else:
            print(f'{Fore.YELLOW}[FAILURE]{Style.RESET_ALL} 0 YARA rules matched in {os.path.basename(file_path)}')

        return yara_results
    except Exception as e:
        print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Error occurred while scanning {os.path.basename(file_path)}: {e}')

def add_result(yara_results, rule, component='N/A', content='N/A'):
    # Helper function to add YARA scan results to the list
    yara_results.append({
        'rule': rule,
        'component': component,
        'content': content
    })

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

    # Extract component and content based on pattern match
    match = re.match(pattern, line)
    if match:
        for key, (comp_idx, cont_idx) in group_indices.items():
            if pattern == patterns.get(key):
                component = match.group(comp_idx)
                content = match.group(cont_idx)
                return component, content
    return 'N/A', 'N/A'
