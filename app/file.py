import yara
import os
from colorama import init, Fore, Style

# Initialize colorama for colored output in console
init(autoreset=True)
yara_results = []

def scan_file(file_path, rules_path, file_type):
    try:
        # Compile YARA rules
        yara_rules = yara.compile(filepath=rules_path)

        # Check if file is text-based and read file data with UTF-8 encoding
        if file_type == 'text':
            with open(file_path, 'r', encoding='utf-8') as file:
                file_data = file.read() # Read entire file (not line-by-line)
                yara_results = process_results(file_data, yara_rules)

        # Check if file is binary-based and read file data in binary mode
        elif file_type in ['binary', 'config', 'database', 'script']:
            with open(file_path, 'rb') as file:
                file_data = file.read() # Read entire file (not line-by-line)
                yara_results = process_results(file_data, yara_rules)

        if yara_results:
            print(f'{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {len(yara_results)} YARA rules matched in {os.path.basename(file_path)}')
        else:
            print(f'{Fore.YELLOW}[FAILURE]{Style.RESET_ALL} 0 YARA rules matched in {os.path.basename(file_path)}')

        return yara_results
    except Exception as e:
        print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Error occurred while scanning {os.path.basename(file_path)}: {e}')

def process_results(file_data, yara_rules):
    # Process YARA rules against file data
    yara_matches = yara_rules.match(data=file_data)
    if yara_matches:
        # Add triggered YARA rules to results list
        for match in yara_matches:
            yara_results.append({'triggered_action': match.rule})
    else:
        yara_results.append({'triggered_action': 'No YARA rules matched'})
    return yara_results
