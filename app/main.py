import yara

#compiling
#rules = yara.compile(filepath = r'C:\Users\avike\OneDrive\Desktop\yara_rules\rules.yar')

#from yara_scanner import yara_scan

# Define the path to the YARA rules and the mounted image
#rules = yara.compile(filepath = r'C:\Users\avike\OneDrive\Desktop\yara_rules\rules.yar')
#sample_file = r'C:\Users\avike\OneDrive\Desktop\yara_rules\sam.txt'

# Run YARA and capture the output
#result = yara_scan(rules, sample_file)

import yara
import csv

def scan_file(rules_path, file_path, output_path):
    rules = yara.compile(filepath=rules_path)

    with open(file_path, 'r') as log_file, open(output_path, 'w', newline='') as output_file:
        csv_writer = csv.writer(output_file)
        csv_writer.writerow(['Rule', 'Log entry'])
        for line in log_file:
            matches = rules.match(data=line)
            if matches:
                for match in matches:
                    #output_file.write(f"Rule '{match.rule}' triggered by '{line.strip()}'")
                    csv_writer.writerow([match.rule, line.strip()])
            else:
                print(f"No matches found in '{file_path}'.")


scan_file("rules.yar", "Windows_2k.log_structured.csv","matches.csv")
