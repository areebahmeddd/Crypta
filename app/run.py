import os
import json
import zipfile
import tempfile

from file_analyzer import scan_file
from network_analyzer import scan_network

with open('app/metadata.json', 'r') as file:
    metadata = json.load(file)
    file_types = metadata['file_types']

def scan_path(input_path, rules_path):
    # Check if input path is a directory, zip file or regular file
    if os.path.isdir(input_path):
        process_directory(input_path, rules_path)
    elif zipfile.is_zipfile(input_path):
        process_zip_file(input_path, rules_path)
    elif os.path.isfile(input_path):
        process_file(input_path, rules_path)
    else:
        print(f'Invalid input path: {input_path}')

def process_directory(directory_path, rules_path):
    # Recursively process all files in the directory and subdirectories
    for root, dirs, files in os.walk(directory_path):
        print(f'Processing Folder: {root}')
        for file in files:
            process_file(os.path.join(root, file), rules_path)

def process_zip_file(zip_path, rules_path):
    # Extract zip file to temporary directory and process files
    print(f'Processing Zip File: {zip_path}')
    with tempfile.TemporaryDirectory() as temp_dir:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        process_directory(temp_dir, rules_path)

def process_file(file_path, rules_path):
    # Process individual file based on file type
    print(f'Processing File: {file_path}')
    file_type = find_type(file_path)
    if file_type == 'network':
        scan_network(file_path)
    elif file_type:
        scan_file(file_path, rules_path, file_type)
    else:
        print(f'Unsupported file type: {file_path}')

def find_type(file_path):
    # Determine file type based on file extension
    name, extension = os.path.splitext(file_path)
    extension = extension.lower()

    # Check if file extension matches known network capture file types
    if extension in ['.pcap', '.cap', '.pcapng']:
        return 'network'

    # Check if file extension matches known file types in metadata
    for file_type, extensions in file_types.items():
        if extension in extensions:
            return file_type
    return None

if __name__ == '__main__':
    scan_path('logs', 'yara-rules/security.yara')
