import os
import psutil
from colorama import init, Fore, Style

# Initialize colorama for colored output in console
init(autoreset=True)

def scan_drive():
    while True:
        try:
            # Get the mountpoint of the removable drive and initialize list to store file metadata
            drive_mountpoint = list_drive()
            file_metadata = []

            if drive_mountpoint:
                # Walk through the drive and append file metadata to list for each file found
                for root, dirs, files in os.walk(drive_mountpoint):
                    for file in files:
                        file_path = os.path.join(root, file)
                        file_metadata.append({
                            'name': file,
                            'path': file_path,
                            'size': os.path.getsize(file_path),
                            'type': os.path.splitext(file)[1],
                            'last_modified': os.stat(file_path).st_mtime
                        })
                return file_metadata
        except Exception as e:
            print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Error occurred while scanning drive: {e}')

def list_drive():
    # Return the mountpoint of the removable drive
    for disk in psutil.disk_partitions():
        if 'removable' in disk.opts:
            return disk.mountpoint
    return None
