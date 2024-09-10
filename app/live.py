import psutil
import os
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

def scan_drive():
    # Initialize list to store detected drives
    detected_drives = []
    files_found = []  # List to store all found files

    try:
        # Get current list of drives and mountpoints
        current_drives = list_drive()

        # Check for new drives and process them if detected
        current_drive_devices = {device for device in current_drives.keys()}  # Use a set for quick lookup
        new_drives = {device: mountpoint for device, mountpoint in current_drives.items() if device not in detected_drives}
        for device, mountpoint in new_drives.items():
            # Process new drive by scanning the root directory for files and directories
            print(f'{Fore.BLUE}[INFO]{Style.RESET_ALL} Drive detected: {device}')
            # Recursively gather files in the drive
            for root, dirs, files in os.walk(mountpoint):
                for file in files:
                    file_path = os.path.join(root, file)
                    files_found.append(file_path)
                    print(f"Found file: {file_path}")  # Print the found file path
            detected_drives.append(device)

        # Check for removed drives and update detected drives list
        removed_drives = [drive for drive in detected_drives if drive not in current_drive_devices]
        for device in removed_drives:
            print(f'{Fore.BLUE}[INFO]{Style.RESET_ALL} Drive removed: {device}')
            detected_drives.remove(device)

        print(f"Detected drives: {detected_drives}")
        return files_found  # Return the list of found files
    except Exception as e:
        print(f'{Fore.RED}[ERROR]{Style.RESET_ALL} Error occurred: {e}')
        return []  # Return an empty list in case of error

def list_drive():
    # Return dictionary of removable drives and their mountpoints
    return {
        disk.device: disk.mountpoint
        for disk in psutil.disk_partitions()
        if disk.opts and 'removable' in disk.opts
    }
