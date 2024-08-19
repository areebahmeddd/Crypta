import psutil
from parse import scan_path

def scan_drive():
    # Initialize set to store detected drives
    detected_drives = set()

    while True:
        try:
            # Get current list of drives and mountpoints
            current_drives = list_drive()

            # Check for new drives and process them if detected
            new_drives = {device: mountpoint for device, mountpoint in current_drives.items() if device not in detected_drives}
            for device, mountpoint in new_drives.items():
                # Process new drive by scanning the root directory for files and directories
                print(f'[INFO] Drive detected: {device}')
                scan_path(mountpoint)
                detected_drives.add(device)

            # Check for removed drives and update detected drives set
            removed_drives = detected_drives - set(current_drives.keys())
            for device in removed_drives:
                print(f'[INFO] Drive removed: {device}')
                detected_drives.remove(device)
        except Exception as e:
            print(f'[ERROR] Error occurred while scanning {device}: {e}')

def list_drive():
    # Return dictionary of removable drives and their mountpoints
    return {
        disk.device: disk.mountpoint
        for disk in psutil.disk_partitions()
        if disk.opts and 'removable' in disk.opts
    }
