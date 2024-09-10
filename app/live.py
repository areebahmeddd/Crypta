import psutil
import os

def scan_drive():
    drive_mountpoint = list_drive()

    if drive_mountpoint:
        file_names = []
        for root, dirs, files in os.walk(drive_mountpoint):
            for file in files:
                file_names.append(file)
        return file_names if file_names else ["No files found on the drive."]
    else:
        return ["No removable drive detected."]

def list_drive():
    for disk in psutil.disk_partitions():
        if 'removable' in disk.opts:
            return disk.mountpoint
    return None
