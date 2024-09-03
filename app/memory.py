
from parse import scan_path
import memprocfs

def scan_dir(vmm, directory =  "/"):
    for entry in vmm.vfs.list(directory):
        full_path = directory + "/" + entry.name
        if entry.is_dir():
            scan_dir(vmm, full_path)
        else:
            scan_path(full_path)


vmm = memprocfs.Vmm(['-device', r'C:\Users\avike\OneDrive\Desktop\MemoryDump_Lab1.raw', '-forensic', '1'])

scan_dir(vmm)



    





