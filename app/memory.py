import memprocfs
from parse import scan_path

# Load the memory dump and enable forensic mode (Be sure to save the memory dump in the same directory as this script)
memory = memprocfs.Vmm(['-device', r'MemoryDump_Lab1.raw', '-forensic', '1'])

# Scan the root directory of the memory dump
for file in memory.vfs.list('/'):
    scan_path(file)
