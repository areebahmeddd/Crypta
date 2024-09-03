
from parse import scan_path
import json
import memprocfs


vmm = memprocfs.Vmm(['-device', r'C:\Users\avike\OneDrive\Desktop\MemoryDump_Lab1.raw', '-forensic', '1'])

for file in vmm.vfs,list("/"):
    scan_path(file)



    





