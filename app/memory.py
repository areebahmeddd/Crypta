r'''import subprocess
from parse import scan_path


#function to automate mount point
def mount(dump_file, mount_point="M:"):

    command = f"memprocfs.exe -mount {mount_point} -device {dump_file} -forensic 1"
    
    try:
        subprocess.run(command, check = True, shell = True, )
        print("mounted successfully at {mount_point}")
        return mount_point
    
    except subprocess.CalledProcessError as e:
        print(f"failed to mount at drive {e}")
    
    except Exception as e:
        print(f"An error occurred: {e}")
    return None


if __name__ == '__main__':

    mem_dump_file = r"C:\Users\avike\OneDrive\Desktop\MemoryDump_Lab1.raw"

    mounted = mount(mem_dump_file, "M:")

    #if mount point is returned then scan the mounted directory 
    if mounted:
        scan_path(mounted)'''


from parse import scan_path
import memprocfs

vmm = memprocfs.Vmm(['-device', r'C:\Users\avike\OneDrive\Desktop\MemoryDump_Lab1.raw'])

for file in vmm.vfs.list("/"):
    scan_path(file)






