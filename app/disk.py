#! To run this script you will have to build pyewf from source. 
# The pre-built binaries are not available for Windows.

# Run these commands in ps to build pyewf from source:
"""
git clone https://github.com/libyal/libewf.git
cd libewf\
.\synclibs.ps1
.\syncwinflexbison.ps1
.\synczlib.ps1
.\autogen.ps1
"""

# after this run
# pip install .

import yara
import pytsk3
import pyewf
import io

class EwfImgInfo(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super(EwfImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._ewf_handle.close()

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._ewf_handle.get_media_size()

def is_image(file_name):
    """Check if a file is an image based on its extension."""
    return file_name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'))

def list_and_scan_directory_recursively(fs, directory_path, yara_rules):
    directory = fs.open_dir(directory_path)
    for entry in directory:
        name = entry.info.name.name.decode()
        if name not in [".", ".."]:
            if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                list_and_scan_directory_recursively(fs, f"{directory_path}/{name}", yara_rules)
            else:
                if is_image(name):
                    try:
                        file_data = entry.read_random(0, entry.info.meta.size)
                        scan_data_with_yara(file_data, yara_rules, name)
                    except Exception as e:
                        print(f"Error processing file {name}: {e}")

def read_raw_sectors(image_path, start_sector, num_sectors):
    filenames = pyewf.glob(image_path)
    ewf_handle = pyewf.handle()
    ewf_handle.open(filenames)
    
    img_info = EwfImgInfo(ewf_handle)
    sector_size = 512
    offset = start_sector * sector_size
    size = num_sectors * sector_size
    
    data = img_info.read(offset, size)
    ewf_handle.close()
    
    return data

def scan_data_with_yara(data, yara_rules, file_name):
    try:
        yara_matches = yara_rules.match(data=data)
        if yara_matches:
            print(f"YARA matches found in {file_name}:")
            for match in yara_matches:
                print(f"  Rule: {match.rule}")
    except Exception as e:
        print(f"Error scanning data: {e}")

def open_e01_image(image_path, yara_rules):
    filenames = pyewf.glob(image_path)
    ewf_handle = pyewf.handle()
    ewf_handle.open(filenames)

    img_info = EwfImgInfo(ewf_handle)
    partition_table = pytsk3.Volume_Info(img_info)
    
    for part in partition_table:
        if part.desc.decode() == "DOS FAT16 (0x04)" or "NTFS" in part.desc.decode():
            print(f"Attempting to open partition: {part.desc.decode()} starting at sector {part.start}")
            filesystem = pytsk3.FS_Info(img_info, offset=part.start * 512)
            list_and_scan_directory_recursively(filesystem, "/", yara_rules)
            break
    else:
        print("No suitable filesystem found.")

def parse_boot_sector(data):
    try:
        boot_sector_info = {
            'OEM Name': data[0x03:0x0B].decode('ascii', errors='ignore'),
            'Bytes per Sector': int.from_bytes(data[0x0B:0x0D], 'little'),
            'Sectors per Cluster': data[0x0D],
            'Reserved Sectors': int.from_bytes(data[0x0E:0x10], 'little'),
            'Number of FATs': data[0x10],
            'Root Directory Entries': int.from_bytes(data[0x11:0x13], 'little'),
            'Total Sectors (16-bit)': int.from_bytes(data[0x13:0x15], 'little'),
            'FAT Size': int.from_bytes(data[0x16:0x18], 'little'),
            'Sectors per Track': int.from_bytes(data[0x18:0x1A], 'little'),
            'Number of Heads': int.from_bytes(data[0x1A:0x1C], 'little'),
            'Hidden Sectors': int.from_bytes(data[0x1C:0x20], 'little'),
            'Total Sectors (32-bit)': int.from_bytes(data[0x20:0x24], 'little')
        }

        for key, value in boot_sector_info.items():
            print(f"{key}: {value}")

    except Exception as e:
        print(f"Error parsing boot sector: {e}")

def print_as_hex(data):
    print(data.hex())

if __name__ == "__main__":
    yara_rules_file = r'yara-rules\security.yara'
    image_path = r"C:\Users\shiva\Downloads\nps-2009-canon2-gen1.E01"

    yara_rules = yara.compile(filepath=yara_rules_file)
    open_e01_image(image_path, yara_rules)
    
    start_sector = 0
    num_sectors = 1
    sector_data = read_raw_sectors(image_path, start_sector, num_sectors)
    
    with open('sector_data.bin', 'wb') as f:
        f.write(sector_data)
        
    with open('sector_data.bin', 'rb') as f:
        sector_data = f.read()
    
    parse_boot_sector(sector_data)
    
    print("HEX-----")
    print_as_hex(sector_data)
