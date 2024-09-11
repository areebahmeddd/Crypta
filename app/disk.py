import pytsk3
import pyewf
import os

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

def list_directory_recursively(fs, directory_path):
    """Recursively list the contents of a directory within the filesystem."""
    directory = fs.open_dir(directory_path)

    print(f"Contents of directory: {directory_path}")
    for entry in directory:
        name = entry.info.name.name.decode()
        if name not in [".", ".."]:
            entry_type = 'Directory' if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR else 'File'
            print(f"Found: {name} - {entry_type}")
            
            # If it's a directory, recursively explore it
            if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    list_directory_recursively(fs, f"{directory_path}/{name}")
                except OSError as e:
                    print(f"Error accessing directory {name}: {e}")

def open_e01_image(image_path):
    """Opens an E01 image and recursively lists the contents of all folders."""
    # Open the EWF file using pyewf
    filenames = pyewf.glob(image_path)
    ewf_handle = pyewf.handle()
    ewf_handle.open(filenames)

    # Wrap the EWF handle with our custom Img_Info class
    img_info = EwfImgInfo(ewf_handle)

    # Attempt to open the FAT16 partition
    partition_table = pytsk3.Volume_Info(img_info)
    for part in partition_table:
        if part.desc.decode() == "DOS FAT16 (0x04)" or "NTFS" in part.desc.decode():  # Adjust for FAT16 or NTFS
            print(f"Attempting to open partition: {part.desc.decode()} starting at sector {part.start}")
            
            # Open the partition using its starting offset
            filesystem = pytsk3.FS_Info(img_info, offset=part.start * 512)

            # Recursively list the contents of the root directory
            list_directory_recursively(filesystem, "/")
            break
    else:
        print("No suitable filesystem found.")

open_e01_image(r"C:\Users\shiva\Downloads\nps-2009-canon2-gen1.E01")
