import pytsk3
import pyewf
import json
import os
from datetime import datetime
from typing import List, Dict, Any

with open('metadata/schema.json', 'r') as file:
    metadata = json.load(file)

class EwfImgInfo(pytsk3.Img_Info):
    def __init__(self, ewf_handle: pyewf.handle) -> None:
        self._ewf_handle = ewf_handle
        super(EwfImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self) -> None:
        self._ewf_handle.close()

    def read(self, offset: int, size: int) -> bytes:
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self) -> int:
        return self._ewf_handle.get_media_size()


def list_directory_recursively(fs: pytsk3.FS_Info, directory_path: str) -> List[Dict[str, Any]]:
    """Recursively list the contents of a directory within the filesystem and collect file metadata."""
    directory = fs.open_dir(directory_path)
    file_metadata = []

    for entry in directory:
        name = entry.info.name.name.decode()
        if name not in [".", ".."]:

            if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    file_metadata.extend(list_directory_recursively(fs, f"{directory_path}/{name}"))
                except OSError as e:
                    print(f"Error accessing directory {name}: {e}")
            else:
                # Collect file metadata if the file extension is supported
                file_ext = os.path.splitext(name)[1]
                
                supported_extensions = [ext for extensions in metadata['file_types'].values() for ext in extensions]
                if file_ext in supported_extensions:
                    file_path = os.path.join(directory_path, name)
                    # Handle time conversion and check for 0 timestamp
                    last_modified = (
                        datetime.fromtimestamp(entry.info.meta.mtime).strftime('%d/%m/%Y')
                        if entry.info.meta.mtime != 0 else 'N/A'
                    )
                    file_metadata.append({
                        'name': name,
                        'path': file_path,
                        'size': entry.info.meta.size,
                        'type': file_ext,
                        'last_modified': last_modified
                    })

    return file_metadata


def open_e01_image(image_path: str) -> List[Dict[str, Any]]:
    """Opens an E01 image and scans the contents of all folders."""
    try:
        # Open the EWF file using pyewf
        filenames: List[str] = pyewf.glob(image_path)
        ewf_handle = pyewf.handle()
        ewf_handle.open(filenames)

        # Wrap the EWF handle with our custom Img_Info class
        img_info = EwfImgInfo(ewf_handle)

        # Attempt to open the FAT16, FAT32, or NTFS partition
        partition_table = pytsk3.Volume_Info(img_info)
        for part in partition_table:
            if (
                part.desc.decode() == "DOS FAT16 (0x04)" or
                part.desc.decode() == "Win95 FAT32 (0x0b)" or
                "NTFS" in part.desc.decode()
            ):
                # Open the partition using its starting offset
                filesystem = pytsk3.FS_Info(img_info, offset=part.start * 512)

                # Scan the contents of the root directory and collect file metadata
                file_metadata = list_directory_recursively(fs=filesystem, directory_path="/")
                ewf_handle.close()

                return file_metadata
        else:
            print("No suitable filesystem found.")
            ewf_handle.close()

            return []

    except Exception as e:
        print(f"An error occurred: {e}")
        return []


print(json.dumps(open_e01_image(r"c:\Users\shiva\Downloads\ubnist1.gen2.E01"), indent=2))
