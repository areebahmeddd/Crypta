import pytsk3
import pyewf
import json
import os
import yara
from datetime import datetime
from typing import List, Dict, Any

# Load metadata and YARA rules
with open('metadata/schema.json', 'r') as file:
    metadata = json.load(file)

rules = yara.compile(filepath='yara-rules/security.yara')


class EwfImage(pytsk3.Img_Info):
    """A class to wrap EWF handle for reading .E01 image files."""

    def __init__(self, ewf_handle: pyewf.handle) -> None:
        self._ewf_handle = ewf_handle
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self) -> None:
        """Close the EWF handle."""
        self._ewf_handle.close()

    def read(self, offset: int, size: int) -> bytes:
        """Read bytes from the EWF handle at the specified offset."""
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self) -> int:
        """Get the size of the EWF image."""
        return self._ewf_handle.get_media_size()


def gather_file_metadata(fs: pytsk3.FS_Info, directory_path: str) -> List[Dict[str, Any]]:
    """Recursively traverse directories and gather metadata from supported files."""
    try:
        directory = fs.open_dir(directory_path)
    except Exception as e:
        print(f"Error opening directory {directory_path}: {e}")
        return []

    file_metadata = []

    for entry in directory:
        name = entry.info.name.name.decode()
        if name not in [".", ".."]:
            try:
                if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    # Recursively traverse subdirectories
                    file_metadata.extend(gather_file_metadata(fs, f"{directory_path}/{name}"))
                else:
                    file_ext = os.path.splitext(name)[1]
                    supported_extensions = [
                        ext for exts in metadata['file_types'].values() for ext in exts
                    ]

                    if file_ext in supported_extensions:
                        file_path = os.path.join(directory_path, name)
                        last_modified = (
                            datetime.fromtimestamp(entry.info.meta.mtime).strftime('%d/%m/%Y')
                            if entry.info.meta.mtime != 0 else 'N/A'
                        )

                        # Read file content and run YARA rules if the file size is valid
                        yara_matches = []
                        try:
                            if entry.info.meta.size > 0:  # Only read if the file has a valid size
                                file_content = entry.read_random(0, entry.info.meta.size)
                                yara_matches = rules.match(data=file_content)
                            else:
                                print(f"Skipping file {file_path} due to invalid or zero size.")
                        except Exception as e:
                            print(f"Error reading file {file_path}: {e}")

                        file_metadata.append({
                            'name': name,
                            'path': file_path,
                            'size': entry.info.meta.size,
                            'type': file_ext,
                            'last_modified': last_modified,
                            'yara_matches': [match.rule for match in yara_matches],
                        })
            except Exception as e:
                print(f"Error processing entry {name} in directory {directory_path}: {e}")

    return file_metadata


def process_disk_image(image_path: str) -> List[Dict[str, Any]]:
    """Open an E01 image, traverse file systems, and return metadata of supported files."""
    if not os.path.exists(image_path):
        print(f"Image path does not exist: {image_path}")
        return []

    try:
        filenames = pyewf.glob(image_path)
        ewf_handle = pyewf.handle()
        ewf_handle.open(filenames)

        ewf_image = EwfImage(ewf_handle)
        partition_table = pytsk3.Volume_Info(ewf_image)

        for partition in partition_table:
            if any(fs in partition.desc.decode() for fs in ["DOS FAT16", "Win95 FAT32", "NTFS"]):
                filesystem = pytsk3.FS_Info(ewf_image, offset=partition.start * 512)
                file_metadata = gather_file_metadata(filesystem, "/")
                ewf_handle.close()
                return file_metadata

        print("No suitable filesystem found.")
        ewf_handle.close()

    except Exception as e:
        print(f"An error occurred: {e}")

    return []
