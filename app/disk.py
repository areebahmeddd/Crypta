import pyewf
import pytsk3
import os
import json
import yara
from datetime import datetime

with open('metadata/schema.json', 'r') as file:
    metadata = json.load(file)

class EwfImage(pytsk3.Img_Info):
    # Class to wrap EWF handle for reading .E01 disk images
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super().__init__(url='', type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        # Close EWF handle when done
        self._ewf_handle.close()

    def read(self, offset, size):
        # Read bytes from the EWF handle at the specified offset
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        # Get the size of the EWF image
        return self._ewf_handle.get_media_size()

def scan_disk(image_path, rules_path):
    # Open an E01 image, traverse file systems, and return metadata of supported files
    print(f'Scanning disk image {image_path}...')
    if not os.path.exists(image_path):
        print(f'Disk image {image_path} not found.')
        return []

    try:
        file_name = pyewf.glob(image_path)
        ewf_handle = pyewf.handle()
        ewf_handle.open(file_name)

        ewf_image = EwfImage(ewf_handle)
        partition_table = pytsk3.Volume_Info(ewf_image)

        for partition in partition_table:
            if any(filesystem in partition.desc.decode() for filesystem in ['DOS FAT16', 'Win95 FAT32', 'NTFS']):
                filesystem = pytsk3.FS_Info(ewf_image, offset=partition.start * 512)
                file_metadata = extract_metadata(filesystem, '/', rules_path)
                ewf_handle.close()
                return file_metadata

        print(f'No supported filesystem found in disk image {image_path}')
        ewf_handle.close()

    except Exception as e:
        print(f'Error processing disk image {image_path}: {e}')

    return []

def extract_metadata(filesystem, directory_path, rules_path):
    # Recursively traverse the file system and extract metadata of supported files
    try:
        directory = filesystem.open_dir(directory_path)
    except Exception as e:
        print(f'Error opening directory {directory_path}: {e}')
        return []

    file_metadata = []

    for file in directory:
        file_name = file.info.name.name.decode()
        if file_name not in ['.', '..']:
            try:
                if file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    # Recursively extract metadata of files in subdirectories
                    file_metadata.extend(extract_metadata(filesystem, f'{directory_path}/{file_name}', rules_path))
                else:
                    file_extension = os.path.splitext(file_name)[1]
                    supported_extensions = [ext for exts in metadata['file_types'].values() for ext in exts]

                    # Check if file extension is supported
                    if file_extension in supported_extensions:
                        file_path = os.path.join(directory_path, file_name)
                        last_modified = (
                            datetime.fromtimestamp(file.info.meta.mtime).strftime('%d/%m/%Y')
                            if file.info.meta.mtime != 0 else 'N/A'
                        )

                        # Scan file for YARA rules
                        yara_matches = []
                        yara_rules = yara.compile(filepath=rules_path)
                        if file.info.meta.size > 0: # Skip empty files
                            file_content = file.read_random(0, file.info.meta.size)
                            yara_matches = yara_rules.match(data=file_content)
                        else:
                            print(f'File {file_path} is empty.')

                        file_metadata.append({
                            'name': file_name,
                            'path': file_path,
                            'size': file.info.meta.size,
                            'type': file_extension,
                            'last_modified': last_modified,
                            'triggered_action': [match.rule for match in yara_matches],
                        })
            except Exception as e:
                print(f'Error processing file {file_name} in {directory_path}: {e}')

    return file_metadata
