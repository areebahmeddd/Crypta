from regipy.registry import RegistryHive
import json

def scan_registry(file_path):
    # Load the registry hive and recursively scan all subkeys
    registry_hive = RegistryHive(file_path)
    subkey_entries = [serialize_subkey(subkey) for subkey in registry_hive.recurse_subkeys()]
    return subkey_entries

def serialize_subkey(subkey):
    # Serialize subkey data to a dictionary
    subkey_data = {
        'subkey_name': subkey.subkey_name,
        'path': subkey.path,
        'timestamp': subkey.timestamp if isinstance(subkey.timestamp, str) else subkey.timestamp.isoformat() if subkey.timestamp else None,
        'values': {value.name: serialize_value(value.value) for value in subkey.values},
        'values_count': subkey.values_count
    }
    return subkey_data

def serialize_value(value):
    # Serialize registry value data to a dictionary
    try:
        return value.decode('utf-8')
    except (AttributeError, UnicodeDecodeError):
        return value.hex() if isinstance(value, bytes) else str(value)

if __name__ == '__main__':
    registry_entries = scan_registry(r'C:\Users\shiva\Downloads\hives\SECURITY')
    print(json.dumps(registry_entries, indent=2))
