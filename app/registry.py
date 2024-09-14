from regipy.registry import RegistryHive
import json
from typing import Any, Dict, List, Union

def serialize_value(value: Any) -> Union[str, None]:
    '''Convert value to a JSON-serializable format.'''
    try:
        return value.decode('utf-8')
    except (AttributeError, UnicodeDecodeError):
        return value.hex() if isinstance(value, bytes) else str(value)

def serialize_subkey(entry: Any) -> Dict[str, Any]:
    '''Convert Subkey object to a dictionary.'''
    entry_dict = {
        'subkey_name': entry.subkey_name,
        'path': entry.path,
        'timestamp': entry.timestamp if isinstance(entry.timestamp, str) else entry.timestamp.isoformat() if entry.timestamp else None,
        'values': {value.name: serialize_value(value.value) for value in entry.values},
        'values_count': entry.values_count
    }
    return entry_dict

def process_registry_hive(file_path: str) -> List[Dict[str, Any]]:
    '''Process the registry hive and return entries as a JSON string.'''
    reg = RegistryHive(file_path)
    entries = [serialize_subkey(entry) for entry in reg.recurse_subkeys()]
    return entries
