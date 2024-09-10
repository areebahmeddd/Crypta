import winreg
import pandas as pd

def read_registry_key(hive, subkey):
    try:
        registry = winreg.OpenKey(hive, subkey)
        values = []
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(registry, i)
                values.append((name, value))
                i += 1
            except OSError:
                break
        return values
    except FileNotFoundError:
        return []

def extract_registry_data():
    # Example subkeys to examine
    subkeys = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SYSTEM\CurrentControlSet\Services"
    ]
    
    data = []
    
    for subkey in subkeys:
        hive = winreg.HKEY_LOCAL_MACHINE if 'HKLM' in subkey else winreg.HKEY_CURRENT_USER
        values = read_registry_key(hive, subkey)
        for name, value in values:
            data.append({
                "Subkey": subkey,
                "Name": name,
                "Value": value
            })
    
    return pd.DataFrame(data)

# Extract and print registry data
df = extract_registry_data()
print(df)
