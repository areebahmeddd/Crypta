import psutil

def build_process_dict():
    
    #Build a dictionary where keys are parent process IDs (PPIDs) and values are lists of child process IDs (PIDs).
    
    process_dict = {}
    
    # Iterate over all processes
    for proc in psutil.process_iter(['pid', 'ppid']):
        try:
            pid = proc.info['pid']
            ppid = proc.info['ppid']
            
            if ppid not in process_dict:
                process_dict[ppid] = []
            process_dict[ppid].append(pid)
        
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            # Handle process exceptions
            print(f"Error: {e}")
    # print(process_dict)
    return process_dict

def detect_anomalies():
    
    #Detect anomalies in the parent-child process relationships.
    
    process_dict = build_process_dict()
    f=0
    # Check for anomalies

    for ppid, children in process_dict.items():
        # Fetch the parent process
        try:
            parent = psutil.Process(ppid)
        except psutil.NoSuchProcess:
            continue
        
        # Check each child
        for child_pid in children:
            try:
                child = psutil.Process(child_pid)
                if child.ppid() != ppid:
                    print(f"Anomaly Detected: Child process {child_pid} has PPID {child.ppid()} but expected {ppid}")
                    f=1
            except psutil.NoSuchProcess:
                continue
    if f==0:
                print("No Anomalies Detected")
        
def list_processes():
    for proc in psutil.process_iter(['pid', 'name', 'ppid']):
        try:
            print(f"PID: {proc.info['pid']}, Name: {proc.info['name']}, PPID: {proc.info['ppid']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

if __name__ == "__main__":
    #list_processes()
    detect_anomalies()
