import psutil

def list_process():
    # Iterate over all running processes and print process ID, name, and parent process ID
    for process in psutil.process_iter(['pid', 'name', 'ppid']):
        print(f'PID: {process.info["pid"]}, Name: {process.info["name"]}, PPID: {process.info["ppid"]}')

def scan_process():
    # Map all running processes to their parent process
    process_tree = map_process()
    anomalies_found = False

    # Iterate over all parent processes and their child processes to detect anomalies
    for parent_pid, child_pids in process_tree.items():
        parent_process = psutil.Process(parent_pid)

        # Check if the parent process has any child processes with different parent process ID
        for child_pid in child_pids:
            child_process = psutil.Process(child_pid)
            if child_process.ppid() != parent_pid:
                print(f'Anomaly detected: Parent process {parent_process.name()} (PID: {parent_pid}) has child process {child_process.name()} (PID: {child_pid}) with different PPID.')
                anomalies_found = True

    if not anomalies_found:
        print('No anomalies detected in process tree.')

def map_process():
    process_tree = {}
    # Iterate over all running processes and map each process to its parent process
    for process in psutil.process_iter(['pid', 'ppid']):
        pid = process.info['pid']
        ppid = process.info['ppid']

        if ppid not in process_tree:
            process_tree[ppid] = []
        process_tree[ppid].append(pid)

    return process_tree

if __name__ == '__main__':
    # list_process()
    scan_process()
