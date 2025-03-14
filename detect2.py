import psutil
import socket
import ctypes
import os

# Define known attacker IPs and suspicious ports
ATTACKER_IPS = ["192.168.1.100"]
SUSPICIOUS_PORTS = [4444, 1337, 9001]
SUSPICIOUS_PROCESSES = ['cmd.exe', 'powershell.exe', 'python.exe', 'nc.exe', 'explorer.exe']


# 🛑 Alert Function
def show_warning(process_name):
    ctypes.windll.user32.MessageBoxW(
        0,
        f"Suspicious activity detected!\nProcess '{process_name}' terminated.",
        "⚠️ Security Alert",
        0x10
    )


# 🔨 Terminate malicious process
def terminate_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        print(f"[ACTION] Terminated suspicious process: {proc.name()} (PID: {pid})")
    except Exception as e:
        print(f"[ERROR] Failed to terminate process {pid}: {e}")


# 🔍 Advanced Reverse Shell Detection
def detect_reverse_shell():
    detected = False

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            # Get network connections for the current process
            connections = proc.connections()

            # 🕵️‍♂️ Check each connection
            for conn in connections:
                # Look for established outbound connections
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    remote_ip, remote_port = conn.raddr

                    # Match attacker IPs or suspicious ports
                    if remote_ip in ATTACKER_IPS or remote_port in SUSPICIOUS_PORTS:
                        print(f"[ALERT] Suspicious Connection Detected: {proc.info['name']} (PID: {proc.info['pid']}) -> {remote_ip}:{remote_port}")
                        terminate_process(proc.info['pid'])
                        show_warning(proc.info['name'])
                        detected = True

            # 🎯 Detect suspicious processes or weird command lines
            proc_name = proc.info.get('name', '').lower()
            cmdline = proc.info.get('cmdline', [])

            # Ensure cmdline is iterable (list/tuple), or default to an empty list
            if not isinstance(cmdline, (list, tuple)):
                cmdline = []

            # Detect suspicious process names or encoded payloads
            if proc_name in SUSPICIOUS_PROCESSES or any("powershell -enc" in arg for arg in cmdline):
                print(f"[ALERT] Suspicious Process Detected: {proc_name} (PID: {proc.info['pid']}) running {' '.join(cmdline) if cmdline else 'No command line'}")
                terminate_process(proc.info['pid'])
                show_warning(proc_name)
                detected = True

        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

    if not detected:
        print("[INFO] No reverse shell detected!")


# ✅ Run the detection
if __name__ == "__main__":
    print("[INFO] Reverse Shell Detection Starting...")
    detect_reverse_shell()
