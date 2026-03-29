##block all suspicious but malware that hide in memory as legit program can still live
import os
import sys
import ctypes
import subprocess
import psutil
import socket


# ================= ADMIN =================

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    params = " ".join([f'"{x}"' for x in sys.argv])
    subprocess.run([
        "powershell",
        "-Command",
        f"Start-Process '{sys.executable}' -ArgumentList '{params}' -Verb RunAs"
    ])
    sys.exit()


if not is_admin():
    run_as_admin()


# ================= FIREWALL =================

def block_port(port):

    subprocess.run([
        "powershell",
        "-Command",
        f"New-NetFirewallRule -DisplayName 'Block Remote Port {port} Outbound' "
        f"-Direction Outbound -Protocol TCP -RemotePort {port} -Action Block"
    ], capture_output=True)

    subprocess.run([
        "powershell",
        "-Command",
        f"New-NetFirewallRule -DisplayName 'Block Remote Port {port} Inbound' "
        f"-Direction Inbound -Protocol TCP -RemotePort {port} -Action Block"
    ], capture_output=True)


# ================= SCRIPT A =================

WINDOWS_DIR = os.environ.get("WINDIR", r"C:\Windows").lower()


def is_non_windows_process(proc):
    try:
        return not proc.exe().lower().startswith(WINDOWS_DIR)
    except:
        return False


def run_script_A():

    blocked = set()
    targets = set()
    seen_ports = set()

    for conn in psutil.net_connections(kind="inet"):

        if conn.status != psutil.CONN_ESTABLISHED:
            continue

        if not conn.raddr or not conn.pid:
            continue

        try:
            proc = psutil.Process(conn.pid)
        except:
            continue

        if not is_non_windows_process(proc):
            continue

        ip = conn.raddr.ip
        port = conn.raddr.port

        if port not in seen_ports:
            seen_ports.add(port)
            block_port(port)
            blocked.add(f"{ip}:{port}")

        targets.add(ip)

    return blocked, targets


# ================= SCRIPT B =================

COMMON_PORTS = [
21,22,23,25,53,80,110,143,443,445,
465,587,993,995,1433,3306,3389,
5432,5900,6379,8080,8443,8888,
9000,9200,27017
]

MESSAGE = "Hello"
TOTAL_PACKETS = 100


def find_open_port(ip):

    for port in COMMON_PORTS:

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            sock.connect((ip, port))
            sock.close()
            return port
        except:
            pass

    return None


def send_packets(ip, port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))

    packet = MESSAGE.encode()

    for _ in range(TOTAL_PACKETS):
        sock.sendall(packet)

    sock.close()


def run_script_B(targets):

    results = []

    for ip in targets:

        port = find_open_port(ip)

        if port:
            results.append(f"{ip}:{port}")
            send_packets(ip, port)

    return results


# ================= MAIN =================

def main():

    blocked, targets = run_script_A()

    results = run_script_B(targets)

    if blocked:
        print("Blocked:", ", ".join(blocked))

    if results:
        print("Target:", ", ".join(results))

    input("\nPress Enter to close...")


if __name__ == "__main__":
    main()