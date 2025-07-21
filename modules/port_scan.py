# modules/port_scan.py

import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(ip, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                return port
    except Exception:
        pass
    return None

def run_port_scan(ip, ports=None, max_threads=100):
    if ports is None:
        # Default: 20'den 1024'e kadar olan portlar
        ports = list(range(20, 1025))

    open_ports = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        results = executor.map(lambda p: scan_port(ip, p), ports)

    for port in results:
        if port:
            open_ports.append(port)

    return open_ports
#