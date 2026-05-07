"""Port scanner — uses nmap if available, falls back to pure socket scan."""

import socket
import subprocess
import concurrent.futures
from . import display as d

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
    8443, 8888, 9200, 9300, 27017, 6379, 5432, 1433,
    2181, 4443, 5000, 5001, 7001, 8000, 8001, 8008,
    8081, 8888, 9000, 9090, 10000,
]

SERVICE_NAMES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'MSRPC',
    139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1723: 'PPTP',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    9200: 'Elasticsearch', 27017: 'MongoDB',
}


def run(host: str, ports: list = None, use_nmap: bool = True) -> list:
    d.section("Port Scan")
    d.info(f"Target: {host}")

    # Resolve hostname → IP
    try:
        ip = socket.gethostbyname(host)
        if ip != host:
            d.result("Resolved IP", ip)
    except socket.gaierror:
        d.error(f"Cannot resolve {host}")
        return []

    ports = ports or TOP_PORTS

    if use_nmap and _nmap_available():
        return _nmap_scan(ip, host)
    else:
        return _socket_scan(ip, ports)


def _nmap_available() -> bool:
    try:
        subprocess.run(['nmap', '--version'], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _nmap_scan(ip: str, host: str) -> list:
    d.info("Using nmap (SV scan)…")
    open_ports = []
    try:
        result = subprocess.run(
            ['nmap', '-sV', '--open', '-T4', '-p',
             ','.join(str(p) for p in TOP_PORTS), ip],
            capture_output=True, text=True, timeout=120
        )
        for line in result.stdout.splitlines():
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                port_proto = parts[0]          # e.g. 80/tcp
                port = int(port_proto.split('/')[0])
                state = parts[1]               # open
                service = parts[2] if len(parts) > 2 else SERVICE_NAMES.get(port, 'unknown')
                version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                entry = {
                    'port': port,
                    'protocol': 'tcp',
                    'state': state,
                    'service': service,
                    'version': version,
                }
                open_ports.append(entry)
                label = f"{port}/tcp  {service:<14}"
                d.success(f"{label} {version}")
    except subprocess.TimeoutExpired:
        d.warn("nmap scan timed out.")
    except Exception as e:
        d.error(f"nmap error: {e}")

    _summarize(open_ports)
    return open_ports


def _socket_scan(ip: str, ports: list) -> list:
    d.info(f"nmap not found — using socket scan on {len(ports)} ports…")
    open_ports = []

    def probe(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                if s.connect_ex((ip, port)) == 0:
                    return port
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        for port in concurrent.futures.as_completed(
            {ex.submit(probe, p): p for p in ports}
        ):
            result = port.result()
            if result:
                service = SERVICE_NAMES.get(result, 'unknown')
                entry = {'port': result, 'protocol': 'tcp', 'state': 'open', 'service': service, 'version': ''}
                open_ports.append(entry)
                d.success(f"{result}/tcp  {service}")

    open_ports.sort(key=lambda x: x['port'])
    _summarize(open_ports)
    return open_ports


def _summarize(open_ports: list):
    d.divider()
    if open_ports:
        d.info(f"{len(open_ports)} open port(s) found.")
    else:
        d.warn("No open ports found.")
