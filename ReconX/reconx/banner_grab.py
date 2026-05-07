"""Banner grabbing — HTTP headers, SSL cert, raw TCP banners."""

import socket
import ssl
import requests
import subprocess
from datetime import datetime
from . import display as d

requests.packages.urllib3.disable_warnings()

HTTP_PORTS  = {80, 8080, 8000, 8001, 8008, 8081, 8888}
HTTPS_PORTS = {443, 8443, 4443, 5001}

INTERESTING_HEADERS = [
    'Server', 'X-Powered-By', 'X-Generator', 'X-Frame-Options',
    'X-Content-Type-Options', 'Strict-Transport-Security',
    'Content-Security-Policy', 'X-AspNet-Version', 'X-Runtime',
    'Via', 'X-Backend-Server', 'X-Forwarded-For',
]

SECURITY_HEADERS = {
    'Strict-Transport-Security': 'HSTS',
    'Content-Security-Policy': 'CSP',
    'X-Frame-Options': 'Clickjacking protection',
    'X-Content-Type-Options': 'MIME sniffing protection',
    'Referrer-Policy': 'Referrer policy',
    'Permissions-Policy': 'Permissions policy',
}


def run(host: str, open_ports: list) -> dict:
    d.section("Banner Grabbing")
    results = {}

    port_numbers = {p['port'] for p in open_ports}

    # HTTP/HTTPS header grab
    for port in sorted(port_numbers):
        if port in HTTPS_PORTS:
            _grab_http(host, port, https=True, results=results)
        elif port in HTTP_PORTS:
            _grab_http(host, port, https=False, results=results)
        else:
            _grab_tcp_banner(host, port, results)

    # SSL certificate (port 443 or first HTTPS port)
    ssl_ports = port_numbers & HTTPS_PORTS
    if ssl_ports:
        _grab_ssl_cert(host, min(ssl_ports), results)

    return results


def _grab_http(host: str, port: int, https: bool, results: dict):
    scheme = 'https' if https else 'http'
    url = f"{scheme}://{host}:{port}"
    d.info(f"HTTP{'S' if https else ''} headers → {url}")

    try:
        resp = requests.get(url, timeout=8, verify=False,
                            allow_redirects=True,
                            headers={'User-Agent': 'Mozilla/5.0'})

        port_results = {
            'url': url,
            'status_code': resp.status_code,
            'final_url': resp.url,
            'headers': {},
            'security_audit': {},
        }

        # Interesting headers
        for h in INTERESTING_HEADERS:
            val = resp.headers.get(h)
            if val:
                d.result(h, val)
                port_results['headers'][h] = val

        # Security header audit
        d.divider()
        d.info("Security header audit:")
        for header, label in SECURITY_HEADERS.items():
            present = header in resp.headers
            if present:
                d.success(f"{label:<30} ✓ present")
                port_results['security_audit'][label] = 'present'
            else:
                d.warn(f"{label:<30} ✗ missing")
                port_results['security_audit'][label] = 'missing'

        # Title
        if 'text/html' in resp.headers.get('Content-Type', ''):
            import re
            match = re.search(r'<title[^>]*>(.*?)</title>', resp.text, re.I | re.S)
            if match:
                title = match.group(1).strip()[:80]
                d.result("Page Title", title)
                port_results['title'] = title

        results[f"{scheme}_{port}"] = port_results

    except requests.exceptions.SSLError:
        d.warn(f"SSL error on {url} — cert may be self-signed.")
    except requests.exceptions.ConnectionError:
        d.warn(f"Connection refused on {url}")
    except requests.exceptions.Timeout:
        d.warn(f"Timeout on {url}")
    except Exception as e:
        d.warn(f"HTTP grab failed on {url}: {e}")


def _grab_ssl_cert(host: str, port: int, results: dict):
    d.divider()
    d.info(f"SSL Certificate → {host}:{port}")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

        if cert:
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer  = dict(x[0] for x in cert.get('issuer', []))
            not_after = cert.get('notAfter', '')

            d.result("Subject CN",    subject.get('commonName', 'N/A'))
            d.result("Issuer",        issuer.get('organizationName', 'N/A'))
            d.result("Valid Until",   not_after)
            d.result("Cipher Suite",  cipher[0] if cipher else 'N/A')
            d.result("TLS Version",   cipher[1] if cipher else 'N/A')

            # SANs
            sans = [v for t, v in cert.get('subjectAltName', []) if t == 'DNS']
            if sans:
                d.info(f"SANs ({len(sans)}):")
                for san in sans[:10]:
                    d.found(san)

            results['ssl_cert'] = {
                'subject_cn': subject.get('commonName'),
                'issuer': issuer.get('organizationName'),
                'valid_until': not_after,
                'sans': sans,
                'cipher': cipher[0] if cipher else None,
                'tls_version': cipher[1] if cipher else None,
            }

    except Exception as e:
        d.warn(f"SSL cert grab failed: {e}")


def _grab_tcp_banner(host: str, port: int, results: dict):
    probes = [b'\r\n', b'HEAD / HTTP/1.0\r\n\r\n', b'']
    for probe in probes:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(4)
                s.connect((host, port))
                if probe:
                    s.sendall(probe)
                banner = s.recv(1024).decode('utf-8', errors='replace').strip()
                if banner:
                    banner_short = banner[:120].replace('\n', ' | ')
                    d.result(f"Banner {port}/tcp", banner_short)
                    results[f"banner_{port}"] = banner
                    return
        except Exception:
            continue
