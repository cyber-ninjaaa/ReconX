"""Final report — JSON save + terminal summary."""

import json
import os
from datetime import datetime
from . import display as d


def run(domain: str, data: dict, output_dir: str) -> str:
    d.section("Reconnaissance Report")

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = os.path.join(output_dir, f"recon_{domain}_{ts}.json")

    report = {
        'meta': {
            'target': domain,
            'timestamp': datetime.now().isoformat(),
            'tool': 'ReconX v1.0',
        },
        **data,
    }

    # Terminal summary
    _print_summary(domain, data)

    # Save JSON
    os.makedirs(output_dir, exist_ok=True)
    with open(filename, 'w') as f:
        json.dump(report, f, indent=4, default=str)

    d.divider()
    d.success(f"Full report saved → {filename}")
    return filename


def _print_summary(domain: str, data: dict):
    from colorama import Fore, Style
    C, G, Y, R, W = Fore.CYAN, Fore.GREEN, Fore.YELLOW, Fore.RED, Fore.WHITE
    BOLD, RESET, DIM = Style.BRIGHT, Style.RESET_ALL, Style.DIM

    print(f"\n  {BOLD}{C}{'═' * 56}{RESET}")
    print(f"  {BOLD}{W}  RECON SUMMARY  —  {domain}{RESET}")
    print(f"  {BOLD}{C}{'═' * 56}{RESET}")

    # WHOIS
    whois = data.get('whois', {})
    if whois:
        registrar = whois.get('Registrar', ['N/A'])[0]
        expires   = whois.get('Expires',   ['N/A'])[0]
        d.result('Registrar', registrar)
        d.result('Expires',   expires)

    # DNS
    dns = data.get('dns', {})
    if dns:
        a_records = dns.get('A', [])
        d.result('A Records', ', '.join(a_records) if a_records else 'none')
        mx = dns.get('MX', [])
        d.result('MX Records', str(len(mx)) + ' found')

    # Subdomains
    subs = data.get('subdomains', [])
    d.result('Subdomains found', str(len(subs)))
    for s in subs[:5]:
        d.found(f"{s['subdomain']} → {', '.join(s['ips'])}")
    if len(subs) > 5:
        d.found(f"… and {len(subs) - 5} more (see JSON report)")

    # Ports
    ports = data.get('ports', [])
    d.result('Open ports', str(len(ports)))
    for p in ports:
        svc = p.get('service', '')
        ver = p.get('version', '')
        d.found(f"{p['port']}/tcp  {svc}  {ver}".strip())

    # SSL
    banners = data.get('banners', {})
    ssl = banners.get('ssl_cert', {})
    if ssl:
        d.result('SSL CN',    ssl.get('subject_cn', 'N/A'))
        d.result('SSL Issuer', ssl.get('issuer', 'N/A'))
        d.result('TLS',        ssl.get('tls_version', 'N/A'))

    # Security header score
    _security_score(banners)


def _security_score(banners: dict):
    from colorama import Fore, Style
    G, Y, R, BOLD, RESET = Fore.GREEN, Fore.YELLOW, Fore.RED, Style.BRIGHT, Style.RESET_ALL

    total_missing = 0
    total_present = 0
    for key, val in banners.items():
        if isinstance(val, dict) and 'security_audit' in val:
            audit = val['security_audit']
            total_present += sum(1 for v in audit.values() if v == 'present')
            total_missing += sum(1 for v in audit.values() if v == 'missing')

    total = total_present + total_missing
    if total == 0:
        return

    score = int((total_present / total) * 100)
    color = G if score >= 70 else (Y if score >= 40 else R)
    d.result('Security Headers', f"{color}{BOLD}{score}% ({total_present}/{total} present){RESET}")
