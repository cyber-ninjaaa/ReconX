#!/usr/bin/env python3
"""ReconX — Automated Reconnaissance Framework."""

import argparse
import sys
import os
from pathlib import Path

from reconx import display as d
from reconx import whois_lookup, dns_enum, subdomain_brute, port_scan, banner_grab, report


def build_parser():
    parser = argparse.ArgumentParser(
        prog='reconx',
        description='ReconX — Automated Reconnaissance Framework',
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument('domain', help='Target domain (e.g. example.com)')
    parser.add_argument('--wordlist',  '-w', help='Custom subdomain wordlist path')
    parser.add_argument('--threads',   '-t', type=int, default=30, help='Threads for subdomain brute-force (default: 30)')
    parser.add_argument('--output',    '-o', default='output', help='Output directory (default: output)')
    parser.add_argument('--no-whois',  action='store_true', help='Skip WHOIS lookup')
    parser.add_argument('--no-dns',    action='store_true', help='Skip DNS enumeration')
    parser.add_argument('--no-subs',   action='store_true', help='Skip subdomain brute-force')
    parser.add_argument('--no-ports',  action='store_true', help='Skip port scan')
    parser.add_argument('--no-banner', action='store_true', help='Skip banner grabbing')
    parser.add_argument('--no-nmap',   action='store_true', help='Force socket scan even if nmap is available')
    parser.add_argument('--quiet',     '-q', action='store_true', help='Suppress banner')
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.quiet:
        d.banner()

    domain = args.domain.strip().lower()
    # Strip http/https if user pastes a URL
    for prefix in ('https://', 'http://'):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split('/')[0]

    d.info(f"Target  : {domain}")
    d.info(f"Output  : {args.output}")
    print()

    data = {}

    # ── 1. WHOIS ─────────────────────────────────────────────────────────────
    if not args.no_whois:
        data['whois'] = whois_lookup.run(domain)

    # ── 2. DNS Enumeration ───────────────────────────────────────────────────
    if not args.no_dns:
        data['dns'] = dns_enum.run(domain)

    # ── 3. Subdomain Brute-Force ─────────────────────────────────────────────
    if not args.no_subs:
        data['subdomains'] = subdomain_brute.run(
            domain,
            wordlist_path=args.wordlist,
            threads=args.threads,
        )

    # ── 4. Port Scan ─────────────────────────────────────────────────────────
    if not args.no_ports:
        data['ports'] = port_scan.run(
            domain,
            use_nmap=not args.no_nmap,
        )

    # ── 5. Banner Grabbing ───────────────────────────────────────────────────
    if not args.no_banner and data.get('ports'):
        data['banners'] = banner_grab.run(domain, data['ports'])

    # ── 6. Report ────────────────────────────────────────────────────────────
    report.run(domain, data, args.output)


if __name__ == '__main__':
    main()
