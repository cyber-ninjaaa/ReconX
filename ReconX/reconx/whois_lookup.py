"""WHOIS lookup — uses system whois binary, falls back to RDAP."""

import subprocess
import re
import requests
from . import display as d


RDAP_URL = "https://rdap.org/domain/{}"

_FIELDS = {
    'Registrar':        r'(?i)registrar:\s*(.+)',
    'Created':          r'(?i)creation date:\s*(.+)',
    'Expires':          r'(?i)expir\w+ date:\s*(.+)',
    'Updated':          r'(?i)updated date:\s*(.+)',
    'Name Servers':     r'(?i)name server:\s*(.+)',
    'Registrant Org':   r'(?i)registrant organization:\s*(.+)',
    'Registrant Email': r'(?i)registrant email:\s*(.+)',
    'Status':           r'(?i)domain status:\s*(.+)',
}


def run(domain: str) -> dict:
    d.section("WHOIS Lookup")
    d.info(f"Target: {domain}")

    raw = _whois_binary(domain) or _whois_rdap(domain)
    if not raw:
        d.error("WHOIS failed — no data returned.")
        return {}

    parsed = {}
    for field, pattern in _FIELDS.items():
        matches = re.findall(pattern, raw)
        if matches:
            # Deduplicate, strip, limit to 3
            vals = list(dict.fromkeys(m.strip() for m in matches))[:3]
            parsed[field] = vals

    if parsed:
        for field, vals in parsed.items():
            for v in vals:
                d.result(field, v)
    else:
        d.warn("WHOIS data returned but could not parse fields.")
        d.result("Raw (first 300 chars)", raw[:300])

    return parsed


def _whois_binary(domain: str) -> str | None:
    try:
        result = subprocess.run(
            ['whois', domain],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout if result.stdout else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _whois_rdap(domain: str) -> str | None:
    """Fallback: query RDAP and flatten to pseudo-whois text."""
    try:
        resp = requests.get(RDAP_URL.format(domain), timeout=10)
        resp.raise_for_status()
        data = resp.json()
        lines = []

        lines.append(f"Registrar: {data.get('registrar', {}).get('name', 'N/A')}")

        for event in data.get('events', []):
            action = event.get('eventAction', '')
            date = event.get('eventDate', '')
            if 'registration' in action:
                lines.append(f"Creation Date: {date}")
            elif 'expiration' in action:
                lines.append(f"Expiration Date: {date}")
            elif 'last changed' in action:
                lines.append(f"Updated Date: {date}")

        for ns in data.get('nameservers', []):
            lines.append(f"Name Server: {ns.get('ldhName', '')}")

        for status in data.get('status', []):
            lines.append(f"Domain Status: {status}")

        return '\n'.join(lines)
    except Exception:
        return None
