"""Subdomain brute-force via DNS resolution."""

import concurrent.futures
import dns.resolver
from . import display as d

# Built-in wordlist — used if no external file provided
BUILTIN_WORDLIST = [
    'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'remote',
    'vpn', 'dev', 'staging', 'test', 'beta', 'api', 'app', 'admin',
    'portal', 'dashboard', 'blog', 'shop', 'store', 'cdn', 'static',
    'media', 'assets', 'img', 'images', 'video', 'docs', 'help',
    'support', 'status', 'monitor', 'mx', 'ns1', 'ns2', 'ns3', 'dns',
    'git', 'gitlab', 'github', 'jenkins', 'ci', 'build', 'deploy',
    'prod', 'production', 'internal', 'intranet', 'corp', 'office',
    'auth', 'login', 'sso', 'id', 'oauth', 'accounts', 'secure',
    'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'elastic',
    'backup', 'archive', 'old', 'legacy', 'new', 'v2', 'v3',
    'mobile', 'm', 'wap', 'ios', 'android', 'download', 'updates',
    'panel', 'cpanel', 'whm', 'plesk', 'webmin', 'phpmyadmin',
    'upload', 'files', 'file', 'data', 'storage', 's3',
    'metrics', 'grafana', 'kibana', 'prometheus', 'elk', 'log', 'logs',
    'smtp', 'relay', 'mx1', 'mx2', 'email', 'newsletter',
    'forum', 'community', 'wiki', 'kb', 'learn', 'training',
    'payment', 'pay', 'billing', 'invoice', 'checkout',
]


def run(domain: str, wordlist_path: str = None, threads: int = 30) -> list:
    d.section("Subdomain Brute-Force")

    wordlist = _load_wordlist(wordlist_path)
    d.info(f"Wordlist: {len(wordlist)} entries | Threads: {threads}")

    found = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    def check(sub):
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, 'A')
            ips = [str(r) for r in answers]
            return fqdn, ips
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check, sub): sub for sub in wordlist}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                fqdn, ips = result
                found.append({'subdomain': fqdn, 'ips': ips})
                d.success(f"{fqdn:<45} → {', '.join(ips)}")

    if not found:
        d.warn("No subdomains discovered.")
    else:
        d.divider()
        d.info(f"Found {len(found)} subdomain(s).")

    return found


def _load_wordlist(path: str | None) -> list:
    if not path:
        return BUILTIN_WORDLIST
    try:
        with open(path) as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return words if words else BUILTIN_WORDLIST
    except FileNotFoundError:
        d.warn(f"Wordlist not found: {path} — using built-in list.")
        return BUILTIN_WORDLIST
