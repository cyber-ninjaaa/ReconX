"""DNS enumeration — A, AAAA, MX, NS, TXT, CNAME, SOA records."""

import dns.resolver
import dns.reversename
from . import display as d

RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']


def run(domain: str) -> dict:
    d.section("DNS Enumeration")
    d.info(f"Querying all record types for {domain}")

    results = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                val = str(rdata).strip()
                records.append(val)
                d.success(f"{rtype:<8} {val}")
            results[rtype] = records
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            d.error(f"Domain {domain} does not exist (NXDOMAIN).")
            break
        except dns.resolver.Timeout:
            d.warn(f"{rtype} query timed out.")
        except Exception as e:
            d.warn(f"{rtype} query failed: {e}")

    # Reverse DNS on A records
    if 'A' in results:
        d.divider()
        d.info("Reverse DNS (PTR):")
        for ip in results['A']:
            try:
                rev = dns.reversename.from_address(ip)
                ptr = resolver.resolve(rev, 'PTR')
                for p in ptr:
                    d.result(ip, str(p))
            except Exception:
                d.result(ip, "(no PTR record)")

    if not results:
        d.warn("No DNS records found.")

    return results
