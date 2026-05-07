# ReconX

**Automated Reconnaissance Framework**

ReconX is a modular Python CLI tool that chains together the full passive and active recon pipeline against a target domain — WHOIS → DNS enumeration → subdomain brute-force → port scanning → banner grabbing — and outputs a structured JSON report with a color-coded terminal summary.

```
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
```

---

## Pipeline

```
Target Domain
     │
     ├─ 1. WHOIS          Registrar, dates, name servers, status
     ├─ 2. DNS Enum        A, AAAA, MX, NS, TXT, CNAME, SOA + reverse PTR
     ├─ 3. Subdomain BF    Concurrent DNS brute-force (built-in or custom wordlist)
     ├─ 4. Port Scan       nmap -sV (fallback: pure socket scan, top 40 ports)
     ├─ 5. Banner Grab     HTTP headers, security header audit, SSL cert, TCP banners
     └─ 6. Report          Color-coded terminal summary + timestamped JSON report
```

---

## Features

- Full recon chain in one command
- Concurrent subdomain brute-force (30 threads by default)
- nmap `-sV` integration with pure-socket fallback
- SSL/TLS certificate inspection (CN, issuer, SANs, cipher, TLS version)
- HTTP security header audit (HSTS, CSP, X-Frame-Options, etc.) with a score
- RDAP fallback if system `whois` is unavailable
- Modular — skip any stage with `--no-*` flags
- Structured JSON report saved per scan with timestamp

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/ReconX.git
cd ReconX
pip install -r requirements.txt
```

Optional but recommended:
```bash
# For enhanced port scanning
sudo apt install nmap whois    # Debian/Ubuntu
brew install nmap whois        # macOS
```

---

## Usage

```bash
python main.py <domain> [OPTIONS]
```

### Examples

```bash
# Full recon
python main.py example.com

# Custom wordlist + more threads
python main.py example.com -w wordlists/top10k.txt -t 50

# Skip subdomain brute-force and port scan (fast passive recon)
python main.py example.com --no-subs --no-ports

# Force socket scan (no nmap)
python main.py example.com --no-nmap

# Save output to custom directory
python main.py example.com -o reports/
```

### Flags

| Flag | Description |
|------|-------------|
| `-w <path>` | Custom subdomain wordlist |
| `-t <int>` | Threads for subdomain brute-force (default: 30) |
| `-o <dir>` | Output directory (default: `output/`) |
| `--no-whois` | Skip WHOIS lookup |
| `--no-dns` | Skip DNS enumeration |
| `--no-subs` | Skip subdomain brute-force |
| `--no-ports` | Skip port scanning |
| `--no-banner` | Skip banner grabbing |
| `--no-nmap` | Force socket scan even if nmap is installed |
| `-q` | Suppress banner |

---

## Project Structure

```
ReconX/
├── reconx/
│   ├── __init__.py
│   ├── display.py          # Colored terminal output helpers
│   ├── whois_lookup.py     # WHOIS + RDAP fallback
│   ├── dns_enum.py         # DNS record enumeration + PTR
│   ├── subdomain_brute.py  # Concurrent subdomain brute-force
│   ├── port_scan.py        # nmap / socket port scanner
│   ├── banner_grab.py      # HTTP headers, SSL cert, TCP banners
│   └── report.py           # Terminal summary + JSON report
│
├── wordlists/              # Drop custom wordlists here
├── output/                 # Reports saved here (gitignored)
├── main.py
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

---

## Output

Terminal: color-coded live results per stage + final summary with security header score.

JSON report (`output/recon_example.com_20240801_143022.json`):
```json
{
    "meta": { "target": "example.com", "timestamp": "...", "tool": "ReconX v1.0" },
    "whois": { "Registrar": ["..."], "Expires": ["..."] },
    "dns": { "A": ["93.184.216.34"], "MX": [...] },
    "subdomains": [{ "subdomain": "www.example.com", "ips": ["93.184.216.34"] }],
    "ports": [{ "port": 443, "service": "https", "version": "nginx 1.24" }],
    "banners": { "ssl_cert": { "subject_cn": "example.com", "tls_version": "TLSv1.3" } }
}
```

---

## Legal Disclaimer

> This tool is intended for **authorized security testing and educational purposes only**.  
> Only run against domains you own or have explicit written permission to test.  
> The author is not responsible for misuse or illegal activity.

---

## License

MIT — see [LICENSE](LICENSE)

---

## Author

**Amine Bououd** — Cybersecurity  
Part of a growing offensive/defensive security toolkit alongside [VTScanX](https://github.com/YOUR_USERNAME/VTScanX).
