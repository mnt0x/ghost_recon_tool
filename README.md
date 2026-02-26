# Ghost Recon Tool

### Passive Domain Intelligence Platform &nbsp;·&nbsp; by mnt0x

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Type](https://img.shields.io/badge/Type-Passive%20OSINT-purple?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

Ghost Recon Tool is a professional passive OSINT platform for authorized penetration testing and bug bounty hunting. It performs comprehensive domain intelligence gathering using 40+ passive data sources — **zero direct contact with the target**.

---

## Features

- **12 intelligence modules** covering the full attack surface
- **40+ passive data sources** — APIs, certificate logs, DNS, public databases
- **Real-time web interface** with live scan progress via SSE
- **Vulnerability detection** — CVEs, service misconfigurations, exposed ports
- **Subdomain takeover detection** — 60+ service fingerprints
- **Email discovery** — with breach exposure and role classification
- **Technology fingerprinting** — 100+ signatures with confidence scoring
- **DNS intelligence** — DMARC, SPF, DKIM analysis, zone enumeration
- **Breach & exposure intelligence** — HaveIBeenPwned, DeHashed, LeakIX
- **Cloud infrastructure mapping** — AWS, GCP, Azure asset discovery
- **Interactive HTML dashboard** with collapsible sections and risk gauge
- **Export** — JSON, TXT, and full HTML report

---

## Screenshots

*Screenshots coming soon*

---

## Quick Start

**Requirements:** Python 3.8+

```bash
git clone https://github.com/mnt0x/ghost-recon-tool
cd ghost-recon-tool

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux / macOS)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run
python recon.py
```

Open your browser at **http://localhost:5000**

---

## API Keys (Optional)

The tool works without any API keys. Keys unlock additional data sources and higher rate limits.

Copy `.env.example` to `.env` and fill in the keys you have:

```bash
cp .env.example .env
```

| Variable | Service | Cost | What it unlocks |
|---|---|---|---|
| `GRT_GITHUB_TOKEN` | GitHub | Free | Code search, secret exposure |
| `GRT_VIRUSTOTAL` | VirusTotal | Free | Passive DNS, domain reports |
| `GRT_OTX` | AlienVault OTX | Free | Threat intelligence, IOCs |
| `GRT_URLSCAN` | urlscan.io | Free | Screenshots, page analysis |
| `GRT_HUNTER_IO` | Hunter.io | Free (25/mo) | Email discovery |
| `GRT_ABUSEIPDB` | AbuseIPDB | Free | IP reputation scoring |
| `GRT_SECURITYTRAILS` | SecurityTrails | Free (50/mo) | Historical DNS, subdomains |
| `GRT_CENSYS_ID` + `GRT_CENSYS_SECRET` | Censys | Free (250/mo) | Certificate search, hosts |
| `GRT_FULLHUNT` | FullHunt | Free | Attack surface discovery |
| `GRT_HIBP` | HaveIBeenPwned | $3.50/mo | Breach lookup by domain |
| `GRT_INTELX` | IntelligenceX | Free tier | Breach data, dark web |
| `GRT_BINARYEDGE` | BinaryEdge | Paid | Internet scan data |
| `GRT_BEVIGIL` | BeVigil | Free | Mobile app OSINT |
| `GRT_SHODAN` | Shodan | Paid | Open ports, banners |
| `GRT_CHAOS` | ProjectDiscovery | Free | Subdomain datasets |
| `GRT_BING_SEARCH` | Azure Bing | Paid | Dorking, indexed pages |

---

## Usage

### Web UI (recommended)

```bash
python recon.py
# Open http://localhost:5000
```

Select a scan mode, enter the target domain, and watch results populate in real time.

### CLI Mode

```bash
# Basic scan (balanced mode, web UI)
python recon.py -d example.com

# Deep scan, export everything
python recon.py -d example.com --mode deep --output all

# Fast scan, JSON output only
python recon.py -d example.com --mode fast --output json

# Custom port
python recon.py --port 8080
```

### Scan Modes

| Mode | Duration | Coverage |
|---|---|---|
| `fast` | 15–30s | Core sources — quick triage |
| `balanced` | 45–90s | Default — recommended for most targets |
| `deep` | 3–8 min | Maximum coverage — full enumeration |

---

## Intelligence Modules

| Module | What it finds |
|---|---|
| **Subdomain Enumeration** | 15+ sources: crt.sh, Subfinder, Amass, Sonar FDNS, Crobat, Entrust CT, SecurityTrails, Chaos, FullHunt, and more |
| **Email Discovery** | Hunter.io, EmailRep, GitHub dorking, website scraping |
| **DNS Intelligence** | A/AAAA/MX/NS/TXT/CNAME records, SPF/DKIM/DMARC analysis, zone transfer attempts |
| **SSL / TLS Analysis** | Certificate details, SAN enumeration, expiry, CT log entries, grade |
| **IP & ASN Intelligence** | Geolocation, ASN info, CDN detection, cloud provider mapping, abuse score |
| **Technology Fingerprinting** | 100+ signatures: frameworks, CMS, CDN, analytics, security tools |
| **Security Headers** | CSP, HSTS, X-Frame-Options, Referrer-Policy — missing header detection |
| **Breach Intelligence** | HIBP domain search, DeHashed, IntelligenceX, LeakIX |
| **Cloud Asset Discovery** | S3 buckets, Azure Blobs, GCS buckets — public exposure check |
| **Subdomain Takeover** | 60+ fingerprints: GitHub Pages, Heroku, Fastly, AWS, Netlify, and more |
| **Vulnerability Intelligence** | CVE lookup, port-based risk scoring, misconfiguration detection |
| **Wayback / Archive** | Historical URLs, exposed endpoints, archived sensitive paths |

---

## Output

All scan results are saved to the `results/` directory:

```
results/
  {domain}-{scan_id}.json    # Full structured data
  {domain}-{scan_id}.txt     # Human-readable summary
  {domain}-{scan_id}.html    # Standalone HTML report
```

Results are also browsable in the web UI under **History**.

---

## Legal Disclaimer

> **This tool is for authorized security testing only.**
>
> Only use Ghost Recon Tool on domains you own or have explicit written permission to test. Unauthorized reconnaissance may be illegal in your jurisdiction. The author is not responsible for any misuse, damage, or legal consequences arising from use of this tool.

---

## Author

**mnt0x**

Built for professional penetration testing and bug bounty hunting.
---


