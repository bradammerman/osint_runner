# OSINT Runner

A comprehensive OSINT (Open Source Intelligence) reconnaissance tool for penetration testing. Performs passive reconnaissance against target domains to gather intelligence about subdomains, live hosts, URLs, vulnerabilities, and security configurations.

> **⚠️ IMPORTANT:** Only use this tool with explicit written authorization for your targets!

## Supported Operating Systems

| OS | Status | Package Manager |
|----|--------|-----------------|
| **macOS** (Intel & Apple Silicon) | ✅ Fully Supported | Homebrew |
| **Linux** (Debian/Ubuntu) | ✅ Fully Supported | apt + Go |
| **Linux** (RHEL/CentOS/Fedora) | ⚠️ Partial | Go + manual install |
| **Kali Linux** | ✅ Fully Supported | apt (most tools pre-installed) |
| **Windows** | ❌ Not Supported | Use WSL2 with Ubuntu |

### WSL2 (Windows Subsystem for Linux)

For Windows users, install WSL2 with Ubuntu:
```powershell
wsl --install -d Ubuntu
```
Then run the tool inside the WSL2 Ubuntu terminal.

## Features

- **Subdomain Enumeration** - amass, subfinder, crt.sh
- **HTTP Probing** - httpx (discover live hosts)
- **DNS Resolution** - dnsx (A, AAAA, CNAME, MX, NS, TXT records)
- **URL Discovery** - gau (GetAllUrls) + waybackurls (Wayback Machine historical URLs)
- **Email & Contact Harvesting** - theHarvester + email format permutation generator
- **Email Security Analysis** - SPF, DKIM, DMARC record checks
- **TLS/SSL Analysis** - sslscan (cipher suites, protocols, vulnerabilities)
- **Security Headers** - HTTP security header analysis
- **Technology Fingerprinting** - whatweb (identify tech stack)
- **Banner Grabbing** - HTTP server banners, headers, and technology detection
- **Cloud/SaaS Detection** - Pattern matching for AWS, Azure, GCP, Cloudflare, etc.
- **Shodan Integration** - Search for exposed services (requires API key)
- **Combined Reporting** - All results in a single beautified report with remediation advice
- **Parallel Execution** - Multi-threaded scanning for faster results

## Quick Start

```bash
# 1. Check what tools you have installed
python3 osint_runner.py --status

# 2. Install missing tools (macOS/Linux)
python3 osint_runner.py --install-tools

# 3. (Optional) Configure Shodan API key
python3 osint_runner.py --configure

# 4. Run a scan
python3 osint_runner.py -d example.com -o ./output --yes --parallel
```

## Installation

### Prerequisites

- Python 3.8+
- macOS or Linux
- One of: Homebrew (macOS), apt (Debian/Ubuntu), or Go

### Install Tools

The script can automatically install all required tools:

```bash
python3 osint_runner.py --install-tools
```

Or install manually:

| Tool | Homebrew (macOS) | Apt (Linux) | Go/Pip |
|------|------------------|-------------|--------|
| amass | `brew install amass` | `apt install amass` | `go install github.com/owasp-amass/amass/v4/...@master` |
| subfinder | `brew install subfinder` | - | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx | `brew install httpx` | `apt install httpx-toolkit` | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| dnsx | - | - | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| gau (getallurls) | - | - | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| waybackurls | - | - | `go install github.com/tomnomnom/waybackurls@latest` |
| theHarvester | - | `apt install theharvester` | `pip install theHarvester` |
| sslscan | `brew install sslscan` | `apt install sslscan` | - |
| whatweb | `brew install whatweb` | `apt install whatweb` | - |
| shodan | - | - | `pip install shodan` |
| jq | `brew install jq` | `apt install jq` | - |
| dig | (built-in) | `apt install dnsutils` | - |

### API Keys

**Shodan** (optional but recommended):
```bash
# Configure interactively
python3 osint_runner.py --configure

# Or set environment variable
export SHODAN_API_KEY=your_api_key_here
```

Get a free Shodan API key at: https://account.shodan.io/

## Usage

### Basic Commands

```bash
# Dry-run (preview commands without executing)
python3 osint_runner.py -d example.com -o ./output

# Full scan with combined report (default)
python3 osint_runner.py -d example.com -o ./output --yes

# Parallel execution (faster)
python3 osint_runner.py -d example.com -o ./output --yes --parallel

# Fast scan (skip extra security checks)
python3 osint_runner.py -d example.com -o ./output --yes --parallel --fast

# Scan multiple domains
python3 osint_runner.py -d target1.com -d target2.com -o ./output --yes --parallel
```

### Recommended Command

For a full-featured scan with maximum speed:

```bash
python3 osint_runner.py -d TARGET.com -o ./output --yes --parallel

# Short form
python3 osint_runner.py -d TARGET.com -o ./output -y -p
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-d, --domain` | Target domain(s) - can be used multiple times |
| `-o, --outdir` | Output directory (default: ./osint_out) |
| `--yes, -y` | Execute commands (default is dry-run mode) |
| `--parallel, -p` | Run tools in parallel (faster) |
| `--workers N, -w` | Number of parallel workers (default: 4) |
| `--timeout SEC` | Timeout per tool in seconds (default: 180s) |
| `--skip-slow` | Skip slow tools (amass, subfinder) - use crt.sh only |
| `--fast, -f` | Skip extra checks (email, TLS, headers, tech, cloud) |
| `--no-report` | Skip combined report, keep individual files only |
| `--no-email` | Skip email security checks |
| `--no-tls` | Skip TLS/SSL analysis |
| `--no-headers` | Skip security headers check |
| `--no-tech` | Skip technology fingerprinting |
| `--no-cloud` | Skip cloud/SaaS detection |
| `--no-prompt` | Skip interactive prompts (for scripted use) |
| `--install-tools` | Install all required tools |
| `--configure` | Configure API keys |
| `--status` | Show tool and API key status |

## Output

### Combined Report (Default)

All results are combined into a single file for easy reading:

```
<output_dir>/<domain>/OSINT_REPORT.txt
```

The report includes:
1. Executive Summary
2. Subdomains Discovered
3. Live Hosts (httpx)
4. DNS Resolution (dnsx)
5. URLs Discovered (GAU + Wayback Machine)
6. Email Security Analysis (SPF/DKIM/DMARC)
7. Security Headers Analysis
8. TLS/SSL Analysis
9. Technology Stack & Fingerprinting
10. Banner Grabbing Results
11. Cloud/SaaS Detection
12. Shodan Intelligence
13. Email & Contact Harvesting (theHarvester)
14. Findings & Remediation Recommendations

### Individual Files

For programmatic access, individual files are also created:

| File | Description |
|------|-------------|
| `OSINT_REPORT.txt` | Combined report with all results |
| `subdomains_*.txt` | All discovered subdomains |
| `httpx_results.json` | Live HTTP services (JSON format) |
| `dnsx_results.json` | DNS resolution records (JSON) |
| `dnsx_results.txt` | DNS resolution records (text) |
| `gau_*.txt` | Historical URLs from GetAllUrls |
| `wayback_*.txt` | URLs from Wayback Machine |
| `urls_combined.txt` | Merged URLs from all sources |
| `harvester_*.json` | Email addresses, names, hosts found |
| `email_permutations_*.txt` | Generated email format variations |
| `email_security_*.txt` | SPF/DKIM/DMARC analysis |
| `sslscan_*.txt` | TLS/SSL details |
| `security_headers_*.txt` | HTTP security headers |
| `whatweb_*.txt` | Technology fingerprinting |
| `tech_fingerprint_*.txt` | Built-in curl fingerprinting |
| `http_headers_*.txt` | Raw HTTP headers |
| `cloud_hints.txt` | Cloud service detection |
| `commands.log` | All commands executed |

## Scan Phases

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Phase 1: Subdomain Enumeration (PARALLEL)                               │
│   crt.sh ──┬── amass ──┬── subfinder    → run simultaneously            │
├─────────────────────────────────────────────────────────────────────────┤
│ Phase 2: Merge & Probe (SEQUENTIAL - needs Phase 1 results)             │
│   merge subdomains → httpx (probe live hosts) → dnsx (DNS resolution)   │
├─────────────────────────────────────────────────────────────────────────┤
│ Phase 3: URL Discovery (PARALLEL)                                       │
│   gau ──┬── waybackurls ──┬── shodan    → run simultaneously            │
├─────────────────────────────────────────────────────────────────────────┤
│ Phase 4: Email & Contact Discovery                                      │
│   theHarvester (emails, names, hosts, IPs)                              │
├─────────────────────────────────────────────────────────────────────────┤
│ Phase 5: Security Checks & Fingerprinting (PARALLEL, skip with --fast)  │
│   email ──┬── sslscan ──┬── headers ──┬── whatweb ──┬── banners         │
│   cloud detection (pattern matching)                                    │
└─────────────────────────────────────────────────────────────────────────┘

Sequential mode: ~5-8 min  |  Parallel mode (--parallel): ~2-3 min
```

## Examples

### Penetration Test Reconnaissance

```bash
# Full recon with all checks
python3 osint_runner.py -d target.com -o ./pentest_output --yes --parallel

# Quick recon (skip extra checks)
python3 osint_runner.py -d target.com -o ./pentest_output --yes --parallel --fast

# Multiple targets
python3 osint_runner.py -d target1.com -d target2.com -d target3.com -o ./pentest_output --yes --parallel
```

### Fast Scanning (Skip Slow Tools)

```bash
# Skip amass/subfinder (they can take 10+ minutes) - RECOMMENDED
python3 osint_runner.py -d target.com -o ./output --yes --parallel --skip-slow

# Custom timeout (60 seconds per tool instead of 180s default)
python3 osint_runner.py -d target.com -o ./output --yes --parallel --timeout 60

# Fastest possible scan: skip slow + fast mode + short timeout
python3 osint_runner.py -d target.com -o ./output --yes --parallel --skip-slow --fast --timeout 60
```

### Automated/Scripted Usage

```bash
# No prompts, suitable for cron jobs or CI/CD
python3 osint_runner.py -d target.com -o ./output --yes --parallel --no-prompt

# Scripted with timeout protection
python3 osint_runner.py -d target.com -o ./output --yes --parallel --no-prompt --timeout 120
```

### Selective Scanning

```bash
# Skip email checks (no MX records)
python3 osint_runner.py -d target.com -o ./output --yes --no-email

# Skip slow tools and extra checks (fastest)
python3 osint_runner.py -d target.com -o ./output --yes --skip-slow --fast
```

## First-Run Wizard

Running the script without arguments launches an interactive setup wizard:

```bash
python3 osint_runner.py
```

The wizard will:
1. Check for installed tools
2. Offer to install missing tools
3. Configure API keys
4. Guide you through your first scan

## Troubleshooting

### Tools Not Installing

**macOS:** Install Homebrew first: https://brew.sh/

**Linux:** Ensure you have `apt` and optionally `Go` installed:
```bash
sudo apt update
sudo apt install golang-go
```

### Shodan Not Working

Ensure your API key is configured:
```bash
python3 osint_runner.py --configure
# or
export SHODAN_API_KEY=your_key
```

### Permission Errors

Some tools may require elevated permissions on certain systems. Try running with `sudo` if needed.

## License

This tool is provided for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any targets.

## Contributing

Contributions are welcome! Please ensure any additions:
- Include proper error handling
- Support both macOS and Linux
- Follow the existing code style
- Include help documentation

---

**Remember:** Always obtain proper authorization before performing reconnaissance on any target!
