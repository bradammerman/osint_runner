osint_runner.py

Purpose:
  Build and optionally execute a standard set of OSINT / External Footprint commands
  against one or more authorized targets. This script **will not run** commands unless
  the user passes --yes / --execute. By default it does a dry-run and prints commands.

IMPORTANT: Run this ONLY with explicit written authorization for the targets you test.
The author is responsible for obeying law, policy, and client ROE. The script assumes
the required tools (amass, subfinder, httpx, masscan, nmap, gau, waybackurls, nuclei, gitleaks, etc.)
are installed and on PATH. Some commands require API keys set as environment variables (e.g., SHODAN_API_KEY).

Usage examples (dry-run):
  python3 osint_runner.py -d example.com -o ./outdir

To actually execute (be careful):
  python3 osint_runner.py -d example.com -o ./outdir --yes

Features:
  - Runs a standard sequence: amass, subfinder, crt.sh query, httpx, gau/wayback, masscan, nmap,
    nuclei, gitleaks, gobuster (if URL), shodan (if API key present)
  - Supports multiple domains (-d or --domain multiple times)
  - Dry-run by default; --yes enables execution
  - Logs stdout/stderr to files in output directory
"""
