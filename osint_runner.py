#!/usr/bin/env python3
"""
osint_runner.py

Purpose:
  OSINT / External Footprint reconnaissance tool for penetration testing.
  Dry-run by default (shows commands). Use --yes to execute.

IMPORTANT: Run ONLY with explicit written authorization for your targets.

Installation:
  python3 osint_runner.py --install-tools    # Auto-install all tools (macOS/Linux)
  python3 osint_runner.py --status           # Check what's installed

Usage:
  python3 osint_runner.py -d example.com -o ./out           # Dry-run
  python3 osint_runner.py -d example.com -o ./out --yes     # Execute
  python3 osint_runner.py -d example.com -o ./out --yes --fast  # Skip extra checks

Features:
  - Subdomain enumeration: amass, subfinder, crt.sh
  - URL discovery: gau, httpx probing
  - Vulnerability scanning: nuclei
  - Email security: SPF/DKIM/DMARC checks (dig)
  - TLS/SSL analysis: sslscan
  - Security headers: snapshot and analysis (curl)
  - Tech fingerprinting: whatweb
  - Cloud/SaaS detection: pattern matching on subdomains
  - Shodan search (requires SHODAN_API_KEY env var)

Flags:
  --fast       Skip extra checks (email, TLS, headers, tech, cloud)
  --no-email   Skip email security checks only
  --no-tls     Skip TLS checks only
  --no-headers Skip security headers only
  --no-tech    Skip tech fingerprinting only
  --no-cloud   Skip cloud detection only
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, UTC
from pathlib import Path
from urllib.parse import urlparse
import threading
import time
import textwrap

# Thread-safe print lock for parallel execution
print_lock = threading.Lock()

# === ANSI Color Codes ===
class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'      # Magenta
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'          # Reset
    
    # Severity colors
    CRITICAL = '\033[91m'    # Red
    HIGH = '\033[38;5;208m'  # Orange
    MEDIUM = '\033[93m'      # Yellow
    LOW = '\033[94m'         # Blue
    INFO = '\033[96m'        # Cyan
    GOOD = '\033[92m'        # Green

    @classmethod
    def disable(cls):
        """Disable colors (for file output)."""
        cls.HEADER = cls.BLUE = cls.CYAN = cls.GREEN = ''
        cls.YELLOW = cls.RED = cls.WHITE = cls.BOLD = ''
        cls.UNDERLINE = cls.END = cls.CRITICAL = cls.HIGH = ''
        cls.MEDIUM = cls.LOW = cls.INFO = cls.GOOD = ''


# === Remediation Suggestions ===
REMEDIATIONS = {
    # Email Security
    "spf_missing": {
        "severity": "HIGH",
        "finding": "SPF Record Missing",
        "description": "No SPF record found. Email spoofing is possible.",
        "remediation": """Add an SPF record to your DNS:
    Example: v=spf1 include:_spf.google.com ~all
    
    Recommended actions:
    1. Identify all legitimate mail servers
    2. Create SPF record with 'include' for third-party senders
    3. Use '-all' (hard fail) instead of '~all' (soft fail) for stricter enforcement"""
    },
    "spf_softfail": {
        "severity": "MEDIUM",
        "finding": "SPF Uses Soft Fail (~all)",
        "description": "SPF record uses '~all' which only marks failures, doesn't reject.",
        "remediation": """Change '~all' to '-all' for stricter enforcement:
    Current: v=spf1 ... ~all
    Recommended: v=spf1 ... -all
    
    Note: Test thoroughly before changing to hard fail."""
    },
    "dmarc_missing": {
        "severity": "HIGH",
        "finding": "DMARC Record Missing",
        "description": "No DMARC record found. No policy for email authentication failures.",
        "remediation": """Add a DMARC record to your DNS at _dmarc.yourdomain.com:
    Start with: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com
    
    Progression path:
    1. p=none (monitor only) - Start here
    2. p=quarantine (spam folder) - After reviewing reports
    3. p=reject (block) - Full protection"""
    },
    "dmarc_none": {
        "severity": "MEDIUM",
        "finding": "DMARC Policy Set to None",
        "description": "DMARC policy is 'none' - monitoring only, no enforcement.",
        "remediation": """Upgrade DMARC policy for enforcement:
    Current: p=none
    Recommended: p=quarantine or p=reject
    
    Before changing:
    1. Review DMARC reports for legitimate senders
    2. Ensure SPF and DKIM are properly configured
    3. Gradually move from 'none' → 'quarantine' → 'reject'"""
    },
    "dkim_missing": {
        "severity": "MEDIUM",
        "finding": "DKIM Not Configured",
        "description": "No DKIM records found for common selectors.",
        "remediation": """Configure DKIM for your email:
    1. Generate DKIM keys through your email provider
    2. Add the public key as a TXT record: selector._domainkey.yourdomain.com
    3. Enable DKIM signing on your mail server
    
    Common selectors to configure:
    - google (Gmail/Workspace)
    - selector1, selector2 (Microsoft 365)
    - default, mail (generic)"""
    },
    
    # Security Headers
    "hsts_missing": {
        "severity": "HIGH",
        "finding": "Strict-Transport-Security (HSTS) Missing",
        "description": "HSTS header not present. Users can be downgraded to HTTP.",
        "remediation": """Add HSTS header to enforce HTTPS:
    Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
    
    Implementation:
    - Apache: Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    - Nginx: add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    Consider HSTS preloading: https://hstspreload.org/"""
    },
    "csp_missing": {
        "severity": "HIGH",
        "finding": "Content-Security-Policy (CSP) Missing",
        "description": "No CSP header. XSS attacks are more likely to succeed.",
        "remediation": """Add a Content-Security-Policy header:
    Start with report-only mode:
    Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report
    
    Example strict policy:
    Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';
    
    Use https://report-uri.com/ to monitor violations."""
    },
    "xfo_missing": {
        "severity": "MEDIUM",
        "finding": "X-Frame-Options Missing",
        "description": "No clickjacking protection. Site can be embedded in iframes.",
        "remediation": """Add X-Frame-Options header:
    X-Frame-Options: DENY (or SAMEORIGIN if framing is needed)
    
    Modern alternative (use both):
    Content-Security-Policy: frame-ancestors 'none';"""
    },
    "xcto_missing": {
        "severity": "MEDIUM",
        "finding": "X-Content-Type-Options Missing",
        "description": "Browser may MIME-sniff responses, potentially executing malicious content.",
        "remediation": """Add X-Content-Type-Options header:
    X-Content-Type-Options: nosniff
    
    This prevents browsers from MIME-sniffing and executing content as a different type."""
    },
    "referrer_missing": {
        "severity": "LOW",
        "finding": "Referrer-Policy Missing",
        "description": "No referrer policy. Sensitive URLs may leak to third parties.",
        "remediation": """Add Referrer-Policy header:
    Referrer-Policy: strict-origin-when-cross-origin
    
    Options (from most to least restrictive):
    - no-referrer
    - same-origin  
    - strict-origin-when-cross-origin (recommended)
    - no-referrer-when-downgrade"""
    },
    "permissions_missing": {
        "severity": "LOW",
        "finding": "Permissions-Policy Missing",
        "description": "No feature restrictions. Browser features can be abused.",
        "remediation": """Add Permissions-Policy header to restrict browser features:
    Permissions-Policy: geolocation=(), microphone=(), camera=()
    
    Restrict features you don't need:
    - geolocation, microphone, camera
    - payment, usb, magnetometer
    - accelerometer, gyroscope"""
    },
    
    # TLS/SSL
    "tls_weak_cipher": {
        "severity": "MEDIUM",
        "finding": "Weak TLS Cipher Suites Enabled",
        "description": "Server supports weak or deprecated cipher suites.",
        "remediation": """Disable weak ciphers and enable only strong ones:
    
    Recommended cipher suites (Mozilla Modern):
    TLS_AES_128_GCM_SHA256
    TLS_AES_256_GCM_SHA384
    TLS_CHACHA20_POLY1305_SHA256
    
    Disable: RC4, DES, 3DES, MD5-based ciphers, export ciphers"""
    },
    "tls_old_version": {
        "severity": "HIGH",
        "finding": "Outdated TLS Versions Supported",
        "description": "Server supports TLS 1.0 or 1.1 which are deprecated.",
        "remediation": """Disable TLS 1.0 and 1.1, require TLS 1.2+:
    
    Nginx: ssl_protocols TLSv1.2 TLSv1.3;
    Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    
    TLS 1.3 is recommended for best security."""
    },
    
    # Cloud/Infrastructure
    "cloud_s3_bucket": {
        "severity": "INFO",
        "finding": "AWS S3 Bucket Detected",
        "description": "S3 bucket references found in subdomains.",
        "remediation": """Verify S3 bucket security:
    1. Check bucket policy for public access
    2. Enable S3 Block Public Access
    3. Review bucket ACLs
    4. Enable access logging
    
    Test with: aws s3 ls s3://bucket-name --no-sign-request"""
    },
    "cloud_azure_blob": {
        "severity": "INFO", 
        "finding": "Azure Blob Storage Detected",
        "description": "Azure storage references found.",
        "remediation": """Verify Azure storage security:
    1. Check container access level (private recommended)
    2. Use SAS tokens with minimal permissions
    3. Enable storage analytics logging
    4. Review network rules"""
    },
}


class ReportGenerator:
    """Generate combined, beautified reports with remediation suggestions."""
    
    def __init__(self, domain, output_dir, use_colors=True):
        self.domain = domain
        self.output_dir = output_dir
        self.findings = []
        self.use_colors = use_colors
        if not use_colors:
            Colors.disable()
    
    def _header(self, text, char="═", width=80):
        """Create a section header."""
        c = Colors
        line = char * width
        return f"\n{c.BOLD}{c.CYAN}{line}{c.END}\n{c.BOLD}{c.WHITE}  {text}{c.END}\n{c.BOLD}{c.CYAN}{line}{c.END}\n"
    
    def _subheader(self, text):
        """Create a subsection header."""
        c = Colors
        return f"\n{c.BOLD}{c.YELLOW}▸ {text}{c.END}\n{'─' * 60}\n"
    
    def _severity_color(self, severity):
        """Get color for severity level."""
        c = Colors
        return {
            "CRITICAL": c.CRITICAL,
            "HIGH": c.HIGH,
            "MEDIUM": c.MEDIUM,
            "LOW": c.LOW,
            "INFO": c.INFO,
            "GOOD": c.GOOD,
        }.get(severity.upper(), c.WHITE)
    
    def _severity_badge(self, severity):
        """Create a colored severity badge."""
        c = Colors
        color = self._severity_color(severity)
        return f"{color}[{severity}]{c.END}"
    
    def add_finding(self, finding_key, extra_info=""):
        """Add a finding with remediation suggestion."""
        if finding_key in REMEDIATIONS:
            finding = REMEDIATIONS[finding_key].copy()
            finding["extra_info"] = extra_info
            self.findings.append(finding)
    
    def _read_file(self, filename):
        """Read a file from the output directory."""
        filepath = os.path.join(self.output_dir, filename)
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    return f.read()
            except:
                return None
        return None
    
    def _analyze_email_security(self, content):
        """Analyze email security results and add findings."""
        if not content:
            return
        
        # Check SPF
        if "=== SPF Record ===" in content:
            spf_section = content.split("=== SPF Record ===")[1].split("===")[0]
            if not spf_section.strip() or "v=spf1" not in spf_section.lower():
                self.add_finding("spf_missing")
            elif "~all" in spf_section:
                self.add_finding("spf_softfail")
        
        # Check DMARC
        if "=== DMARC Record ===" in content:
            dmarc_section = content.split("=== DMARC Record ===")[1].split("===")[0]
            if not dmarc_section.strip() or "v=dmarc1" not in dmarc_section.lower():
                self.add_finding("dmarc_missing")
            elif "p=none" in dmarc_section.lower():
                self.add_finding("dmarc_none")
        
        # Check DKIM
        if "=== DKIM Records ===" in content:
            dkim_section = content.split("=== DKIM Records ===")[1]
            if "v=dkim1" not in dkim_section.lower():
                self.add_finding("dkim_missing")
    
    def _analyze_security_headers(self, content):
        """Analyze security headers and add findings."""
        if not content:
            return
        
        if "[MISSING] Strict-Transport-Security" in content:
            self.add_finding("hsts_missing")
        if "[MISSING] Content-Security-Policy" in content:
            self.add_finding("csp_missing")
        if "[MISSING] X-Frame-Options" in content:
            self.add_finding("xfo_missing")
        if "[MISSING] X-Content-Type-Options" in content:
            self.add_finding("xcto_missing")
        if "[MISSING] Referrer-Policy" in content:
            self.add_finding("referrer_missing")
        if "[MISSING] Permissions-Policy" in content:
            self.add_finding("permissions_missing")
    
    def _analyze_cloud_hints(self, content):
        """Analyze cloud detection results and add findings."""
        if not content:
            return
        
        if "[AWS]" in content:
            self.add_finding("cloud_s3_bucket")
        if "[Azure]" in content:
            self.add_finding("cloud_azure_blob")
    
    def generate(self):
        """Generate the combined report."""
        c = Colors
        report = []
        
        # Title
        report.append(f"""
{c.BOLD}{c.CYAN}╔{'═'*78}╗{c.END}
{c.BOLD}{c.CYAN}║{c.END}{c.BOLD}{c.WHITE}{'OSINT RECONNAISSANCE REPORT':^78}{c.END}{c.BOLD}{c.CYAN}║{c.END}
{c.BOLD}{c.CYAN}║{c.END}{c.WHITE}{f'Target: {self.domain}':^78}{c.END}{c.BOLD}{c.CYAN}║{c.END}
{c.BOLD}{c.CYAN}║{c.END}{c.WHITE}{f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}':^78}{c.END}{c.BOLD}{c.CYAN}║{c.END}
{c.BOLD}{c.CYAN}╚{'═'*78}╝{c.END}
""")
        
        # Table of Contents
        report.append(self._header("TABLE OF CONTENTS"))
        report.append(f"""  1. Executive Summary
  2. Subdomains Discovered
  3. Live Hosts (httpx)
  4. URLs Discovered (GAU)
  5. Email Security Analysis (SPF/DKIM/DMARC)
  6. Security Headers Analysis
  7. TLS/SSL Analysis
  8. Technology Stack
  9. Cloud/SaaS Detection
  10. Shodan Intelligence
  11. Nuclei Vulnerability Findings
  12. Findings & Remediation Recommendations
""")
        
        # Executive Summary
        report.append(self._header("1. EXECUTIVE SUMMARY"))
        
        # Read all files for analysis
        subdomains = self._read_file(f"subdomains_{self.domain.replace('.', '_')}.txt") or \
                     self._read_file(f"subdomains_{self.domain}.txt")
        email_security = self._read_file(f"email_security_{self.domain.replace('.', '_')}.txt") or \
                        self._read_file(f"email_security_{self.domain}.txt")
        headers_https = self._read_file(f"security_headers_https_{self.domain.replace('.', '_')}.txt") or \
                       self._read_file(f"security_headers_https_{self.domain}.txt")
        cloud_hints = self._read_file("cloud_hints.txt")
        
        # Analyze for findings
        self._analyze_email_security(email_security)
        self._analyze_security_headers(headers_https)
        self._analyze_cloud_hints(cloud_hints)
        
        # Count findings by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        subdomain_count = len(subdomains.strip().split('\n')) if subdomains and subdomains.strip() else 0
        
        report.append(f"""
  {c.BOLD}Target Domain:{c.END} {self.domain}
  {c.BOLD}Subdomains Found:{c.END} {subdomain_count}
  
  {c.BOLD}Findings Summary:{c.END}
    {c.CRITICAL}■ Critical:{c.END} {severity_counts['CRITICAL']}
    {c.HIGH}■ High:{c.END}     {severity_counts['HIGH']}
    {c.MEDIUM}■ Medium:{c.END}   {severity_counts['MEDIUM']}
    {c.LOW}■ Low:{c.END}      {severity_counts['LOW']}
    {c.INFO}■ Info:{c.END}     {severity_counts['INFO']}
""")
        
        # Subdomains
        report.append(self._header("2. SUBDOMAINS DISCOVERED"))
        if subdomains and subdomains.strip():
            for sub in subdomains.strip().split('\n')[:50]:  # Limit to 50
                report.append(f"  • {sub}\n")
            if subdomain_count > 50:
                report.append(f"\n  ... and {subdomain_count - 50} more (see full file)\n")
        else:
            report.append(f"  {c.YELLOW}No subdomains discovered.{c.END}\n")
        
        # Live Hosts (httpx)
        report.append(self._header("3. LIVE HOSTS (HTTPX)"))
        httpx_results = self._read_file("httpx_results.json")
        if httpx_results and httpx_results.strip():
            live_hosts = []
            for line in httpx_results.strip().split('\n'):
                try:
                    data = json.loads(line)
                    url = data.get("url", "")
                    status = data.get("status_code", "")
                    title = data.get("title", "")[:50] if data.get("title") else ""
                    live_hosts.append(f"  [{status}] {url}" + (f" - {title}" if title else ""))
                except:
                    continue
            if live_hosts:
                for host in live_hosts[:100]:  # Limit to 100
                    report.append(f"{host}\n")
                if len(live_hosts) > 100:
                    report.append(f"\n  ... and {len(live_hosts) - 100} more hosts\n")
            else:
                report.append(f"  {c.YELLOW}No live hosts found.{c.END}\n")
        else:
            report.append(f"  {c.YELLOW}HTTP probing not performed.{c.END}\n")
        
        # URLs Discovered (GAU)
        report.append(self._header("4. URLs DISCOVERED (GAU)"))
        urls_combined = self._read_file("urls_combined.txt") or \
                       self._read_file(f"gau_{self.domain.replace('.', '_')}.txt")
        if urls_combined and urls_combined.strip():
            url_list = urls_combined.strip().split('\n')
            url_count = len(url_list)
            for url in url_list[:50]:  # Limit to 50
                report.append(f"  • {url}\n")
            if url_count > 50:
                report.append(f"\n  ... and {url_count - 50} more URLs\n")
        else:
            report.append(f"  {c.YELLOW}URL discovery not performed.{c.END}\n")
        
        # Email Security
        report.append(self._header("5. EMAIL SECURITY ANALYSIS"))
        if email_security:
            # Format nicely
            report.append(f"{c.WHITE}{email_security}{c.END}\n")
        else:
            report.append(f"  {c.YELLOW}Email security check not performed.{c.END}\n")
        
        # Security Headers
        report.append(self._header("6. SECURITY HEADERS ANALYSIS"))
        if headers_https:
            # Color code the results
            formatted = headers_https
            formatted = formatted.replace("[FOUND]", f"{c.GREEN}[FOUND]{c.END}")
            formatted = formatted.replace("[MISSING]", f"{c.RED}[MISSING]{c.END}")
            report.append(f"{formatted}\n")
        else:
            report.append(f"  {c.YELLOW}Security headers check not performed.{c.END}\n")
        
        # TLS/SSL
        report.append(self._header("7. TLS/SSL ANALYSIS"))
        sslscan_file = self._read_file(f"sslscan_{self.domain.replace('.', '_')}.txt") or \
                      self._read_file(f"sslscan_{self.domain}.txt")
        if sslscan_file:
            report.append(f"{c.WHITE}{sslscan_file[:3000]}{c.END}\n")  # Limit length
            if len(sslscan_file) > 3000:
                report.append(f"\n  ... (truncated, see full file)\n")
        else:
            report.append(f"  {c.YELLOW}TLS/SSL check not performed.{c.END}\n")
        
        # Technology Stack
        report.append(self._header("8. TECHNOLOGY STACK"))
        whatweb_file = self._read_file(f"whatweb_https_{self.domain.replace('.', '_')}.txt") or \
                      self._read_file(f"whatweb_https_{self.domain}.txt")
        if whatweb_file:
            report.append(f"{c.WHITE}{whatweb_file}{c.END}\n")
        else:
            report.append(f"  {c.YELLOW}Technology fingerprinting not performed.{c.END}\n")
        
        # Cloud Detection
        report.append(self._header("9. CLOUD/SAAS DETECTION"))
        if cloud_hints:
            report.append(f"{c.WHITE}{cloud_hints}{c.END}\n")
        else:
            report.append(f"  {c.YELLOW}Cloud detection not performed.{c.END}\n")
        
        # Shodan Intelligence
        report.append(self._header("10. SHODAN INTELLIGENCE"))
        shodan_results = self._read_file("shodan.txt")
        if shodan_results and shodan_results.strip():
            report.append(f"{c.WHITE}{shodan_results}{c.END}\n")
        else:
            report.append(f"  {c.YELLOW}Shodan search not performed (API key required).{c.END}\n")
        
        # Nuclei Findings
        report.append(self._header("11. NUCLEI VULNERABILITY FINDINGS"))
        nuclei_findings = self._read_file("nuclei_findings.txt")
        if nuclei_findings and nuclei_findings.strip():
            # Color-code severity levels in nuclei output
            formatted = nuclei_findings
            formatted = formatted.replace("[critical]", f"{c.CRITICAL}[critical]{c.END}")
            formatted = formatted.replace("[high]", f"{c.HIGH}[high]{c.END}")
            formatted = formatted.replace("[medium]", f"{c.MEDIUM}[medium]{c.END}")
            formatted = formatted.replace("[low]", f"{c.LOW}[low]{c.END}")
            formatted = formatted.replace("[info]", f"{c.INFO}[info]{c.END}")
            report.append(f"{formatted}\n")
        else:
            report.append(f"  {c.YELLOW}Nuclei vulnerability scan not performed.{c.END}\n")
        
        # Findings & Remediation
        report.append(self._header("12. FINDINGS & REMEDIATION RECOMMENDATIONS"))
        
        if self.findings:
            # Sort by severity
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x.get("severity", "INFO"), 5))
            
            for i, finding in enumerate(sorted_findings, 1):
                sev = finding.get("severity", "INFO")
                color = self._severity_color(sev)
                
                report.append(f"""
{c.BOLD}Finding #{i}: {finding['finding']}{c.END}
{self._severity_badge(sev)}

{c.BOLD}Description:{c.END}
  {finding['description']}

{c.BOLD}{c.GREEN}Remediation:{c.END}
{textwrap.indent(finding['remediation'], '  ')}

{'─' * 60}
""")
        else:
            report.append(f"\n  {c.GREEN}✓ No significant findings requiring remediation.{c.END}\n")
        
        # Footer
        report.append(f"""
{c.BOLD}{c.CYAN}{'═' * 80}{c.END}
{c.WHITE}Report generated by OSINT Runner{c.END}
{c.WHITE}Output directory: {self.output_dir}{c.END}
{c.BOLD}{c.CYAN}{'═' * 80}{c.END}
""")
        
        return ''.join(report)
    
    def save(self, filename="OSINT_REPORT.txt"):
        """Save the report to a file."""
        # Generate with colors for terminal
        colored_report = self.generate()
        
        # Generate without colors for file
        Colors.disable()
        plain_report = self.generate()
        
        # Save plain text version
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(plain_report)
        
        return filepath, colored_report

def safe_print(msg):
    """Thread-safe print function."""
    with print_lock:
        print(msg)

# === Progress Tracking ===
class ScanProgress:
    """Track and display scan progress."""
    
    def __init__(self, domain, parallel=False, fast=False):
        self.domain = domain
        self.parallel = parallel
        self.fast = fast
        self.start_time = None
        self.phase_start = None
        self.current_phase = 0
        self.total_phases = 5  # Always 5 phases, phase 5 shows as skipped in fast mode
        self.tasks = {}  # task_name: {"status": "pending|running|done|skipped", "time": seconds}
        self.phase_times = {}
    
    def start(self):
        """Start the scan timer."""
        self.start_time = time.time()
        return self
    
    def elapsed(self):
        """Get elapsed time as formatted string."""
        if not self.start_time:
            return "0s"
        secs = int(time.time() - self.start_time)
        if secs < 60:
            return f"{secs}s"
        mins = secs // 60
        secs = secs % 60
        return f"{mins}m {secs}s"
    
    def phase_elapsed(self):
        """Get current phase elapsed time."""
        if not self.phase_start:
            return "0s"
        secs = int(time.time() - self.phase_start)
        return f"{secs}s"
    
    def start_phase(self, phase_num, phase_name):
        """Start a new phase."""
        self.current_phase = phase_num
        self.phase_start = time.time()
        mode = "parallel" if self.parallel else "sequential"
        print(f"\n{'─'*60}")
        print(f"[{phase_num}/{self.total_phases}] {phase_name}")
        print(f"{'─'*60}")
    
    def end_phase(self, phase_name):
        """End current phase and record time."""
        if self.phase_start:
            elapsed = time.time() - self.phase_start
            self.phase_times[phase_name] = elapsed
    
    def task_start(self, task_name):
        """Mark a task as started."""
        self.tasks[task_name] = {"status": "running", "start": time.time()}
        safe_print(f"  ▶ {task_name}...")
    
    def task_done(self, task_name, skipped=False):
        """Mark a task as completed."""
        if task_name in self.tasks:
            elapsed = time.time() - self.tasks[task_name].get("start", time.time())
            self.tasks[task_name]["status"] = "skipped" if skipped else "done"
            self.tasks[task_name]["time"] = elapsed
            status = "⊘ skipped" if skipped else f"✓ done ({elapsed:.1f}s)"
            safe_print(f"  {status}: {task_name}")
        else:
            status = "⊘ skipped" if skipped else "✓ done"
            safe_print(f"  {status}: {task_name}")
    
    def task_skip(self, task_name, reason=""):
        """Mark a task as skipped."""
        self.tasks[task_name] = {"status": "skipped", "time": 0}
        reason_str = f" ({reason})" if reason else ""
        safe_print(f"  ⊘ {task_name}{reason_str}")
    
    def show_plan(self, skip_list, args):
        """Show the scan plan before starting."""
        print(f"\n{'═'*60}")
        print(f"  SCAN PLAN: {self.domain}")
        print(f"{'═'*60}")
        print(f"  Mode: {'Parallel' if self.parallel else 'Sequential'}", end="")
        if self.parallel:
            print(f" ({args.threads} threads)")
        else:
            print()
        print(f"  Fast mode: {'Yes (skipping extra checks)' if self.fast else 'No'}")
        print()
        
        # Phase 1
        print("  Phase 1 - Subdomain Enumeration:")
        self._show_tool_status("    ", "crt.sh", "crtsh", skip_list)
        self._show_tool_status("    ", "amass", "amass", skip_list)
        self._show_tool_status("    ", "subfinder", "subfinder", skip_list)
        
        # Phase 2
        print("  Phase 2 - HTTP Probing:")
        self._show_tool_status("    ", "httpx", "httpx", skip_list)
        
        # Phase 3
        print("  Phase 3 - URL Discovery:")
        self._show_tool_status("    ", "gau", "gau", skip_list)
        self._show_tool_status("    ", "shodan", "shodan", skip_list)
        
        # Phase 4
        print("  Phase 4 - Vulnerability Scanning:")
        self._show_tool_status("    ", "nuclei", "nuclei", skip_list)
        
        # Phase 5
        if not self.fast:
            print("  Phase 5 - Security Checks:")
            self._show_tool_status("    ", "email (SPF/DKIM/DMARC)", "email_security", skip_list, check_arg=not args.no_email)
            self._show_tool_status("    ", "sslscan", "sslscan", skip_list, check_arg=not args.no_tls)
            self._show_tool_status("    ", "security headers", "sec_headers", skip_list, check_arg=not args.no_headers)
            self._show_tool_status("    ", "whatweb", "tech_detect", skip_list, check_arg=not args.no_tech)
            self._show_tool_status("    ", "cloud detection", None, skip_list, check_arg=not args.no_cloud, always_available=True)
        else:
            print("  Phase 5 - Security Checks: SKIPPED (--fast mode)")
        
        print(f"\n{'═'*60}\n")
    
    def _show_tool_status(self, indent, display_name, step_name, skip_list, check_arg=True, always_available=False):
        """Show if a tool will run or be skipped."""
        if not check_arg:
            print(f"{indent}⊘ {display_name} (disabled)")
        elif always_available:
            print(f"{indent}● {display_name}")
        elif step_name and not ensure_tools_for_step_silent(step_name, skip_list):
            print(f"{indent}⊘ {display_name} (not installed)")
        else:
            print(f"{indent}● {display_name}")
    
    def show_summary(self):
        """Show final summary with timing."""
        total_time = time.time() - self.start_time if self.start_time else 0
        
        print(f"\n{'═'*60}")
        print(f"  SCAN COMPLETE: {self.domain}")
        print(f"{'═'*60}")
        print(f"  Total time: {self.elapsed()}")
        print()
        
        # Phase timing
        if self.phase_times:
            print("  Phase timing:")
            for phase, secs in self.phase_times.items():
                print(f"    {phase}: {secs:.1f}s")
            print()
        
        # Task summary
        done_count = sum(1 for t in self.tasks.values() if t["status"] == "done")
        skip_count = sum(1 for t in self.tasks.values() if t["status"] == "skipped")
        print(f"  Tasks: {done_count} completed, {skip_count} skipped")
        print(f"{'═'*60}\n")


def ensure_tools_for_step_silent(step, skip):
    """Check if required tools for a step are available (silent version)."""
    for t in REQUIRED_FOR_STEP.get(step, []):
        if skip and t in skip:
            return False
        bin_name = TOOLS.get(t, {}).get("bin", t)
        if not shutil.which(bin_name):
            return False
    return True

# === Configuration ===
CONFIG_FILE = Path.home() / ".osint_runner_config.json"

# Supported API keys with descriptions
API_KEYS = {
    "SHODAN_API_KEY": {
        "name": "Shodan",
        "description": "Search engine for internet-connected devices",
        "url": "https://account.shodan.io/",
        "required": False,
    },
}

def load_config():
    """Load configuration from file."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}

def save_config(config):
    """Save configuration to file."""
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
        os.chmod(CONFIG_FILE, 0o600)  # Restrict permissions (owner read/write only)
        return True
    except IOError as e:
        print(f"[error] Failed to save config: {e}")
        return False

def load_api_keys():
    """Load API keys from config file into environment variables."""
    config = load_config()
    api_keys = config.get("api_keys", {})
    loaded = []
    for key_name, key_value in api_keys.items():
        if key_value and not os.environ.get(key_name):
            os.environ[key_name] = key_value
            loaded.append(key_name)
    return loaded

def configure_api_keys():
    """Interactive prompt to configure API keys."""
    print(f"\n{'='*60}")
    print("API Key Configuration")
    print(f"{'='*60}")
    print(f"\nConfig file: {CONFIG_FILE}")
    print("\nAPI keys are stored locally and used for enhanced scanning.")
    print("Keys are optional - the script works without them but with reduced functionality.\n")
    
    config = load_config()
    if "api_keys" not in config:
        config["api_keys"] = {}
    
    for key_env, key_info in API_KEYS.items():
        current = config["api_keys"].get(key_env, "")
        masked = f"{current[:8]}...{current[-4:]}" if len(current) > 12 else ("(set)" if current else "(not set)")
        
        print(f"\n{key_info['name']} ({key_env})")
        print(f"  Description: {key_info['description']}")
        print(f"  Get your key: {key_info['url']}")
        print(f"  Current: {masked}")
        
        response = input(f"  Enter new key (or press Enter to keep current, 'clear' to remove): ").strip()
        
        if response.lower() == 'clear':
            config["api_keys"][key_env] = ""
            print(f"  [cleared] {key_env}")
        elif response:
            config["api_keys"][key_env] = response
            print(f"  [saved] {key_env}")
        else:
            print(f"  [unchanged] {key_env}")
    
    if save_config(config):
        print(f"\n[+] Configuration saved to {CONFIG_FILE}")
        print(f"[i] File permissions set to owner-only (600)")
    else:
        print(f"\n[!] Failed to save configuration")
    
    print("")

def show_api_key_status():
    """Show current API key status."""
    config = load_config()
    api_keys = config.get("api_keys", {})
    
    print("\nAPI Keys:")
    for key_env, key_info in API_KEYS.items():
        # Check config file first, then environment
        config_value = api_keys.get(key_env, "")
        env_value = os.environ.get(key_env, "")
        
        if config_value:
            masked = f"{config_value[:8]}..." if len(config_value) > 8 else "(set)"
            print(f"  [+] {key_env}: {masked} (from config)")
        elif env_value:
            masked = f"{env_value[:8]}..." if len(env_value) > 8 else "(set)"
            print(f"  [+] {key_env}: {masked} (from environment)")
        else:
            print(f"  [-] {key_env}: Not configured")
            print(f"      Get key: {key_info['url']}")

def first_run_wizard():
    """Interactive first-run setup wizard when no arguments are provided."""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                         OSINT RUNNER - Setup Wizard                          ║
║                                                                              ║
║           External Footprint Reconnaissance for Penetration Testing          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")
    
    # Check tool status
    missing_tools = []
    installed_tools = []
    for tool in SCAN_TOOLS:
        bin_name = TOOLS.get(tool, {}).get("bin", tool)
        if shutil.which(bin_name):
            installed_tools.append(tool)
        else:
            missing_tools.append(tool)
    
    # Check core tools
    missing_core = []
    for tool in CORE_TOOLS:
        bin_name = TOOLS.get(tool, {}).get("bin", tool)
        if not shutil.which(bin_name):
            missing_core.append(tool)
    
    # Check API keys
    config = load_config()
    api_keys = config.get("api_keys", {})
    shodan_configured = bool(api_keys.get("SHODAN_API_KEY") or os.environ.get("SHODAN_API_KEY"))
    
    # Display current status
    print("Current Status:")
    print(f"  Core tools:    {len(CORE_TOOLS) - len(missing_core)}/{len(CORE_TOOLS)} installed", end="")
    print(" ✓" if not missing_core else f" (missing: {', '.join(missing_core)})")
    print(f"  Scan tools:    {len(installed_tools)}/{len(SCAN_TOOLS)} installed", end="")
    print(" ✓" if not missing_tools else "")
    print(f"  Shodan API:    {'Configured ✓' if shodan_configured else 'Not configured'}")
    
    if missing_tools:
        print(f"\n  Missing scan tools: {', '.join(missing_tools)}")
    
    # Step 1: Offer to install tools
    if missing_tools:
        print("\n" + "─" * 60)
        print("Step 1: Install Tools")
        print("─" * 60)
        print("\nWould you like to install the missing OSINT tools?")
        print("This will use Homebrew (macOS) or apt-get (Linux) + Go.")
        
        while True:
            response = input("\nInstall missing tools? [y/n]: ").strip().lower()
            if response in ['y', 'yes']:
                print("")
                install_tools()
                break
            elif response in ['n', 'no']:
                print("Skipping tool installation.")
                break
            else:
                print("Please enter 'y' or 'n'.")
    else:
        print("\n✓ All scan tools are installed!")
    
    # Step 2: Offer to configure API keys
    print("\n" + "─" * 60)
    print("Step 2: Configure API Keys (Optional)")
    print("─" * 60)
    
    if shodan_configured:
        print("\n✓ Shodan API key is already configured.")
        response = input("Would you like to reconfigure it? [y/n]: ").strip().lower()
        if response in ['y', 'yes']:
            configure_api_keys()
    else:
        print("\nShodan API key enables internet device searches.")
        print("The tool works without it, but with reduced functionality.")
        
        while True:
            response = input("\nConfigure Shodan API key now? [y/n]: ").strip().lower()
            if response in ['y', 'yes']:
                configure_api_keys()
                break
            elif response in ['n', 'no']:
                print("Skipping API key configuration.")
                print("You can configure it later with: python3 osint_runner.py --configure")
                break
            else:
                print("Please enter 'y' or 'n'.")
    
    # Step 3: Show usage examples
    print("\n" + "─" * 60)
    print("Setup Complete! Here's how to use OSINT Runner:")
    print("─" * 60)
    print("""
Quick Start Examples:
─────────────────────
  # Dry-run (preview commands without executing)
  python3 osint_runner.py -d example.com -o ./output

  # Execute a full scan
  python3 osint_runner.py -d example.com -o ./output --yes

  # Fast scan (skip extra checks)
  python3 osint_runner.py -d example.com -o ./output --yes --fast

  # Scan multiple domains
  python3 osint_runner.py -d target1.com -d target2.com -o ./output --yes

Other Commands:
───────────────
  --help         Show full help with all options
  --status       Check tool and API key status
  --configure    Configure API keys
  --install-tools  Install/update OSINT tools

Ready to scan? Run:
  python3 osint_runner.py -d <target-domain> -o ./output --yes
""")
# Tool definitions with installation methods for different platforms
# brew = Homebrew (macOS), apt = apt-get (Debian/Ubuntu), go = go install, pip = pip install
TOOLS = {
    "amass":      {"bin": "amass",      "brew": "amass",           "apt": "amass",         "go": "github.com/owasp-amass/amass/v4/...@master"},
    "subfinder":  {"bin": "subfinder",  "brew": "subfinder",       "apt": None,            "go": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "httpx":      {"bin": "httpx",      "brew": "httpx",           "apt": "httpx-toolkit", "go": "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    "gau":        {"bin": "gau",        "brew": None,              "apt": None,            "go": "github.com/lc/gau/v2/cmd/gau@latest"},
    "nuclei":     {"bin": "nuclei",     "brew": "nuclei",          "apt": None,            "go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    "shodan":     {"bin": "shodan",     "brew": None,              "apt": None,            "pip": "shodan"},
    "jq":         {"bin": "jq",         "brew": "jq",              "apt": "jq"},
    "curl":       {"bin": "curl",       "brew": "curl",            "apt": "curl"},
    "git":        {"bin": "git",        "brew": "git",             "apt": "git"},
    "dig":        {"bin": "dig",        "brew": None,              "apt": "dnsutils"},  # dig is in base macOS
    "sslscan":    {"bin": "sslscan",    "brew": "sslscan",         "apt": "sslscan"},
    "whatweb":    {"bin": "whatweb",    "brew": "whatweb",         "apt": "whatweb"},
}

# Tools used in the scan (for status display)
CORE_TOOLS = ["curl", "jq", "dig", "git"]
SCAN_TOOLS = ["amass", "subfinder", "httpx", "gau", "nuclei", "sslscan", "whatweb", "shodan"]
REQUIRED_FOR_STEP = {
    "crtsh":         ["curl", "jq"],
    "amass":         ["amass"],
    "subfinder":     ["subfinder"],
    "httpx":         ["httpx"],
    "gau":           ["gau"],
    "nuclei":        ["nuclei"],
    "shodan":        ["shodan"],
    "email_security":["dig"],
    "sslscan":       ["sslscan"],
    "sec_headers":   ["curl"],
    "tech_detect":   ["whatweb"],
}

# === Tool Installation ===
def get_platform():
    """Detect platform: 'macos', 'linux', or 'unknown'."""
    import platform
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    elif system == "linux":
        return "linux"
    return "unknown"

def brew_available():
    return shutil.which("brew") is not None

def go_available():
    return shutil.which("go") is not None

def pip_available():
    return shutil.which("pip3") is not None or shutil.which("pip") is not None

def run_install_cmd(cmd, name):
    """Run an installation command and return success status."""
    print(f"  [installing] {name}...")
    proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if proc.returncode != 0:
        print(f"    [FAILED] {name}")
        if proc.stdout:
            for line in proc.stdout.strip().split('\n')[-3:]:  # Show last 3 lines of error
                print(f"      {line}")
        return False
    print(f"    [OK] {name}")
    return True

def install_tools():
    """Install all required OSINT tools based on detected platform."""
    platform = get_platform()
    print(f"\n{'='*60}")
    print("OSINT Tool Installer")
    print(f"{'='*60}")
    print(f"Detected platform: {platform}")
    
    # Check available package managers
    has_brew = brew_available()
    has_apt = apt_available()
    has_go = go_available()
    has_pip = pip_available()
    
    print(f"\nPackage managers available:")
    print(f"  Homebrew (brew): {'Yes' if has_brew else 'No'}")
    print(f"  APT (apt-get):   {'Yes' if has_apt else 'No'}")
    print(f"  Go:              {'Yes' if has_go else 'No'}")
    print(f"  Pip:             {'Yes' if has_pip else 'No'}")
    
    if platform == "macos" and not has_brew:
        print("\n[!] Homebrew not found. Install it first:")
        print('    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"')
        return False
    
    if platform == "linux" and not has_apt:
        print("\n[!] apt-get not found. This installer supports Debian/Ubuntu.")
        return False
    
    # Install Go if needed (required for many tools)
    if not has_go:
        print("\n[+] Installing Go (required for security tools)...")
        if platform == "macos" and has_brew:
            run_install_cmd("brew install go", "go")
        elif platform == "linux" and has_apt:
            run_install_cmd("sudo apt-get update && sudo apt-get install -y golang-go", "go")
        has_go = go_available()
        if has_go:
            # Set up Go path
            go_path = os.path.expanduser("~/go/bin")
            if go_path not in os.environ.get("PATH", ""):
                os.environ["PATH"] = f"{go_path}:{os.environ.get('PATH', '')}"
    
    print(f"\n[+] Installing tools...\n")
    
    results = {"installed": [], "failed": [], "skipped": []}
    
    for tool_name, tool_info in TOOLS.items():
        bin_name = tool_info.get("bin", tool_name)
        
        # Skip if already installed
        if shutil.which(bin_name):
            print(f"  [skip] {tool_name} (already installed)")
            results["skipped"].append(tool_name)
            continue
        
        installed = False
        
        # Try platform-specific package manager first
        if platform == "macos" and has_brew and tool_info.get("brew"):
            installed = run_install_cmd(f"brew install {tool_info['brew']}", tool_name)
        elif platform == "linux" and has_apt and tool_info.get("apt"):
            installed = run_install_cmd(f"sudo apt-get install -y {tool_info['apt']}", tool_name)
        
        # Try Go install if package manager didn't work
        if not installed and has_go and tool_info.get("go"):
            go_path = os.path.expanduser("~/go/bin")
            if go_path not in os.environ.get("PATH", ""):
                os.environ["PATH"] = f"{go_path}:{os.environ.get('PATH', '')}"
            installed = run_install_cmd(f"go install {tool_info['go']}", tool_name)
        
        # Try pip install
        if not installed and has_pip and tool_info.get("pip"):
            pip_cmd = "pip3" if shutil.which("pip3") else "pip"
            installed = run_install_cmd(f"{pip_cmd} install {tool_info['pip']}", tool_name)
        
        if installed:
            results["installed"].append(tool_name)
        else:
            results["failed"].append(tool_name)
    
    # Summary
    print(f"\n{'='*60}")
    print("Installation Summary")
    print(f"{'='*60}")
    print(f"  Installed: {len(results['installed'])} - {', '.join(results['installed']) or 'none'}")
    print(f"  Skipped:   {len(results['skipped'])} - {', '.join(results['skipped']) or 'none'}")
    print(f"  Failed:    {len(results['failed'])} - {', '.join(results['failed']) or 'none'}")
    
    if results["failed"]:
        print(f"\n[!] Some tools failed to install. You may need to install manually:")
        for tool in results["failed"]:
            print(f"    - {tool}")
    
    # Remind about Go path
    if has_go:
        go_path = os.path.expanduser("~/go/bin")
        print(f"\n[i] Make sure ~/go/bin is in your PATH:")
        print(f'    export PATH="$PATH:{go_path}"')
        print(f"    (Add this to your ~/.zshrc for persistence)")
    
    # Remind about Shodan API key
    print(f"\n[i] For Shodan, set your API key:")
    print(f'    export SHODAN_API_KEY="your-api-key-here"')
    
    return len(results["failed"]) == 0

def check_tools_status():
    """Display status of all required tools and API keys."""
    print(f"\n{'='*60}")
    print("OSINT Runner Status")
    print(f"{'='*60}")
    
    print("\nCore tools (required):")
    for tool in CORE_TOOLS:
        bin_name = TOOLS.get(tool, {}).get("bin", tool)
        status = "OK" if shutil.which(bin_name) else "MISSING"
        symbol = "+" if status == "OK" else "!"
        print(f"  [{symbol}] {tool}: {status}")
    
    print("\nScan tools:")
    for tool in SCAN_TOOLS:
        bin_name = TOOLS.get(tool, {}).get("bin", tool)
        status = "OK" if shutil.which(bin_name) else "MISSING"
        symbol = "+" if status == "OK" else "-"
        print(f"  [{symbol}] {tool}: {status}")
    
    # Show API key status using the dedicated function
    show_api_key_status()
    
    # Show config file location
    print(f"\nConfig file: {CONFIG_FILE}")
    print(f"  Run --configure to set up API keys")
    print("")
def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False
def slugify(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")
def normalize_target(target: str) -> str:
    if "://" in target:
        netloc = urlparse(target).netloc
        if not netloc:
            raise ValueError(f"Invalid URL: {target}")
        domain = netloc.split(":")[0]
    else:
        domain = target
    domain = domain.strip().lower()
    domain = re.sub(r"^www\.", "", domain)
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        raise ValueError(f"Invalid domain: {target} -> {domain}")
    return domain
def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return os.path.abspath(path)
def check_tool(tool_name):
    bin_name = TOOLS.get(tool_name, {}).get("bin", tool_name)
    return shutil.which(bin_name) is not None
def apt_available():
    return shutil.which("apt-get") is not None
def apt_install(pkgs):
    if not pkgs:
        return True
    if not apt_available():
        return False
    pkgs = [p for p in pkgs if p]
    if not pkgs:
        return True
    print(f"[installer] apt-get install: {' '.join(pkgs)}")
    cmd = f"apt-get update && apt-get install -y {' '.join(pkgs)}"
    proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
    return proc.returncode == 0
def ensure_tools_for_step(step, skip):
    """Check if required tools for a step are available."""
    missing = []
    for t in REQUIRED_FOR_STEP.get(step, []):
        if skip and t in skip:
            continue
        if not check_tool(t):
            missing.append(t)
    if not missing:
        return True
    print(f"[warn] Missing tools for step '{step}': {', '.join(missing)}")
    print(f"       Run: python3 osint_runner.py --install-tools")
    return False
def run(cmd, cwd=None, logfile=None, execute=False):
    print(f"> {cmd}")
    if not execute:
        return 0, "", ""
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, text=True)
    out, err = proc.communicate()
    if logfile:
        ensure_dir(os.path.dirname(logfile))
        with open(logfile, "a", encoding="utf-8") as f:
            f.write(f"\n=== Command: {cmd}\n")
            f.write(out or "")
            f.write(err or "")
            f.write("\n")
    return proc.returncode, out, err
# === Tools wrappers ===
def query_crtsh(domain, outpath, execute=False):
    ensure_dir(outpath)
    out = os.path.join(outpath, f"crtsh_{slugify(domain)}.txt")
    cmd = f'curl -s "https://crt.sh/?q=%25.{domain}&output=json" | jq -r \'.[].name_value\' | sed "s/\\*\\.//g" | sort -u > "{out}"'
    return run(cmd, logfile=os.path.join(outpath, "commands.log"), execute=execute)
def amass_enum(domain, outpath, execute=False):
    base = os.path.join(outpath, "amass")
    ensure_dir(base)
    cmd = f'amass enum -passive -d "{domain}" -oA "{os.path.join(base, slugify(domain))}"'
    return run(cmd, logfile=os.path.join(outpath, "commands.log"), execute=execute)
def subfinder_run(domain, outpath, execute=False):
    ensure_dir(outpath)
    out = os.path.join(outpath, f"subfinder_{slugify(domain)}.txt")
    cmd = f'subfinder -d "{domain}" -o "{out}"'
    return run(cmd, logfile=os.path.join(outpath, "commands.log"), execute=execute)
def merge_subdomains(domain, outpath):
    ensure_dir(outpath)
    files = []
    amass_file = os.path.join(outpath, "amass", f"{slugify(domain)}.txt")
    if os.path.exists(amass_file):
        files.append(amass_file)
    sf = os.path.join(outpath, f"subfinder_{slugify(domain)}.txt")
    if os.path.exists(sf):
        files.append(sf)
    crt = os.path.join(outpath, f"crtsh_{slugify(domain)}.txt")
    if os.path.exists(crt):
        files.append(crt)
    merged = os.path.join(outpath, f"subdomains_{slugify(domain)}.txt")
    ensure_dir(os.path.dirname(merged))
    seen = set()
    with open(merged, "w", encoding="utf-8") as out:
        for f in files:
            try:
                with open(f, encoding="utf-8") as fh:
                    for line in fh:
                        name = line.strip()
                        if not name:
                            continue
                        if name not in seen:
                            seen.add(name)
                            out.write(name + "\n")
            except FileNotFoundError:
                continue
    return merged
def httpx_probe(subs_file, outpath, execute=False):
    ensure_dir(outpath)
    out_json = os.path.join(outpath, "httpx_results.json")
    cmd = f'cat "{subs_file}" | httpx -threads 50 -json -o "{out_json}"'
    return run(cmd, logfile=os.path.join(outpath, "commands.log"), execute=execute)
def gau_run(domain, outpath, execute=False):
    ensure_dir(outpath)
    out = os.path.join(outpath, f"gau_{slugify(domain)}.txt")
    cmd = f'gau "{domain}" | sort -u > "{out}"'
    return run(cmd, logfile=os.path.join(outpath, "commands.log"), execute=execute)
def merge_urls(domain, outpath):
    """Merge URL files from gau into a combined file."""
    urls_file = os.path.join(outpath, "urls_combined.txt")
    gau_file = os.path.join(outpath, f"gau_{slugify(domain)}.txt")
    seen = set()
    with open(urls_file, "w", encoding="utf-8") as out:
        if os.path.exists(gau_file):
            with open(gau_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    u = line.strip()
                    if not u or u in seen:
                        continue
                    seen.add(u)
                    out.write(u + "\n")
    return urls_file
def nuclei_scan(urls_file, outpath, templates_dir="/opt/nuclei-templates", execute=False):
    ensure_dir(outpath)
    out = os.path.join(outpath, "nuclei_findings.txt")
    cmd = f'nuclei -l "{urls_file}" -t "{templates_dir}" -o "{out}"'
    return run(cmd, logfile=os.path.join(outpath, "commands.log"), execute=execute)
def gitleaks_run(target_dir, outpath, execute=False):
    ensure_dir(outpath)
    out = os.path.join(outpath, "gitleaks_report.json")
    cmd = f'gitleaks detect --source="{target_dir}" -o "{out}"'
    return run(cmd, logfile=os.path.join(outpath, "commands.log"), execute=execute)
def shodan_search(domain, outpath, execute=False):
    ensure_dir(outpath)
    if not os.environ.get("SHODAN_API_KEY"):
        print("[info] SHODAN_API_KEY not set; skipping shodan search.")
        return 0, "", ""
    out = os.path.join(outpath, "shodan.txt")
    cmd = f"shodan search --fields ip_str,port,org 'hostname:{domain}' > \"{out}\""
    return run(cmd, logfile=os.path.join(outpath, "commands.log"), execute=execute)

# === Email Security (SPF/DKIM/DMARC) ===
def check_email_security(domain, outpath, execute=False):
    """Check SPF, DKIM, DMARC records - fast DNS lookups."""
    ensure_dir(outpath)
    out = os.path.join(outpath, f"email_security_{slugify(domain)}.txt")
    # Combined dig commands for SPF, DMARC, and common DKIM selectors
    dkim_selectors = ["default", "google", "selector1", "selector2", "k1", "mail", "email"]
    dkim_checks = " && ".join([
        f'echo "DKIM ({sel}):" && dig +short {sel}._domainkey.{domain} TXT'
        for sel in dkim_selectors
    ])
    cmd = f'''(
echo "=== SPF Record ===" && dig +short {domain} TXT | grep -i spf
echo ""
echo "=== DMARC Record ===" && dig +short _dmarc.{domain} TXT
echo ""
echo "=== DKIM Records (common selectors) ===" && {dkim_checks}
) > "{out}" 2>&1'''
    return run(cmd, logfile=os.path.join(outpath, "commands.log"), execute=execute)

# === TLS/SSL Checks ===
def sslscan_check(target, outpath, execute=False):
    """Fast TLS check using sslscan."""
    ensure_dir(outpath)
    out = os.path.join(outpath, f"sslscan_{slugify(target)}.txt")
    # --no-colour for clean output, --no-heartbleed to speed up (skip slow check)
    cmd = f'sslscan --no-colour --no-heartbleed {target} > "{out}" 2>&1'
    return run(cmd, logfile=os.path.join(outpath, "commands.log"), execute=execute)

# === Security Headers ===
def check_security_headers(url, outpath, execute=False):
    """Capture security headers from a URL - very fast."""
    ensure_dir(outpath)
    out = os.path.join(outpath, f"security_headers_{slugify(url)}.txt")
    # Check for common security headers
    headers_to_check = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Embedder-Policy",
    ]
    cmd = f'''(
echo "=== Security Headers Check for {url} ==="
echo ""
curl -sI -m 10 "{url}" | head -50
echo ""
echo "=== Security Header Analysis ==="
HEADERS=$(curl -sI -m 10 "{url}")
for h in {' '.join(headers_to_check)}; do
    if echo "$HEADERS" | grep -qi "^$h:"; then
        echo "[FOUND] $h"
    else
        echo "[MISSING] $h"
    fi
done
) > "{out}" 2>&1'''
    return run(cmd, logfile=os.path.join(outpath, "commands.log"), execute=execute)

# === Technology Fingerprinting ===
def whatweb_scan(target, outpath, aggression=1, execute=False):
    """Tech fingerprinting with whatweb. Aggression 1=fast/stealthy, 3=thorough."""
    ensure_dir(outpath)
    out = os.path.join(outpath, f"whatweb_{slugify(target)}.txt")
    cmd = f'whatweb -a {aggression} --no-errors --color=never "{target}" > "{out}" 2>&1'
    return run(cmd, logfile=os.path.join(outpath, "commands.log"), execute=execute)

# === Cloud/SaaS Pattern Detection ===
CLOUD_PATTERNS = {
    "AWS": [r"\.amazonaws\.com", r"\.aws\.amazon\.com", r"s3[\.-]", r"\.elb\.amazonaws\.com", r"\.cloudfront\.net"],
    "Azure": [r"\.azure\.com", r"\.azurewebsites\.net", r"\.blob\.core\.windows\.net", r"\.azureedge\.net", r"\.azure-api\.net"],
    "GCP": [r"\.googleapis\.com", r"\.storage\.googleapis\.com", r"\.appspot\.com", r"\.cloudfunctions\.net", r"\.run\.app"],
    "Cloudflare": [r"\.cloudflare\.com", r"\.cloudflaressl\.com", r"\.cfssl\.com"],
    "Heroku": [r"\.herokuapp\.com", r"\.herokussl\.com"],
    "DigitalOcean": [r"\.digitaloceanspaces\.com", r"\.ondigitalocean\.app"],
    "Fastly": [r"\.fastly\.net", r"\.fastlylb\.net"],
    "Akamai": [r"\.akamai\.net", r"\.akamaitechnologies\.com", r"\.edgekey\.net"],
    "Firebase": [r"\.firebaseio\.com", r"\.firebaseapp\.com", r"\.web\.app"],
    "Netlify": [r"\.netlify\.app", r"\.netlify\.com"],
    "Vercel": [r"\.vercel\.app", r"\.now\.sh"],
    "GitHub": [r"\.github\.io", r"\.githubusercontent\.com"],
    "Salesforce": [r"\.force\.com", r"\.salesforce\.com", r"\.site\.com"],
    "Zendesk": [r"\.zendesk\.com"],
    "Shopify": [r"\.myshopify\.com", r"\.shopify\.com"],
    "HubSpot": [r"\.hubspot\.com", r"\.hs-sites\.com"],
}

def detect_cloud_patterns(subdomains_file, outpath):
    """Fast pattern matching to detect cloud/SaaS services from discovered subdomains."""
    ensure_dir(outpath)
    out = os.path.join(outpath, "cloud_hints.txt")
    results = {provider: [] for provider in CLOUD_PATTERNS}
    
    if not os.path.exists(subdomains_file):
        return out
    
    with open(subdomains_file, "r", encoding="utf-8") as f:
        subdomains = [line.strip().lower() for line in f if line.strip()]
    
    for subdomain in subdomains:
        for provider, patterns in CLOUD_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, subdomain, re.IGNORECASE):
                    if subdomain not in results[provider]:
                        results[provider].append(subdomain)
                    break
    
    with open(out, "w", encoding="utf-8") as f:
        f.write("=== Cloud/SaaS Service Detection ===\n\n")
        found_any = False
        for provider, matches in results.items():
            if matches:
                found_any = True
                f.write(f"[{provider}] ({len(matches)} found)\n")
                for m in matches[:20]:  # Limit output
                    f.write(f"  - {m}\n")
                if len(matches) > 20:
                    f.write(f"  ... and {len(matches) - 20} more\n")
                f.write("\n")
        if not found_any:
            f.write("No cloud/SaaS patterns detected in discovered subdomains.\n")
    
    return out

# === Main ===
def main():
    parser = argparse.ArgumentParser(
        prog="osint_runner.py",
        description="""
╔══════════════════════════════════════════════════════════════════════════════╗
║                           OSINT RUNNER                                       ║
║           External Footprint Reconnaissance for Penetration Testing          ║
╚══════════════════════════════════════════════════════════════════════════════╝

A comprehensive OSINT tool that performs passive reconnaissance against target
domains. By default, commands are shown but NOT executed (dry-run mode).
Use --yes to actually run the commands.

IMPORTANT: Only use this tool with explicit written authorization!
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SETUP & CONFIGURATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  python3 osint_runner.py --install-tools     Install all required tools
  python3 osint_runner.py --configure         Configure API keys (Shodan, etc.)
  python3 osint_runner.py --status            Check tool & API key status

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RECOMMENDED COMMAND (full featured scan)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  python3 osint_runner.py -d TARGET.com -o ./output --yes --parallel --report
  
  Short form:
  python3 osint_runner.py -d TARGET.com -o ./output -y -p -r

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REPORT OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Combined Report File: OSINT_REPORT.txt
  Location: <output_dir>/<domain>/OSINT_REPORT.txt

  # Generate combined report (DEFAULT - all results in one file)
  python3 osint_runner.py -d example.com -o ./output --yes

  # Separate files only (skip combined report)
  python3 osint_runner.py -d example.com -o ./output --yes --no-report

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SCANNING EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  # Dry-run (preview commands without executing)
  python3 osint_runner.py -d example.com -o ./output

  # Full scan with combined report (report is default)
  python3 osint_runner.py -d example.com -o ./output --yes

  # Full scan with parallel execution (faster)
  python3 osint_runner.py -d example.com -o ./output --yes --parallel

  # Full scan with 8 threads for maximum speed
  python3 osint_runner.py -d example.com -o ./output --yes --parallel --threads 8

  # Fast scan (skip extra checks) + parallel
  python3 osint_runner.py -d example.com -o ./output --yes --parallel --fast

  # Scan multiple domains
  python3 osint_runner.py -d target1.com -d target2.com -o ./output --yes --parallel

  # Automated/scripted scan (skip prompts)
  python3 osint_runner.py -d example.com -o ./output --yes --parallel --no-prompt

  # Separate files only (no combined report)
  python3 osint_runner.py -d example.com -o ./output --yes --no-report

  # Skip email checks (when target has no email/MX records)
  python3 osint_runner.py -d example.com -o ./output --yes --parallel --no-email

  # Skip multiple checks
  python3 osint_runner.py -d example.com -o ./output --yes --no-email --no-tls --no-tech

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SCAN PHASES (use --parallel for faster execution)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ Phase 1: Subdomain Enumeration (PARALLEL with --parallel)               │
  │   crt.sh ──┬── amass ──┬── subfinder    → run simultaneously            │
  ├─────────────────────────────────────────────────────────────────────────┤
  │ Phase 2: Merge & Probe (SEQUENTIAL - needs Phase 1 results)             │
  │   merge subdomains → httpx (probe live hosts)                           │
  ├─────────────────────────────────────────────────────────────────────────┤
  │ Phase 3: URL Discovery (PARALLEL with --parallel)                       │
  │   gau ──┬── shodan                      → run simultaneously            │
  ├─────────────────────────────────────────────────────────────────────────┤
  │ Phase 4: Vulnerability Scan (SEQUENTIAL - needs Phase 3 results)        │
  │   merge URLs → nuclei                                                   │
  ├─────────────────────────────────────────────────────────────────────────┤
  │ Phase 5: Security Checks (PARALLEL with --parallel, skip with --fast)   │
  │   email ──┬── sslscan ──┬── headers ──┬── whatweb → run simultaneously  │
  │   cloud detection (pattern matching)                                    │
  └─────────────────────────────────────────────────────────────────────────┘

  Sequential mode: ~5-8 min  |  Parallel mode (--parallel): ~2-3 min

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OUTPUT FILES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Results are saved to: <outdir>/<domain>/

  ★ PRIMARY OUTPUT (all results in one file):
    - OSINT_REPORT.txt        Combined report with ALL scan results
                              Includes: subdomains, live hosts, URLs, email
                              security, headers, TLS, tech stack, cloud hints,
                              Shodan, Nuclei findings, and remediation advice

  Individual files (for programmatic access):
    - subdomains_*.txt        All discovered subdomains
    - httpx_results.json      Live HTTP services (JSON)
    - gau_*.txt               Historical URLs
    - nuclei_findings.txt     Vulnerability findings
    - email_security_*.txt    SPF/DKIM/DMARC analysis
    - sslscan_*.txt           TLS/SSL details
    - security_headers_*.txt  HTTP security headers
    - whatweb_*.txt           Technology stack
    - cloud_hints.txt         Cloud service detection
    - commands.log            All commands executed
    
  Use --no-report to skip combined report generation

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )
    
    # Setup & Configuration group
    setup_group = parser.add_argument_group('Setup & Configuration')
    setup_group.add_argument("--install-tools", action="store_true", 
                            help="Install all required OSINT tools (brew/apt/go/pip)")
    setup_group.add_argument("--configure", action="store_true", 
                            help="Configure API keys (Shodan, etc.) interactively")
    setup_group.add_argument("--status", action="store_true", 
                            help="Show installation status of tools and API keys")
    
    # Target options group
    target_group = parser.add_argument_group('Target Options')
    target_group.add_argument("-d", "--domain", action="append", metavar="DOMAIN",
                             help="Target domain(s) or URL(s). Can be used multiple times.")
    target_group.add_argument("-o", "--outdir", default="./osint_out", metavar="DIR",
                             help="Output directory (default: ./osint_out)")
    
    # Execution options group
    exec_group = parser.add_argument_group('Execution Options')
    exec_group.add_argument("--yes", "-y", action="store_true", 
                           help="Execute commands (default is dry-run/preview mode)")
    exec_group.add_argument("--fast", "-f", action="store_true", 
                           help="Fast mode: only subdomain enum, httpx, gau, nuclei, shodan")
    exec_group.add_argument("--parallel", "-p", action="store_true",
                           help="Run independent tools in parallel (faster, more resource intensive)")
    exec_group.add_argument("--threads", type=int, default=4, metavar="N",
                           help="Number of parallel threads (default: 4, use with --parallel)")
    exec_group.add_argument("--skip", action="append", choices=list(TOOLS.keys()), metavar="TOOL",
                           help="Skip specific tool (can be used multiple times)")
    exec_group.add_argument("--no-report", action="store_true",
                           help="Skip combined report generation (keep individual files only)")
    exec_group.add_argument("--report", "-r", action="store_true", default=True,
                           help="Generate combined report (default: enabled)")
    
    # Skip options group
    skip_group = parser.add_argument_group('Skip Individual Checks')
    skip_group.add_argument("--no-email", action="store_true", 
                           help="Skip email security checks (SPF/DKIM/DMARC)")
    skip_group.add_argument("--no-tls", action="store_true", 
                           help="Skip TLS/SSL analysis (sslscan)")
    skip_group.add_argument("--no-headers", action="store_true", 
                           help="Skip security headers check")
    skip_group.add_argument("--no-tech", action="store_true", 
                           help="Skip technology fingerprinting (whatweb)")
    skip_group.add_argument("--no-cloud", action="store_true", 
                           help="Skip cloud/SaaS pattern detection")
    skip_group.add_argument("--no-prompt", action="store_true",
                           help="Skip the pre-scan tool check prompt (for scripted use)")
    
    args = parser.parse_args()
    
    # Load API keys from config file
    load_api_keys()
    
    # Handle --install-tools
    if args.install_tools:
        success = install_tools()
        sys.exit(0 if success else 1)
    
    # Handle --configure
    if args.configure:
        configure_api_keys()
        sys.exit(0)
    
    # Handle --status
    if args.status:
        check_tools_status()
        sys.exit(0)
    
    # Require domain for scanning - if no domain, run first-run wizard
    if not args.domain:
        first_run_wizard()
        sys.exit(0)
    
    # Pre-scan check: detect missing tools and offer to install
    missing_tools = []
    installed_tools = []
    for tool in SCAN_TOOLS:
        bin_name = TOOLS.get(tool, {}).get("bin", tool)
        if shutil.which(bin_name):
            installed_tools.append(tool)
        else:
            missing_tools.append(tool)
    
    # If all tools are installed, auto-skip the prompt
    if not missing_tools:
        print(f"\n[✓] All {len(SCAN_TOOLS)} scan tools installed - ready to scan!\n")
    elif missing_tools and args.no_prompt:
        # Silent mode - just show info and continue
        print(f"[i] {len(missing_tools)}/{len(SCAN_TOOLS)} tools not installed ({', '.join(missing_tools[:3])}{'...' if len(missing_tools) > 3 else ''})")
        print(f"    Use --install-tools to add them.")
    elif missing_tools:
        # Interactive mode - show prompt to install
        print(f"\n{'='*60}")
        print("Pre-Scan Tool Check")
        print(f"{'='*60}")
        print(f"\nInstalled ({len(installed_tools)}/{len(SCAN_TOOLS)}):")
        for tool in installed_tools:
            print(f"  [+] {tool}")
        print(f"\nMissing ({len(missing_tools)}/{len(SCAN_TOOLS)}):")
        for tool in missing_tools:
            print(f"  [-] {tool}")
        
        print("\nThe scan will run with reduced functionality without these tools.")
        print("You can install them now or continue with available tools.\n")
        
        while True:
            response = input("Would you like to install missing tools now? [y/n/skip]: ").strip().lower()
            if response in ['y', 'yes']:
                print("")
                success = install_tools()
                if success:
                    print("\n[+] Tools installed successfully! Continuing with scan...\n")
                else:
                    print("\n[!] Some tools failed to install. Continuing with available tools...\n")
                break
            elif response in ['n', 'no']:
                print("\nTo install tools later, run: python3 osint_runner.py --install-tools")
                print("Exiting.\n")
                sys.exit(0)
            elif response in ['s', 'skip', 'c', 'continue']:
                print("\nContinuing with available tools...\n")
                break
            else:
                print("Please enter 'y' to install, 'n' to exit, or 'skip' to continue without installing.")
    
    mode = "DRY RUN: no commands executed" if not args.yes else "EXECUTION ENABLED"
    if args.parallel:
        mode += f" (PARALLEL MODE: {args.threads} threads)"
    print(mode)
    
    outdir = ensure_dir(args.outdir)
    log = os.path.join(outdir, "run.log")
    with open(log, "a", encoding="utf-8") as f:
        f.write(f"OSINT run started: {datetime.now(UTC).isoformat()}Z\n")
        if args.parallel:
            f.write(f"Parallel mode enabled with {args.threads} threads\n")
    
    for raw_target in args.domain:
        try:
            domain = normalize_target(raw_target)
        except ValueError as e:
            print(f"[error] {e}; skipping {raw_target}")
            continue
        
        dom_dir = ensure_dir(os.path.join(outdir, slugify(domain)))
        
        # Initialize progress tracker
        progress = ScanProgress(domain, parallel=args.parallel, fast=args.fast)
        progress.show_plan(args.skip, args)
        progress.start()
        
        if args.parallel:
            # === PARALLEL EXECUTION MODE ===
            run_scan_parallel(domain, dom_dir, args, progress)
        else:
            # === SEQUENTIAL EXECUTION MODE ===
            run_scan_sequential(domain, dom_dir, args, progress)
        
        # Show summary
        progress.show_summary()
        
        # Generate combined report (default behavior)
        if not args.no_report and args.yes:
            print(f"\n[+] Generating combined report...")
            report_gen = ReportGenerator(domain, dom_dir, use_colors=True)
            report_file, colored_report = report_gen.save()
            print(colored_report)
            print(f"\n{'='*60}")
            print(f"[✓] COMBINED REPORT: {report_file}")
            print(f"    (All scan results in one file for easy reading)")
            print(f"{'='*60}")
        elif not args.no_report and not args.yes:
            print(f"\n[i] Report generation skipped (dry-run mode - no data collected)")
        
        with open(log, "a", encoding="utf-8") as f:
            f.write(f"Completed domain: {domain} at {datetime.now(UTC).isoformat()}Z\n")
    
    print("Done. Check output directory for logs and results.")


def run_scan_sequential(domain, dom_dir, args, progress):
    """Run scan in sequential mode (original behavior)."""
    
    # === PHASE 1: Subdomain Enumeration ===
    progress.start_phase(1, "Subdomain Enumeration")
    
    if ensure_tools_for_step("crtsh", args.skip):
        progress.task_start("crt.sh")
        query_crtsh(domain, dom_dir, execute=args.yes)
        progress.task_done("crt.sh")
    else:
        progress.task_skip("crt.sh", "missing tools")
    
    if ensure_tools_for_step("amass", args.skip):
        progress.task_start("amass")
        amass_enum(domain, dom_dir, execute=args.yes)
        progress.task_done("amass")
    else:
        progress.task_skip("amass", "not installed")
    
    if ensure_tools_for_step("subfinder", args.skip):
        progress.task_start("subfinder")
        subfinder_run(domain, dom_dir, execute=args.yes)
        progress.task_done("subfinder")
    else:
        progress.task_skip("subfinder", "not installed")
    
    progress.end_phase("Phase 1: Subdomain Enum")
    
    # === PHASE 2: Merge & HTTP Probing ===
    progress.start_phase(2, "Merge Subdomains & HTTP Probing")
    
    progress.task_start("merge subdomains")
    subs_file = merge_subdomains(domain, dom_dir)
    progress.task_done("merge subdomains")
    
    if os.path.exists(subs_file) and os.path.getsize(subs_file) > 0:
        if ensure_tools_for_step("httpx", args.skip):
            progress.task_start("httpx")
            httpx_probe(subs_file, dom_dir, execute=args.yes)
            progress.task_done("httpx")
        else:
            progress.task_skip("httpx", "not installed")
    else:
        progress.task_skip("httpx", "no subdomains found")
    
    progress.end_phase("Phase 2: HTTP Probing")
    
    # === PHASE 3: URL Discovery ===
    progress.start_phase(3, "URL Discovery & Shodan")
    
    if ensure_tools_for_step("gau", args.skip):
        progress.task_start("gau")
        gau_run(domain, dom_dir, execute=args.yes)
        progress.task_done("gau")
    else:
        progress.task_skip("gau", "not installed")
    
    if ensure_tools_for_step("shodan", args.skip):
        progress.task_start("shodan")
        shodan_search(domain, dom_dir, execute=args.yes)
        progress.task_done("shodan")
    else:
        progress.task_skip("shodan", "not installed")
    
    progress.end_phase("Phase 3: URL Discovery")
    
    # === PHASE 4: Vulnerability Scanning ===
    progress.start_phase(4, "Vulnerability Scanning")
    
    progress.task_start("merge URLs")
    urls_file = merge_urls(domain, dom_dir)
    progress.task_done("merge URLs")
    
    if os.path.exists(urls_file) and os.path.getsize(urls_file) > 0:
        if ensure_tools_for_step("nuclei", args.skip):
            progress.task_start("nuclei")
            nuclei_scan(urls_file, dom_dir, execute=args.yes)
            progress.task_done("nuclei")
        else:
            progress.task_skip("nuclei", "not installed")
    else:
        progress.task_skip("nuclei", "no URLs found")
    
    progress.end_phase("Phase 4: Vuln Scanning")
    
    # === PHASE 5: Additional Security Checks ===
    if not args.fast:
        progress.start_phase(5, "Security Checks")
        
        if not args.no_email:
            if ensure_tools_for_step("email_security", args.skip):
                progress.task_start("email security")
                check_email_security(domain, dom_dir, execute=args.yes)
                progress.task_done("email security")
            else:
                progress.task_skip("email security", "dig not available")
        else:
            progress.task_skip("email security", "disabled")
        
        if not args.no_tls:
            if ensure_tools_for_step("sslscan", args.skip):
                progress.task_start("sslscan")
                sslscan_check(domain, dom_dir, execute=args.yes)
                progress.task_done("sslscan")
            else:
                progress.task_skip("sslscan", "not installed")
        else:
            progress.task_skip("sslscan", "disabled")
        
        if not args.no_headers:
            if ensure_tools_for_step("sec_headers", args.skip):
                progress.task_start("security headers (https)")
                check_security_headers(f"https://{domain}", dom_dir, execute=args.yes)
                progress.task_done("security headers (https)")
                progress.task_start("security headers (http)")
                check_security_headers(f"http://{domain}", dom_dir, execute=args.yes)
                progress.task_done("security headers (http)")
            else:
                progress.task_skip("security headers", "curl not available")
        else:
            progress.task_skip("security headers", "disabled")
        
        if not args.no_tech:
            if ensure_tools_for_step("tech_detect", args.skip):
                progress.task_start("whatweb")
                whatweb_scan(f"https://{domain}", dom_dir, aggression=1, execute=args.yes)
                progress.task_done("whatweb")
            else:
                progress.task_skip("whatweb", "not installed")
        else:
            progress.task_skip("whatweb", "disabled")
        
        if not args.no_cloud:
            progress.task_start("cloud detection")
            if args.yes and os.path.exists(subs_file):
                detect_cloud_patterns(subs_file, dom_dir)
            progress.task_done("cloud detection")
        else:
            progress.task_skip("cloud detection", "disabled")
        
        progress.end_phase("Phase 5: Security Checks")
    else:
        progress.start_phase(5, "Security Checks - SKIPPED (--fast mode)")
        progress.end_phase("Phase 5: Skipped")


def run_scan_parallel(domain, dom_dir, args, progress):
    """Run scan in parallel mode for faster execution."""
    max_workers = args.threads
    
    # Helper to run a task and return result
    def run_task(name, func, *func_args, **func_kwargs):
        try:
            progress.task_start(name)
            start = time.time()
            result = func(*func_args, **func_kwargs)
            elapsed = time.time() - start
            progress.tasks[name] = {"status": "done", "time": elapsed}
            safe_print(f"  ✓ done ({elapsed:.1f}s): {name}")
            return (name, True, result)
        except Exception as e:
            progress.tasks[name] = {"status": "failed", "time": 0}
            safe_print(f"  ✗ failed: {name} - {e}")
            return (name, False, str(e))
    
    # ═══════════════════════════════════════════════════════════════════
    # PHASE 1: Subdomain Enumeration (parallel: crt.sh, amass, subfinder)
    # ═══════════════════════════════════════════════════════════════════
    progress.start_phase(1, "Subdomain Enumeration (parallel)")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        
        if ensure_tools_for_step("crtsh", args.skip):
            futures.append(executor.submit(run_task, "crt.sh", query_crtsh, domain, dom_dir, args.yes))
        else:
            progress.task_skip("crt.sh", "missing tools")
        
        if ensure_tools_for_step("amass", args.skip):
            futures.append(executor.submit(run_task, "amass", amass_enum, domain, dom_dir, args.yes))
        else:
            progress.task_skip("amass", "not installed")
        
        if ensure_tools_for_step("subfinder", args.skip):
            futures.append(executor.submit(run_task, "subfinder", subfinder_run, domain, dom_dir, args.yes))
        else:
            progress.task_skip("subfinder", "not installed")
        
        for future in as_completed(futures):
            future.result()
    
    progress.end_phase("Phase 1: Subdomain Enum")
    
    # ═══════════════════════════════════════════════════════════════════
    # PHASE 2: Merge & Probe (sequential: merge subdomains, httpx)
    # ═══════════════════════════════════════════════════════════════════
    progress.start_phase(2, "Merge Subdomains & HTTP Probing")
    
    progress.task_start("merge subdomains")
    subs_file = merge_subdomains(domain, dom_dir)
    progress.task_done("merge subdomains")
    
    if os.path.exists(subs_file) and os.path.getsize(subs_file) > 0:
        if ensure_tools_for_step("httpx", args.skip):
            progress.task_start("httpx")
            httpx_probe(subs_file, dom_dir, execute=args.yes)
            progress.task_done("httpx")
        else:
            progress.task_skip("httpx", "not installed")
    else:
        progress.task_skip("httpx", "no subdomains found")
    
    progress.end_phase("Phase 2: HTTP Probing")
    
    # ═══════════════════════════════════════════════════════════════════
    # PHASE 3: URL Discovery & Shodan (parallel: gau, shodan)
    # ═══════════════════════════════════════════════════════════════════
    progress.start_phase(3, "URL Discovery & Shodan (parallel)")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        
        if ensure_tools_for_step("gau", args.skip):
            futures.append(executor.submit(run_task, "gau", gau_run, domain, dom_dir, args.yes))
        else:
            progress.task_skip("gau", "not installed")
        
        if ensure_tools_for_step("shodan", args.skip):
            futures.append(executor.submit(run_task, "shodan", shodan_search, domain, dom_dir, args.yes))
        else:
            progress.task_skip("shodan", "not installed")
        
        for future in as_completed(futures):
            future.result()
    
    progress.end_phase("Phase 3: URL Discovery")
    
    # ═══════════════════════════════════════════════════════════════════
    # PHASE 4: Vulnerability Scanning (sequential: merge URLs, nuclei)
    # ═══════════════════════════════════════════════════════════════════
    progress.start_phase(4, "Vulnerability Scanning")
    
    progress.task_start("merge URLs")
    urls_file = merge_urls(domain, dom_dir)
    progress.task_done("merge URLs")
    
    if os.path.exists(urls_file) and os.path.getsize(urls_file) > 0:
        if ensure_tools_for_step("nuclei", args.skip):
            progress.task_start("nuclei")
            nuclei_scan(urls_file, dom_dir, execute=args.yes)
            progress.task_done("nuclei")
        else:
            progress.task_skip("nuclei", "not installed")
    else:
        progress.task_skip("nuclei", "no URLs found")
    
    progress.end_phase("Phase 4: Vuln Scanning")
    
    # ═══════════════════════════════════════════════════════════════════
    # PHASE 5: Additional Checks (parallel: email, TLS, headers, tech)
    # ═══════════════════════════════════════════════════════════════════
    if not args.fast:
        progress.start_phase(5, "Security Checks (parallel)")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            
            if not args.no_email and ensure_tools_for_step("email_security", args.skip):
                futures.append(executor.submit(run_task, "email security", 
                    check_email_security, domain, dom_dir, args.yes))
            elif args.no_email:
                progress.task_skip("email security", "disabled")
            else:
                progress.task_skip("email security", "dig not available")
            
            if not args.no_tls and ensure_tools_for_step("sslscan", args.skip):
                futures.append(executor.submit(run_task, "sslscan", 
                    sslscan_check, domain, dom_dir, args.yes))
            elif args.no_tls:
                progress.task_skip("sslscan", "disabled")
            else:
                progress.task_skip("sslscan", "not installed")
            
            if not args.no_headers and ensure_tools_for_step("sec_headers", args.skip):
                futures.append(executor.submit(run_task, "headers-https", 
                    check_security_headers, f"https://{domain}", dom_dir, args.yes))
                futures.append(executor.submit(run_task, "headers-http", 
                    check_security_headers, f"http://{domain}", dom_dir, args.yes))
            elif args.no_headers:
                progress.task_skip("security headers", "disabled")
            else:
                progress.task_skip("security headers", "curl not available")
            
            if not args.no_tech and ensure_tools_for_step("tech_detect", args.skip):
                futures.append(executor.submit(run_task, "whatweb", 
                    whatweb_scan, f"https://{domain}", dom_dir, 1, args.yes))
            elif args.no_tech:
                progress.task_skip("whatweb", "disabled")
            else:
                progress.task_skip("whatweb", "not installed")
            
            for future in as_completed(futures):
                future.result()
        
        if not args.no_cloud:
            progress.task_start("cloud detection")
            if args.yes and os.path.exists(subs_file):
                detect_cloud_patterns(subs_file, dom_dir)
            progress.task_done("cloud detection")
        else:
            progress.task_skip("cloud detection", "disabled")
        
        progress.end_phase("Phase 5: Security Checks")
    else:
        progress.start_phase(5, "Security Checks - SKIPPED (--fast mode)")
        progress.end_phase("Phase 5: Skipped")
if __name__ == '__main__':
    main()