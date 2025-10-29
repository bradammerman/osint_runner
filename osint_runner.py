#!/usr/bin/env python3
"""
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
import argparse
import os
import shutil
import subprocess
import sys
import re
from datetime import datetime
from urllib.parse import urlparse
TOOLS = {
    "amass":      {"bin": "amass",      "apt": "amass"},
    "subfinder":  {"bin": "subfinder",  "apt": "subfinder"},
    "httpx":      {"bin": "httpx",      "apt": "httpx-toolkit"},
    "gau":        {"bin": "gau",        "apt": "gau"},
    "getallurls": {"bin": "getallurls", "apt": None},  # NEW
    "waybackurls":{"bin": "waybackurls","apt": "waybackurls"},
    "masscan":    {"bin": "masscan",    "apt": "masscan"},
    "nmap":       {"bin": "nmap",       "apt": "nmap"},
    "nuclei":     {"bin": "nuclei",     "apt": "nuclei"},
    "gitleaks":   {"bin": "gitleaks",   "apt": "gitleaks"},
    "gobuster":   {"bin": "gobuster",   "apt": "gobuster"},
    "shodan":     {"bin": "shodan",     "apt": "python3-shodan"},
    "jq":         {"bin": "jq",         "apt": "jq"},
    "curl":       {"bin": "curl",       "apt": "curl"},
    "git":        {"bin": "git",        "apt": "git"},
    "dnsx":       {"bin": "dnsx",       "apt": None},
}
REQUIRED_FOR_STEP = {
    "crtsh":      ["curl", "jq"],
    "amass":      ["amass"],
    "subfinder":  ["subfinder"],
    "httpx":      ["httpx"],
    "gau":        ["gau"],
    "getallurls": ["getallurls"],
    "wayback":    ["waybackurls"],
    "masscan":    ["masscan"],
    "nmap":       ["nmap"],
    "nuclei":     ["nuclei"],
    "gitleaks":   ["gitleaks"],
    "gobuster":   ["gobuster"],
    "shodan":     ["shodan"],
}
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
def ensure_tools_for_step(step, skip, auto_install=False):
    missing = []
    for t in REQUIRED_FOR_STEP.get(step, []):
        if skip and t in skip:
            continue
        if not check_tool(t):
            missing.append(t)
    if not missing:
        return True
    print(f"[warn] Missing tools for step '{step}': {', '.join(missing)}")
    if auto_install:
        if not is_root():
            print("[warn] --auto-install requested, but not root. Re-run with sudo.")
            return False
        apt_pkgs = [TOOLS[m]["apt"] for m in missing if TOOLS.get(m, {}).get("apt")]
        if apt_pkgs:
            ok = apt_install(apt_pkgs)
            if not ok:
                print(f"[warn] Failed to install tools for step '{step}'.")
                return False
            still_missing = [m for m in missing if not check_tool(m)]
            if still_missing:
                print(f"[warn] Still missing: {', '.join(still_missing)}")
                return False
            return True
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
def getallurls_run(domain, outpath, execute=False):
    ensure_dir(outpath)
    out = os.path.join(outpath, f"getallurls_{slugify(domain)}.txt")
    cmd = f'getallurls -d "{domain}" -o "{out}"'
    return run(cmd, logfile=os.path.join(outpath, "commands.log"), execute=execute)
def merge_urls(domain, outpath):
    urls_file = os.path.join(outpath, "urls_combined.txt")
    parts = []
    gau_file = os.path.join(outpath, f"gau_{slugify(domain)}.txt")
    getallurls_file = os.path.join(outpath, f"getallurls_{slugify(domain)}.txt")
    if os.path.exists(gau_file):
        parts.append(gau_file)
    if os.path.exists(getallurls_file):
        parts.append(getallurls_file)
    seen = set()
    with open(urls_file, "w", encoding="utf-8") as out:
        for f in parts:
            with open(f, "r", encoding="utf-8") as fh:
                for line in fh:
                    u = line.strip()
                    if not u or u in seen:
                        continue
                    seen.add(u)
                    out.write(u + "\n")
    return urls_file
def masscan_scan(alive_hosts_file, outpath, rate=1000, ports="1-65535", execute=False):
    ensure_dir(outpath)
    out = os.path.join(outpath, "masscan.txt")
    cmd = f'masscan -iL "{alive_hosts_file}" -p{ports} --rate={rate} -oL "{out}"'
    return run(cmd, logfile=os.path.join(outpath, "commands.log"), execute=execute)
def nmap_scan(alive_hosts_file, outpath, execute=False):
    outdir = os.path.join(outpath, "nmap")
    ensure_dir(outdir)
    cmd = f'nmap -sS -Pn -T4 -p- --min-rate 500 -iL "{alive_hosts_file}" -oA "{os.path.join(outdir, "full_scan")}"'
    return run(cmd, logfile=os.path.join(outpath, "commands.log"), execute=execute)
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
# === Main ===
def main():
    parser = argparse.ArgumentParser(description="OSINT Runner - dry-run by default. Use --yes to execute commands.")
    parser.add_argument("-d", "--domain", action="append", required=True, help="Target domain(s) or URL(s).")
    parser.add_argument("-o", "--outdir", default="./osint_out", help="Output directory")
    parser.add_argument("--yes", action="store_true", help="Execute commands")
    parser.add_argument("--skip", action="append", choices=list(TOOLS.keys()), help="Skip specific tools")
    parser.add_argument("--rate", type=int, default=1000, help="masscan rate")
    parser.add_argument("--auto-install", action="store_true", help="Attempt apt-get install for missing tools")
    args = parser.parse_args()
    print("DRY RUN: no commands executed" if not args.yes else "EXECUTION ENABLED")
    outdir = ensure_dir(args.outdir)
    log = os.path.join(outdir, "run.log")
    with open(log, "a", encoding="utf-8") as f:
        f.write(f"OSINT run started: {datetime.utcnow().isoformat()}Z\n")
    for raw_target in args.domain:
        try:
            domain = normalize_target(raw_target)
        except ValueError as e:
            print(f"[error] {e}; skipping {raw_target}")
            continue
        dom_dir = ensure_dir(os.path.join(outdir, slugify(domain)))
        # crtsh
        if ensure_tools_for_step("crtsh", args.skip, auto_install=args.auto_install):
            query_crtsh(domain, dom_dir, execute=args.yes)
        # amass
        if ensure_tools_for_step("amass", args.skip, auto_install=args.auto_install):
            amass_enum(domain, dom_dir, execute=args.yes)
        # subfinder
        if ensure_tools_for_step("subfinder", args.skip, auto_install=args.auto_install):
            subfinder_run(domain, dom_dir, execute=args.yes)
        # merge subdomains
        subs_file = merge_subdomains(domain, dom_dir)
        # httpx
        if os.path.exists(subs_file) and os.path.getsize(subs_file) > 0:
            if ensure_tools_for_step("httpx", args.skip, auto_install=args.auto_install):
                httpx_probe(subs_file, dom_dir, execute=args.yes)
        # gau
        if ensure_tools_for_step("gau", args.skip, auto_install=args.auto_install):
            gau_run(domain, dom_dir, execute=args.yes)
        # getallurls
        if ensure_tools_for_step("getallurls", args.skip, auto_install=args.auto_install):
            getallurls_run(domain, dom_dir, execute=args.yes)
        # merge gau + getallurls into urls_combined
        urls_file = merge_urls(domain, dom_dir)
        # masscan + nmap (only if alive_hosts exists)
        alive_hosts_file = os.path.join(dom_dir, "alive_hosts.txt")
        if os.path.exists(alive_hosts_file) and os.path.getsize(alive_hosts_file) > 0:
            if ensure_tools_for_step("masscan", args.skip, auto_install=args.auto_install):
                masscan_scan(alive_hosts_file, dom_dir, rate=args.rate, execute=args.yes)
            if ensure_tools_for_step("nmap", args.skip, auto_install=args.auto_install):
                nmap_scan(alive_hosts_file, dom_dir, execute=args.yes)
        # nuclei
        if os.path.exists(urls_file) and os.path.getsize(urls_file) > 0:
            if ensure_tools_for_step("nuclei", args.skip, auto_install=args.auto_install):
                nuclei_scan(urls_file, dom_dir, execute=args.yes)
        # shodan
        if ensure_tools_for_step("shodan", args.skip, auto_install=args.auto_install):
            shodan_search(domain, dom_dir, execute=args.yes)
        with open(log, "a", encoding="utf-8") as f:
            f.write(f"Completed domain: {domain} at {datetime.utcnow().isoformat()}Z\n")
    print("Done. Check output directory for logs and results.")
if __name__ == '__main__':
    main()