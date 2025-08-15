#!/usr/bin/env python3
import os
import re
import subprocess
import sys
from pathlib import Path

# Colors
GREEN = "\033[1;32m"
CYAN = "\033[1;36m"
YELLOW = "\033[1;33m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Usage check
if len(sys.argv) != 2:
    print(f"{YELLOW}Usage: {sys.argv[0]} <target_ip>{RESET}")
    sys.exit(1)

target = sys.argv[1]
outdir = Path(f"/tmp/VirexCore/{target.replace('/', '_')}")
outdir.mkdir(exist_ok=True, parents=True)
outfile = outdir / "rustscan.txt"

# Header
print(f"{CYAN}{BOLD}======================[ Rustscan ]==================================={RESET}")
print(f"{GREEN}[+] Running Rustscan scan...  [+] Target: {target}{RESET}")

cmd = [
    "rustscan", "-a", target, "--ulimit", "5000", "--", "-A", "-oN", str(outfile)
]

# Start Rustscan
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

open_ports = []
services_details = []
os_info = []

capture_service = False
service_block = []

# Section: Port Summary
print(f"{YELLOW}=============[ OPEN PORTS ]=================={RESET}")

for line in proc.stdout:
    line = line.rstrip()

    # Display open port summary
    if line.startswith("Open "):
        print(f"{GREEN}{line}{RESET}")

    elif re.match(r'^(\d+)/tcp\s+open\s+', line):
        port = re.match(r'^(\d+)/tcp\s+open', line).group(1)
        open_ports.append(port)
        if service_block:
            services_details.append("\n".join(service_block))
            service_block = []
        service_block.append(line)
        capture_service = True

    elif capture_service and line.startswith("|"):
        service_block.append(line)

    elif capture_service and not line.startswith("|"):
        services_details.append("\n".join(service_block))
        service_block = []
        capture_service = False

    elif line.lower().startswith(("running:", "os cpe:", "os details:", "device type:", "service info:")):
        os_info.append(line)

# Append remaining service block
if service_block:
    services_details.append("\n".join(service_block))

proc.wait()

# Scan Complete
print(f"{CYAN}{'='*65}")
print(f"[+] Scan completed")
print(f"{'='*65}{RESET}")

# Port & Service Detection
print(f"{YELLOW}==============[ PORT & SERVICE DETECTION ]=================={RESET}")
for port in open_ports:
    print(f"{GREEN}{port}{RESET}")

# Detailed Service Info
if services_details:
    print(f"\n{YELLOW}--- Services (detailed) ---{RESET}")
    print("\n\n".join(services_details))

# OS Detection Info
if os_info:
    print(f"\n{YELLOW}========================[ OS Detection ]=============================={RESET}")
    print("\n".join(os_info))

# Full Report
print(f"{CYAN}{'='*91}")
print(f"{GREEN}Full report: {outfile}   {RESET}{BOLD}{{ without cuts }}{RESET}")
print(f"{CYAN}{'='*65}")

# Run curl_web_checker.py if available
script_dir = Path(__file__).parent
curl_script = script_dir / "curl_web_checker.py"

if curl_script.exists():
    if open_ports:
        port_args = ",".join(open_ports)
#        print(f"{GREEN}[✓] Start Curl for Web hosting ports...{RESET}")
        subprocess.call(["python3", str(curl_script), target, port_args])
    else:
        print(f"{YELLOW}[!] No open ports found to pass to curl_web_checker.py. Skipping...{RESET}")
else:
    print(f"{YELLOW}[!] curl_web_checker.py not found. Skipping...{RESET}")
