#!/usr/bin/env python3

import subprocess
import sys
import os
import signal
from pathlib import Path
from threading import Timer

# === Colors ===
GREEN = "\033[1;32m"
RED = "\033[1;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
WHITE = "\033[1;37m"
BOLD = "\033[1m"
RESET = "\033[0m"

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

# === Timeout Input with visible prompt and timeout handling ===
def timeout_input(prompt, timeout=3):
    def timeout_handler(signum, frame):
        raise TimeoutError

    # Register the signal handler for SIGALRM
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)

    try:
        # Print prompt and flush so it's visible immediately
        print(prompt, end='', flush=True)
        user_input = sys.stdin.readline()
        signal.alarm(0)  # Cancel alarm on success
        return user_input.strip()
    except TimeoutError:
        print()  # newline after timeout for clean output
        return ''  # Return empty string on timeout
    except KeyboardInterrupt:
        print()  # newline for clean output
        raise  # re-raise to be handled outside
    finally:
        signal.alarm(0)  # Cancel alarm if any

# === CLI Arguments ===
if len(sys.argv) != 3:
    print(f"{GREEN}Usage: {sys.argv[0]} <target_ip> <comma_separated_ports>{RESET}")
    sys.exit(1)

TARGET_IP = sys.argv[1].strip()
PORTS_ARG = sys.argv[2].strip()

try:
    open_ports = sorted(set(p.strip() for p in PORTS_ARG.split(",") if p.strip().isdigit()))
except ValueError:
    print(f"{RED}[!] Invalid port list.{RESET}")
    sys.exit(1)

if not open_ports:
    print(f"{RED}[!] No valid ports provided.{RESET}")
    sys.exit(1)

# === Create output directory ===
outdir = Path(f"/tmp/outputs/{TARGET_IP.replace('/', '_')}")
outdir.mkdir(parents=True, exist_ok=True)
outfile = outdir / "ffuf_results.txt"

# === Display Fuzzing Menu ===
print(f"{BOLD}{CYAN}====================== FUZZING =========================={RESET}")
print(f"{WHITE}[1] Subdomain fuzzing (http://FUZZ.localhost:<port>){RESET}")
print(f"{WHITE}[2] Path fuzzing (http://localhost:<port>/FUZZ){RESET}")
print(f"{CYAN}{'=' * 90}{RESET}")

# === Mode Selection ===
try:
    mode = timeout_input(f"{WHITE}[?] Select fuzzing mode (default = 2): {RESET}", timeout=3)
    if not mode:
        mode = "2"
except KeyboardInterrupt:
    print()  # Clean newline
    mode = "2"

# === Wordlist Selection ===
try:
    use_default = timeout_input(
        f"{WHITE}[?] Use default wordlist ({DEFAULT_WORDLIST})? [y/n]: {RESET}", timeout=3
    ).lower()
    if not use_default:
        use_default = 'y'
except KeyboardInterrupt:
    print()  # Clean newline
    use_default = 'y'

if use_default == 'y':
    wordlist = DEFAULT_WORDLIST
else:
    wordlist = input(f"{WHITE}[*] Enter custom wordlist path: {RESET}").strip()
    if not os.path.exists(wordlist):
        print(f"{RED}[!] Wordlist path not found.{RESET}")
        sys.exit(1)

print(f"{CYAN}{'=' * 90}{RESET}")

# === Web Server Detection ===
valid_ports = []

for port in open_ports:
    try:
        res = subprocess.run(
            ["curl", "-s", "-I", "--max-time", "2", f"http://{TARGET_IP}:{port}"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        if b"HTTP/" in res.stdout:
            print(f"{GREEN}[+] HTTP detected on port {port}{RESET}")
            valid_ports.append(port)
#        else:
#            print(f"{RED}[-] No web server on port {port}{RESET}")
    except Exception:
        continue

if not valid_ports:
    print(f"{RED}[!] No web servers found on open ports.{RESET}")
    sys.exit(0)

# === FFUF Fuzzing ===
for index, port in enumerate(valid_ports):
    is_last_port = (index == len(valid_ports) - 1)

    if mode == "1":
        url = f"http://FUZZ.{TARGET_IP}:{port}/"
    else:
        url = f"http://{TARGET_IP}:{port}/FUZZ"

    print(f"{CYAN}{'=' * 56}{RESET}")
    print(f"{BOLD}{GREEN}Fuzzing URL: {url}{RESET}")
    print(f"{CYAN}{'=' * 56}{RESET}")

    try:
        result = subprocess.run(
            [
                "ffuf",
                "-u", url,
                "-w", wordlist,
                "-t", "40",
                "-mc", "200,301,302,307,401,403,405,500"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        with open(outfile, "a") as f:
            for line in result.stdout.splitlines():
                if "[Status:" in line:
                    print(line)
                    f.write(line + "\n")

    except KeyboardInterrupt:
        print(f"\n{RED}[!] FFUF interrupted by user.{RESET}")
        sys.exit(1)

if is_last_port:
 #   print(f"{YELLOW}[+] Starting service triggering...{RESET}")
    #print(f"{CYAN}{'=' * 56}{RESET}")

    # Get rustscan output file path for start-triggering.py
    rustscan_output = f"/tmp/VirexCore/{TARGET_IP.replace('/', '_')}/rustscan.txt"
    start_triggering_script = os.path.join(os.path.dirname(__file__), "start-triggering.py")

    if not os.path.isfile(start_triggering_script):
        print(f"{RED}[!] start-triggering.py not found at: {start_triggering_script}{RESET}")
    else:
        try:
            # Pass the rustscan output file and target IP to start-triggering.py
            subprocess.run(["python3", start_triggering_script, rustscan_output, TARGET_IP])
        except Exception as e:
            print(f"{RED}[!] Failed to run start-triggering.py: {e}{RESET}")
