#!/usr/bin/env python3

import os
import sys
import subprocess
import re
from datetime import datetime
from pathlib import Path

# Colors
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
BOLD = "\033[1m"
RESET = "\033[0m"

def banner():
    print(f"{CYAN}====================== WPScan ======================{RESET}")

def run_wpscan(target_url, output_file):
    """Run WPScan with enumeration options"""
    print(f"{YELLOW}[~] Running wpscan enumeration...{RESET}")
    
    try:
        # Basic WPScan command with user and plugin enumeration
        cmd = [
            "wpscan", 
            "--url", target_url,
            "-e", "u,vp,vt",  # enumerate users, vulnerable plugins, vulnerable themes
            "--api-token", "anonymous",
            "--format", "cli",
            "--no-banner"
        ]
        
        result = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        # Save output
        with open(output_file, 'w') as f:
            f.write(result.stdout)
            if result.stderr:
                f.write(f"\n--- STDERR ---\n{result.stderr}")
        
        return result.stdout, result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print(f"{RED}[!] WPScan timed out{RESET}")
        return "", False
    except FileNotFoundError:
        print(f"{RED}[!] WPScan not found. Please install wpscan.{RESET}")
        return "", False
    except Exception as e:
        print(f"{RED}[!] WPScan error: {e}{RESET}")
        return "", False

def extract_wordpress_info(output):
    """Extract key WordPress information from WPScan output"""
    info = {
        'version': None,
        'theme': None,
        'users': [],
        'vulnerabilities': [],
        'interesting_files': []
    }
    
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Extract WordPress version
        if 'WordPress version' in line:
            version_match = re.search(r'WordPress version (\d+\.\d+(?:\.\d+)?)', line)
            if version_match:
                info['version'] = version_match.group(1)
        
        # Extract theme information
        if 'theme in use' in line.lower():
            theme_match = re.search(r'theme in use: (.+)', line, re.IGNORECASE)
            if theme_match:
                info['theme'] = theme_match.group(1).strip()
        
        # Extract users
        if line.startswith('[+]') and 'User(s) Identified' in line:
            # Users are typically listed after this line
            continue
        elif re.match(r'^\[i\]\s+User\(s\) Identified:', line):
            continue
        elif re.match(r'^\[\+\]\s+\w+', line) and 'User' not in line:
            # This might be a username
            user_match = re.search(r'^\[\+\]\s+(\w+)', line)
            if user_match:
                username = user_match.group(1)
                if username not in info['users']:
                    info['users'].append(username)
        
        # Extract interesting files
        if any(keyword in line.lower() for keyword in ['xml-rpc', 'readme', 'wp-cron', 'wp-config']):
            info['interesting_files'].append(line)
        
        # Extract vulnerabilities
        if '[!]' in line and any(vuln_keyword in line.lower() for vuln_keyword in ['vulnerability', 'cve', 'exploit']):
            info['vulnerabilities'].append(line)
    
    return info

def display_results(info, target_url):
    """Display extracted WordPress information"""
    
    print(f"{GREEN}[+] URL: {target_url}{RESET}")
    print(f"{GREEN}[+] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{CYAN}===================================================={RESET}")
    
    # WordPress Version
    if info['version']:
        print(f"{CYAN}=================== WordPress Version ======================{RESET}")
        print(f"{GREEN}[+] WordPress version: {info['version']}{RESET}")
    
    # Theme Information
    if info['theme']:
        print(f"{CYAN}=================== Theme Information ====================={RESET}")
        print(f"{GREEN}[+] Theme in use: {info['theme']}{RESET}")
    
    # Interesting Files
    if info['interesting_files']:
        print(f"{CYAN}====================== Files ============================={RESET}")
        for file_info in info['interesting_files'][:10]:  # Limit to 10 files
            print(f"{YELLOW}{file_info}{RESET}")
    
    # Users
    if info['users']:
        print(f"{CYAN}=================== Enumerating Users ======================{RESET}")
        print(f"{GREEN}[+] User(s) Identified:{RESET}")
        for i, user in enumerate(info['users'], 1):
            print(f"{GREEN}[+] {user}{RESET}")
    
    # Vulnerabilities
    if info['vulnerabilities']:
        print(f"{CYAN}=================== Vulnerabilities ======================{RESET}")
        for vuln in info['vulnerabilities'][:5]:  # Limit to 5 vulnerabilities
            print(f"{RED}{vuln}{RESET}")
    
    # Password cracking suggestion
    if info['users']:
        print(f"{CYAN}================= User Password Cracking ==================={RESET}")
        print(f"{YELLOW}[?] Found {len(info['users'])} user(s) for potential password attacks{RESET}")
        print(f"{CYAN}================================================{RESET}")
        
        for i, user in enumerate(info['users'], 1):
            print(f"{CYAN}{i}) {user}{RESET}")
        
        print(f"{CYAN}================================================{RESET}")
        print(f"{YELLOW}[i] To perform password attack, run:{RESET}")
        print(f"{CYAN}wpscan --url {target_url} --password-attack xmlrpc -U {','.join(info['users'])} -P /usr/share/wordlists/rockyou.txt{RESET}")
        print(f"{CYAN}================================================{RESET}")

def main():
    if len(sys.argv) < 2:
        print(f"{RED}Usage: {sys.argv[0]} <target_url> [port]{RESET}")
        print(f"{YELLOW}Example: {sys.argv[0]} http://example.com{RESET}")
        print(f"{YELLOW}Example: {sys.argv[0]} example.com 80{RESET}")
        sys.exit(1)
    
    target = sys.argv[1]
    port = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Format target URL
    if not target.startswith(('http://', 'https://')):
        if port:
            target_url = f"http://{target}:{port}"
        else:
            target_url = f"http://{target}"
    else:
        target_url = target
    
    banner()
    
    # Create output directory
    output_dir = Path("/tmp/VirexCore/wpscan")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "wpscan_output.txt"
    
    # Run WPScan
    output, success = run_wpscan(target_url, output_file)
    
    if success:
        print(f"{GREEN}[✓] WPScan completed successfully{RESET}")
        
        # Extract and display information
        info = extract_wordpress_info(output)
        display_results(info, target_url)
        
    else:
        print(f"{RED}[!] WPScan failed to run or returned errors{RESET}")
        # Try to show any output we got
        if output:
            print(f"{YELLOW}[i] Partial output:{RESET}")
            print(output[:500])  # Show first 500 chars
    
    print(f"{CYAN}============================================================{RESET}")
    print(f"{GREEN}[!] WPScan scan completed. Results saved in {output_dir}{RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] WPScan interrupted by user{RESET}")
        sys.exit(1)