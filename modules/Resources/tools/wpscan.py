#!/usr/bin/env python3
import subprocess
import sys
import os
import re
from datetime import datetime

def is_valid_domain(domain):
    domain_regex = re.compile(
        r"^([a-zA-Z0-9-_]+(\.[a-zA-Z0-9-_]+)*|\d{1,3}(\.\d{1,3}){3})$"
    )
    return bool(domain_regex.match(domain))

def is_valid_port(port):
    try:
        p = int(port)
        return 1 <= p <= 65535
    except ValueError:
        return False

def parse_wpscan_output(raw_output, url, ip):
    lines = raw_output.splitlines()

    start_time = None
    headers = []
    xmlrpc = {}
    readme = {}
    wpcron = {}
    wp_version = {}
    theme_info = {}
    users = []

    section = None
    current_user = None
    in_user_details = False

    def clean_line(l):
        return l.strip(" |")

    for i, line in enumerate(lines):
        line = line.rstrip()

        if line.startswith("[+] Started:"):
            start_time = line.split("Started:",1)[1].strip()

        # Headers
        if "[+] Headers" in line:
            section = "headers"
            continue
        if section == "headers" and line.strip().startswith("-"):
            m = re.match(r"[-\s]*([^:]+):\s*(.+)", line.strip(" |-"))
            if m:
                headers.append((m.group(1).strip(), m.group(2).strip()))
            continue
        if section == "headers" and line.strip() == "":
            section = None

        # XML-RPC
        if "XML-RPC seems to be enabled" in line:
            section = "xmlrpc"
            xmlrpc['url'] = re.search(r'http\S+', line)
            if xmlrpc['url']:
                xmlrpc['url'] = xmlrpc['url'].group(0)
            xmlrpc['refs'] = []
            j = i + 1
            while j < len(lines) and (lines[j].startswith(" |") or lines[j].startswith("  -")):
                ref_match = re.search(r"https?://\S+", lines[j])
                if ref_match:
                    xmlrpc['refs'].append(ref_match.group(0))
                j += 1
            continue

        # Readme
        if "WordPress readme found" in line:
            readme['url'] = re.search(r'http\S+', line)
            if readme['url']:
                readme['url'] = readme['url'].group(0)
            readme['confidence'] = "100%"
            continue

        # WP-Cron
        if "The external WP-Cron seems to be enabled" in line:
            wpcron['url'] = re.search(r'http\S+', line)
            if wpcron['url']:
                wpcron['url'] = wpcron['url'].group(0)
            wpcron['confidence'] = None
            wpcron['refs'] = []
            j = i + 1
            while j < len(lines) and lines[j].startswith(" |"):
                conf_match = re.search(r"Confidence: (\d+%)", lines[j])
                if conf_match:
                    wpcron['confidence'] = conf_match.group(1)
                ref_match = re.search(r"https?://\S+", lines[j])
                if ref_match:
                    wpcron['refs'].append(ref_match.group(0))
                j += 1
            continue

        # WordPress Version
        if "WordPress version" in line:
            m = re.search(r"WordPress version ([\d\.]+)", line)
            if m:
                wp_version['version'] = m.group(1)
            m_date = re.search(r"released on (\d{4}-\d{2}-\d{2})", line)
            if m_date:
                wp_version['release_date'] = m_date.group(1)
            if i+1 < len(lines) and "Found By:" in lines[i+1]:
                wp_version['found_by'] = clean_line(lines[i+1].split("Found By:")[1])
            wp_version['sources'] = []
            j = i + 2
            while j < len(lines) and lines[j].strip().startswith("- http"):
                wp_version['sources'].append(lines[j].strip().lstrip("- ").split(",")[0])
                j += 1
            continue

        # Theme Info
        if "WordPress theme in use" in line or line.startswith("[+] twentytwenty"):
            section = "theme"
            theme_info['name'] = re.search(r": ([^\s]+)", line)
            if theme_info['name']:
                theme_info['name'] = theme_info['name'].group(1)
            theme_info['details'] = []
            j = i + 1
            while j < len(lines) and (lines[j].startswith(" |") or lines[j].startswith("  -")):
                theme_info['details'].append(lines[j].strip(" |"))
                j += 1
            continue

        # USER DETECTION - NEW IMPROVED VERSION
        if "[i] User(s) Identified:" in line:
            section = "users"
            in_user_details = True
            continue

        if section == "users":
            # Detect new user
            if line.strip().startswith("[+]"):
                username_match = re.search(r"\[\+\]\s+(\w+)", line)
                if username_match:
                    current_user = {'name': username_match.group(1), 'details': []}
                    users.append(current_user)
                    in_user_details = True
                else:
                    in_user_details = False
            # Capture user details
            elif current_user and in_user_details and line.strip().startswith("|"):
                cleaned = clean_line(line)
                # Skip reference URLs
                if cleaned and not cleaned.startswith("http"):
                    current_user['details'].append(cleaned)
            # Reset at blank lines
            elif line.strip() == "":
                in_user_details = False

    # Output Building
    output = []
    output.append("="*30 + " WPScan Scan " + "="*30)
    output.append("-"*67)
    output.append(f"[+] Target URL     : {url} [{ip}]")
    if start_time:
        try:
            dt = datetime.strptime(start_time, "%a %b %d %H:%M:%S %Y")
            formatted_time = dt.strftime("%A, %B %d, %Y – %I:%M:%S %p")
        except Exception:
            formatted_time = start_time
        output.append(f"[+] Scan Started   : {formatted_time}")
    else:
        output.append(f"[+] Scan Started   : Unknown")
    output.append("-"*67)

    output.append("================[ 🔍 Interesting Findings: ]=======================")
    if headers:
        output.append("[+] Response Headers:")
        for k,v in headers:
            output.append(f"    - {k:<13} : {v}")
        output.append("    - Detection Method : Headers (Passive)")
        output.append("    - Confidence        : 100%")
        output.append("-"*67)
    else:
        output.append("[!] No interesting headers found.")
        output.append("-"*67)

    output.append("================[ 📄 Discovered Files & Endpoints: ]===============")
    if xmlrpc:
        output.append("[+] XML-RPC Interface Enabled")
        output.append(f"    - URL         : {xmlrpc.get('url','N/A')}")
        output.append("    - Detection   : Direct Access (Aggressive)")
        output.append("    - Confidence  : 100%")
        if xmlrpc.get('refs'):
            output.append("    - References:")
            for r in xmlrpc['refs']:
                output.append(f"        • {r}")
    if readme:
        output.append("[+] WordPress Readme File Exposed")
        output.append(f"    - URL         : {readme.get('url','N/A')}")
        output.append("    - Detection   : Direct Access (Aggressive)")
        output.append(f"    - Confidence  : {readme.get('confidence','N/A')}")
    if wpcron:
        output.append("[+] WP-Cron Endpoint Enabled")
        output.append(f"    - URL         : {wpcron.get('url','N/A')}")
        output.append("    - Detection   : Direct Access (Aggressive)")
        output.append(f"    - Confidence  : {wpcron.get('confidence','N/A')}")
        if wpcron.get('refs'):
            output.append("    - References:")
            for r in wpcron['refs']:
                output.append(f"        • {r}")
    if wp_version:
        output.append(f"[+] WordPress Version Detected: **{wp_version.get('version','N/A')}** _(Outdated, released on {wp_version.get('release_date','N/A')})_")
        output.append(f"    - Detection   : {wp_version.get('found_by','N/A')}")
        if wp_version.get('sources'):
            output.append("    - Source URLs :")
            for src in wp_version['sources']:
                output.append(f"        • {src}")
    output.append("-"*67)

    output.append("=================[ 🎨 Theme Information: ]=======================")
    if theme_info:
        name = theme_info.get('name','N/A')
        details = theme_info.get('details',[])
        version = "N/A"
        last_updated = "N/A"
        readme_file = "N/A"
        description = ""
        author_uri = "N/A"
        confidence = "N/A"
        for d in details:
            if d.lower().startswith("last updated"):
                last_updated = d.split(":")[-1].strip()
            elif d.lower().startswith("readme"):
                readme_file = d.split(":")[-1].strip()
            elif d.lower().startswith("description"):
                description = d.split(":",1)[1].strip()
            elif d.lower().startswith("author uri"):
                author_uri = d.split(":")[-1].strip()
            elif d.lower().startswith("version"):
                version = d.split(":")[-1].strip()
            elif "confidence" in d.lower():
                m = re.search(r"(\d+%)", d)
                if m:
                    confidence = m.group(1)
        output.append(f"[+] Active Theme: **{name}**")
        output.append(f"    - Location       : http://{url.split('/')[2]}/wp-content/themes/{name}/")
        output.append(f"    - Version        : {version} (Up to date)")
        output.append(f"    - Last Updated   : {last_updated}")
        output.append(f"    - Readme         : {readme_file}")
        output.append(f"    - Description    : {description}")
        output.append(f"    - Author URI     : {author_uri}")
        output.append(f"    - Confidence     : {confidence}")
    else:
        output.append("[!] No theme information found.")
    output.append("-"*67)

    output.append("=================[ User Enumeration: ]===========================")
    if users:
        for u in users:
            output.append(f"[+] User Identified  : {u['name']}")
            if u['details']:
                output.append("    - " + "\n    - ".join(u['details']))
            else:
                output.append("    - Found By       : Unknown")
    else:
        output.append("[!] No users identified.")
    output.append("-"*67)

    return "\n".join(output)

def run_wpscan(domain, port):
    url = f"http://{domain}:{port}/"
    output_dir = f"/tmp/VirexCore/{domain}"
    output_file = os.path.join(output_dir, "wpscan_output.txt")

    os.makedirs(output_dir, exist_ok=True)

    command = ["wpscan", "--url", url, "--enumerate", "u,p,t"]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=300  # Increased timeout for better reliability
        )
        ip_match = re.search(r"\[([\d\.]+)\]", result.stdout)
        ip = ip_match.group(1) if ip_match else "N/A"

        formatted = parse_wpscan_output(result.stdout, url, ip)

        print(formatted)

        with open(output_file, "w") as f:
            f.write(formatted)

        print(f"\nOutput saved to {output_file}")

    except subprocess.TimeoutExpired:
        print("wpscan command timed out. Please check network and try again.")
    except subprocess.CalledProcessError as e:
        print("wpscan encountered an error:")
        print(e.stderr)
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <domain_or_ip> <port>")
        sys.exit(1)

    domain = sys.argv[1].lower()
    port = sys.argv[2]

    if not is_valid_domain(domain):
        print("Invalid domain or IP address.")
        sys.exit(1)

    if not is_valid_port(port):
        print("Invalid port number. Must be between 1 and 65535.")
        sys.exit(1)

    run_wpscan(domain, port)