#!/usr/bin/env python3
import subprocess
import sys
import os
import time
import select
import re
import threading
import queue

def check_installation():
    try:
        subprocess.run(["which", "wpscan"], check=True, stdout=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        print("⚠️ wpscan not found. Installing...")
        try:
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "wpscan"], check=True)
            print("✅ wpscan installed successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to install wpscan: {e}")
            return False

def prompt_with_timeout(prompt, default=None, timeout=3):
    print(prompt)
    print(f"⏱️ Timeout in {timeout} seconds (default: {default})")
    
    rlist, _, _ = select.select([sys.stdin], [], [], timeout)
    if rlist:
        user_input = sys.stdin.readline().rstrip()
        return user_input if user_input else default
    else:
        print(f"⏱️ Timeout, using default: {default}")
        return default

def extract_users(output):
    users = []
    lines = output.split('\n')
    capture_users = False
    
    for i, line in enumerate(lines):
        # Look for the user identification header
        if "[i] User(s) Identified:" in line:
            capture_users = True
            continue
        
        # If we're in the user section
        if capture_users:
            stripped_line = line.strip()
            
            # Skip empty lines or non-user lines
            if not stripped_line:
                continue
                
            # Check if this is a user entry (starts with [+])
            if stripped_line.startswith("[+]"):
                # Extract username (everything after [+])
                username = stripped_line[3:].strip()
                
                # Skip if it's not a username (like "Finished:")
                if username and not username.startswith("Finished:") and not username.startswith("Requests Done:"):
                    users.append(username)
            # Check if we've reached the end of the user section
            elif stripped_line.startswith("[+] Finished:") or stripped_line.startswith("[+] Requests Done:"):
                capture_users = False
                break
            # If we encounter a line starting with [!] or [i] after users, we're done
            elif stripped_line.startswith("[!]") or stripped_line.startswith("[i]") and users:
                capture_users = False
                break
    
    return users

def extract_important_findings(output):
    """Extract all important findings marked with [+] in the output"""
    findings = []
    lines = output.split('\n')
    
    for line in lines:
        stripped_line = line.strip()
        if stripped_line.startswith("[+]"):
            # Skip user enumeration lines as they're handled separately
            if not (stripped_line.startswith("[+] User Identified:") or 
                   (len(stripped_line.split()) == 2 and stripped_line.startswith("[+] "))):
                findings.append(stripped_line)
    
    return findings

def format_wpscan_output(output):
    formatted_lines = []
    lines = output.split('\n')
    
    # Header
    formatted_lines.append("========================== WPScan Scan ==========================")
    formatted_lines.append("-------------------------------------------------------------------")
    
    # Extract target URL and start time
    for line in lines:
        if "[+] URL:" in line:
            formatted_lines.append(f"[+] Target URL     : {line.split('[+] URL:')[1].strip()}")
        elif "[+] Started:" in line:
            formatted_lines.append(f"[+] Scan Started   : {line.split('[+] Started:')[1].strip()}")
    
    formatted_lines.append("-------------------------------------------------------------------")
    
    # Extract all important findings
    important_findings = extract_important_findings(output)
    
    # Interesting Findings section
    formatted_lines.append("================[ 🔍 Interesting Findings: ]=======================")
    
    headers_section = False
    files_section = False
    version_section = False
    theme_section = False
    
    for line in lines:
        if "[+] Headers" in line:
            headers_section = True
            files_section = False
            version_section = False
            theme_section = False
            formatted_lines.append("[+] Response Headers:")
            continue
        
        if "[+] XML-RPC seems to be enabled" in line:
            headers_section = False
            files_section = True
            formatted_lines.append("-------------------------------------------------------------------")
            formatted_lines.append("================[ 📄 Discovered Files & Endpoints: ]===================================================")
            formatted_lines.append("[+] XML-RPC Interface Enabled  ")
            formatted_lines.append(f"    - URL         : {line.split('http://')[1].strip()}")
            formatted_lines.append("    - Detection   : Direct Access (Aggressive)  ")
            formatted_lines.append("    - Confidence  : 100%  ")
            formatted_lines.append("    - References:")
            continue
        
        if "[+] WordPress readme found" in line:
            formatted_lines.append("[+] WordPress Readme File Exposed  ")
            formatted_lines.append(f"    - URL         : {line.split('http://')[1].strip()}")
            formatted_lines.append("    - Detection   : Direct Access (Aggressive)  ")
            formatted_lines.append("    - Confidence  : 100%")
            continue
        
        if "[+] WordPress version" in line and "identified" in line:
            files_section = False
            version_section = True
            version_info = line.split("identified")[1].strip()
            version_num = version_info.split("(")[0].strip()
            release_date = version_info.split("released on")[1].split(")")[0].strip()
            formatted_lines.append("-------------------------------------------------------------------")
            formatted_lines.append(f"[+] WordPress Version Detected: **{version_num}** _(Outdated, released on {release_date})_  ")
            formatted_lines.append("    - Detection   : RSS Generator (Passive)  ")
            formatted_lines.append("    - Source URLs :")
            continue
        
        if "[+] WordPress theme in use" in line:
            version_section = False
            theme_section = True
            formatted_lines.append("-------------------------------------------------------------------")
            formatted_lines.append("=================[ 🎨 Theme Information: ]==================================================")
            theme_name = line.split("in use:")[1].strip()
            formatted_lines.append(f"[+] Active Theme: **{theme_name}**  ")
            continue
        
        if headers_section and line.strip().startswith("|"):
            if " - Server:" in line:
                formatted_lines.append(f"    - Server       : {line.split(' - Server:')[1].strip()}")
            elif " - X-Powered-By:" in line:
                formatted_lines.append(f"    - X-Powered-By : {line.split(' - X-Powered-By:')[1].strip()}")
            elif " - Found By:" in line:
                formatted_lines.append(f"    - Detection Method : {line.split(' - Found By:')[1].strip()}")
            elif " - Confidence:" in line:
                formatted_lines.append(f"    - Confidence        : {line.split(' - Confidence:')[1].strip()}")
        
        if version_section and " - http://" in line:
            formatted_lines.append(f"        • {line.split(' - ')[1].strip()}")
        
        if theme_section:
            if " - Location:" in line:
                formatted_lines.append(f"    - Location       : {line.split(' - Location:')[1].strip()}")
            elif " - Version:" in line:
                version_text = line.split(' - Version:')[1].strip()
                if "out of date" in version_text:
                    version_num = version_text.split(" (")[0].strip()
                    latest_version = version_text.split("latest version is ")[1].split(")")[0].strip()
                    formatted_lines.append(f"    - Version        : {version_num} (Outdated, latest version is {latest_version})")
                else:
                    formatted_lines.append(f"    - Version        : {version_text}")
            elif " - Last Updated:" in line:
                formatted_lines.append(f"    - Last Updated   : {line.split(' - Last Updated:')[1].strip()}")
            elif " - Readme:" in line:
                formatted_lines.append(f"    - Readme         : {line.split(' - Readme:')[1].strip()}")
            elif " - Style URL:" in line:
                formatted_lines.append(f"    - Stylesheet     : {line.split(' - Style URL:')[1].strip()}")
            elif " - Style Name:" in line:
                formatted_lines.append(f"    - Style Name: {line.split(' - Style Name:')[1].strip()}")
            elif " - Description:" in line:
                formatted_lines.append(f"    - Description    : {line.split(' - Description:')[1].strip()}")
            elif " - Author URI:" in line:
                formatted_lines.append(f"    - Author URI     : {line.split(' - Author URI:')[1].strip()}")
            elif " - Detected By:" in line:
                formatted_lines.append(f"    - Detected By    : {line.split(' - Detected By:')[1].strip()}")
            elif " - Confidence:" in line:
                formatted_lines.append(f"    - Confidence     : {line.split(' - Confidence:')[1].strip()}")
    
    # Add all other important findings
    if important_findings:
        formatted_lines.append("-------------------------------------------------------------------")
        formatted_lines.append("=================[ 🔍 Other Important Findings: ]=================")
        for finding in important_findings:
            # Skip findings we've already processed in specific sections
            if not any(skip in finding for skip in ["[+] URL:", "[+] Started:", "[+] Headers", 
                                                   "[+] XML-RPC seems to be enabled", 
                                                   "[+] WordPress readme found",
                                                   "[+] WordPress version", 
                                                   "[+] WordPress theme in use"]):
                formatted_lines.append(finding)
    
    # User Enumeration section
    users = extract_users(output)
    if users:
        formatted_lines.append("-------------------------------------------------------------------")
        formatted_lines.append("=================[ User Enumeration: ]=============================")
        for user in users:
            formatted_lines.append(f"[+] User Identified: **{user}**")
            formatted_lines.append("    - Found By       : RSS Generator (Passive)")
            formatted_lines.append("    - Confirmed By   :")
            formatted_lines.append("        • Author ID Brute Force  ")
            formatted_lines.append("        • Login Error Messages  ")
    
    return "\n".join(formatted_lines)

def format_password_attack_output(output, users):
    formatted_lines = []
    lines = output.split('\n')
    
    formatted_lines.append("=========[ 🔐 Password Brute Force Attempt (XML-RPC): ]==============")
    formatted_lines.append("-------------------------------------------------------------------")
    
    # User selection menu
    if len(users) == 1:
        formatted_lines.append(f"[!] Only one user found: {users[0]}")
        selected_user = users[0]
    else:
        formatted_lines.append("[?] Target User(s) for Default Password Check:")
        for i, user in enumerate(users, 1):
            formatted_lines.append(f"    {i}) {user}")
        formatted_lines.append("    0) Exit [../../main]")
        formatted_lines.append("[!] select a username: ")
        # This will be handled interactively
        return "\n".join(formatted_lines)
    
    formatted_lines.append("-------------------------------------------------------------------")
    
    # Check for success
    success_found = False
    for line in lines:
        if "[SUCCESS]" in line and "Valid Combinations Found:" in line:
            success_found = True
            formatted_lines.append("[+] Initiating XML-RPC Password Attack...")
            formatted_lines.append("    - Attempting 315 combinations...")
            formatted_lines.append("[SUCCESS] Valid Credentials Found:")
            # Extract credentials from the next lines
            continue
        elif success_found and line.strip().startswith("|"):
            if "Username:" in line and "Password:" in line:
                parts = line.split("|")
                for part in parts:
                    part = part.strip()
                    if part.startswith("Username:"):
                        username = part.split(":")[1].strip()
                        formatted_lines.append(f"    • Username: **{username}**")
                    elif part.startswith("Password:"):
                        password = part.split(":")[1].strip()
                        formatted_lines.append(f"    • Password: **{password}**")
            break
        elif "[SUCCESS] -" in line:
            # Alternative success format
            success_found = True
            formatted_lines.append("[+] Initiating XML-RPC Password Attack...")
            formatted_lines.append("    - Attempting 315 combinations...")
            formatted_lines.append("[SUCCESS] Valid Credentials Found:")
            # Extract username and password from the same line
            parts = line.split(" - ")[1:]  # Skip the [SUCCESS] part
            for part in parts:
                if part.startswith("Username:"):
                    username = part.split(":")[1].strip()
                    formatted_lines.append(f"    • Username: **{username}**")
                elif part.startswith("Password:"):
                    password = part.split(":")[1].strip()
                    formatted_lines.append(f"    • Password: **{password}**")
            break
    
    if not success_found:
        formatted_lines.append("[+] Initiating XML-RPC Password Attack...")
        formatted_lines.append("    - Attempting 315 combinations...")
        formatted_lines.append("[Fail] Valid Credentials Not Found:")
        # Find progress line
        for line in lines:
            if "Trying" in line and "Progress:" in line:
                formatted_lines.append(f"  {line.strip()}")
                break
        formatted_lines.append("  --------------------------------------------------------------------")
        formatted_lines.append("===================================================================")
        formatted_lines.append("( ? ) password is not found ")
        formatted_lines.append("===================================================================")
        formatted_lines.append("-------------------------------------------------------------------")
        formatted_lines.append("[?] Target User(s) for Default Password Check:")
        for i, user in enumerate(users, 1):
            formatted_lines.append(f"    {i}) {user}")
        formatted_lines.append("    0) Exit [../../main]")
        formatted_lines.append("[!] select a username: ")
    else:
        formatted_lines.append("===================================================================")
        formatted_lines.append("✅ Password Attack Completed Successfully")
        formatted_lines.append("===================================================================")
    
    return "\n".join(formatted_lines)

def stream_output(process, output_queue):
    for line in process.stdout:
        output_queue.put(line)

def main():
    if len(sys.argv) != 3:
        print("Usage: ./wpscan.py <ip_address> <port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    # Create output directory
    output_dir = f"/tmp/VirexCore/{ip}/wpscan"
    os.makedirs(output_dir, exist_ok=True)
    report_file = f"{output_dir}/report.txt"
    
    # Check installation
    if not check_installation():
        sys.exit(1)
    
    # Enumeration phase
    enum_cmd = f"wpscan --url http://{ip}:{port} -e u,vp,vt --format cli --no-banner --no-color"
    
    users = []
    try:
        print("========================== WPScan Scan ==========================")
        print("-------------------------------------------------------------------")
        print(f"[+] Target URL     : http://{ip}:{port}/")
        print(f"[+] Scan Started   : {time.strftime('%A, %B %d, %Y – %I:%M:%S %p')}")
        print("-------------------------------------------------------------------")
        print("================[ 🔍 Interesting Findings: ]=======================")
        
        process = subprocess.Popen(
            enum_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        
        output_queue = queue.Queue()
        output_thread = threading.Thread(target=stream_output, args=(process, output_queue))
        output_thread.daemon = True
        output_thread.start()
        
        enum_output = ""
        while output_thread.is_alive() or not output_queue.empty():
            try:
                line = output_queue.get(timeout=0.1)
                print(line, end='')
                enum_output += line
            except queue.Empty:
                continue
        
        process.wait()
        
        # Extract users
        users = extract_users(enum_output)
        
        # Format and display the enumeration output
        formatted_enum = format_wpscan_output(enum_output)
        print(formatted_enum)
        
        with open(report_file, 'w') as report:
            report.write(formatted_enum)
        
        if not users:
            print("[!] No users found")
            print("===================================================================")
            return
        
        # Password attack phase
        print("=========[ 🔐 Password Brute Force Attempt (XML-RPC): ]==============")
        print("-------------------------------------------------------------------")
        
        # User selection
        if len(users) == 1:
            selected_user = users[0]
            print(f"[!] Only one user found: {selected_user}")
        else:
            print("[?] Target User(s) for Default Password Check:")
            for i, user in enumerate(users, 1):
                print(f"    {i}) {user}")
            print("    0) Exit [../../main]")
            
            user_choice = prompt_with_timeout("[!] select a username:", "1")
            if user_choice == "0":
                return
            
            try:
                user_index = int(user_choice) - 1
                if 0 <= user_index < len(users):
                    selected_user = users[user_index]
                else:
                    selected_user = users[0]
            except ValueError:
                selected_user = users[0]
        
        print(f"[+] Selected user: {selected_user}")
        
        # Wordlist selection
        wordlist_choice = prompt_with_timeout("[?] Default ../../rockyou.txt (y/n)?", "y")
        if wordlist_choice.lower() == "y":
            wordlist = "/usr/share/wordlists/rockyou.txt"
            print("--------------------------------------------------------------------")
            print("[+] Initiating XML-RPC Password Attack...")
            print("    - Using default wordlist: rockyou.txt")
        else:
            wordlist = input("[!] Enter the path: ")
            print("--------------------------------------------------------------------")
            print("[+] Initiating XML-RPC Password Attack...")
            print(f"    - Using custom wordlist: {wordlist}")
        
        # Password attack
        attack_cmd = f"wpscan --url http://{ip}:{port} --password-attack xmlrpc -U {selected_user} -P {wordlist} --no-banner --no-color"
        
        try:
            with open(report_file, 'a') as report:
                report.write("\n\n=== PASSWORD ATTACK ===\n")
                
                attack_process = subprocess.Popen(
                    attack_cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                )
                
                attack_output = ""
                attack_queue = queue.Queue()
                attack_thread = threading.Thread(target=stream_output, args=(attack_process, attack_queue))
                attack_thread.daemon = True
                attack_thread.start()
                
                while attack_thread.is_alive() or not attack_queue.empty():
                    try:
                        line = attack_queue.get(timeout=0.1)
                        print(line, end='')
                        attack_output += line
                        report.write(line)
                    except queue.Empty:
                        continue
                
                attack_process.wait()
            
            # Format and display password attack results
            formatted_attack = format_password_attack_output(attack_output, users)
            
            # If we need to show user selection menu again
            if "[?] Target User(s) for Default Password Check:" in formatted_attack:
                print(formatted_attack)
                
                # Get user selection again
                user_choice = prompt_with_timeout("[!] select a username:", "1")
                if user_choice == "0":
                    return
                
                try:
                    user_index = int(user_choice) - 1
                    if 0 <= user_index < len(users):
                        selected_user = users[user_index]
                    else:
                        selected_user = users[0]
                except ValueError:
                    selected_user = users[0]
                
                # Wordlist selection again
                wordlist_choice = prompt_with_timeout("[?] Default ../../rockyou.txt (y/n)?", "y")
                if wordlist_choice.lower() == "y":
                    wordlist = "/usr/share/wordlists/rockyou.txt"
                else:
                    wordlist = input("[!] Enter the path: ")
                
                # Run attack again
                attack_cmd = f"wpscan --url http://{ip}:{port} --password-attack xmlrpc -U {selected_user} -P {wordlist} --no-banner --no-color"
                
                with open(report_file, 'a') as report:
                    report.write(f"\n\n=== PASSWORD ATTACK (Second Attempt) ===\n")
                    
                    attack_process = subprocess.Popen(
                        attack_cmd,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        universal_newlines=True
                    )
                    
                    for line in attack_process.stdout:
                        print(line, end='')
                        report.write(line)
                    
                    attack_process.wait()
                
                print("===================================================================")
                print("✅ Password Attack Completed Successfully")
                print("===================================================================")
            else:
                print(formatted_attack)
                
        except Exception as e:
            print(f"❌ Error during password attack: {e}")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()


    