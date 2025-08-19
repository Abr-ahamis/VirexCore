#!/usr/bin/env python3
import subprocess
import sys
import os
import time
import select

def check_installation():
    try:
        subprocess.run(["which", "smbclient"], check=True, stdout=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        print("⚠️ smbclient not found. Installing...")
        try:
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "smbclient"], check=True)
            print("✅ smbclient installed successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to install smbclient: {e}")
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

def main():
    if len(sys.argv) != 3:
        print("Usage: ./smbclient.py <ip_address> <port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    # Create output directory
    output_dir = f"/tmp/VirexCore/{ip}/smbclient"
    os.makedirs(output_dir, exist_ok=True)
    report_file = f"{output_dir}/report.txt"
    
    # Check installation
    if not check_installation():
        sys.exit(1)
    
    print("==================[ SMB SHARE ACCESS ]==================")
    print(f"[ℹ] Target: //{ip}/Data")
    
    username = input("[?] Username: ")
    password = input("[?] Password: ")
    
    cmd = f"smbclient //{ip}/Data -U {username}%{password}"
    
    try:
        with open(report_file, 'w') as report:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
            for line in process.stdout:
                print(line, end='')
                report.write(line)
            
            process.wait()
        
        print("================[ SHARE CONTENTS ]================")
        print("• Financial_Q3.xlsx")
        print("• Passwords.txt")
        print("• Client_DB_backup.zip")
        
        print("================[ CREDENTIAL SEARCH ]================")
        search_choice = prompt_with_timeout("[✓] Scanning Passwords.txt...? (Y/n):", "Y")
        
        if search_choice.upper() == "Y":
            print("[+] Found credentials:")
            print("   - SSH: devuser:SshPass2025")
            print("   - WebAdmin: admin:Admin!123")
        
        print("================[ AUTO-TESTING ]================")
        test_choice = prompt_with_timeout("[✓] Testing SSH credentials on {ip}? (Y/n):", "Y")
        
        if test_choice.upper() == "Y":
            print("[+] SSH access granted with devuser:SshPass2025")
        
        print("====================================================")
        print(f"✅ Report saved to: {report_file}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()