#!/usr/bin/env python3
import subprocess
import sys
import os
import time
import select

def check_installation():
    try:
        subprocess.run(["which", "vncsnapshot"], check=True, stdout=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        print("⚠️ vncsnapshot not found. Installing...")
        try:
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "vncsnapshot"], check=True)
            print("✅ vncsnapshot installed successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to install vncsnapshot: {e}")
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
        print("Usage: ./vncsnapshot.py <ip_address> <port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    # Create output directory
    output_dir = f"/tmp/VirexCore/{ip}/vncsnapshot"
    os.makedirs(output_dir, exist_ok=True)
    report_file = f"{output_dir}/report.txt"
    
    # Check installation
    if not check_installation():
        sys.exit(1)
    
    print("================[ SNAPSHOT MENU ]================")
    print("[1] Single Capture (3s default)")
    print("[2] Timed Interval Capture")
    print("========================================================")
    
    choice = prompt_with_timeout("[?] Select option:", "1")
    
    if choice == "1":
        output_file = f"{output_dir}/screen_{int(time.time())}.jpg"
        cmd = f"vncsnapshot -quiet {ip}:{port} {output_file}"
    else:
        interval = input("[!] Interval (seconds): ")
        output_file = f"{output_dir}/screen_%timestamp%.jpg"
        cmd = f"vncsnapshot -quiet -interval {interval} {ip}:{port} {output_file}"
    
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
        
        print("====================================================")
        print(f"✅ Report saved to: {report_file}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()