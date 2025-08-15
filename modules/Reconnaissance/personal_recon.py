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

class PersonalRecon:
    def __init__(self, target):
        self.target = target  # This would be a username, email, or name
        self.output_base = "/tmp/VirexCore"
        self.output_dir = self._create_output_dir(target)
        
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
    
    def _get_user_info(self):
        """Get additional user information"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[1/6] Getting user information...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        # Ask for additional information (optional)
        user_info = {}
        
        print(f"{Colors.CYAN}[+] Enter additional information (press Enter to skip):{Colors.RESET}")
        
        print(f"{Colors.YELLOW}Full name:{Colors.RESET}", end=" ")
        user_info['full_name'] = input().strip()
        
        print(f"{Colors.YELLOW}Email:{Colors.RESET}", end=" ")
        user_info['email'] = input().strip()
        
        print(f"{Colors.YELLOW}Location:{Colors.RESET}", end=" ")
        user_info['location'] = input().strip()
        
        print(f"{Colors.YELLOW}Company:{Colors.RESET}", end=" ")
        user_info['company'] = input().strip()
        
        print(f"{Colors.YELLOW}Phone number:{Colors.RESET}", end=" ")
        user_info['phone'] = input().strip()
        
        # Save user info to file
        with open(os.path.join(self.output_dir, "user_info.json"), 'w') as f:
            json.dump(user_info, f, indent=4)
        
        return user_info
    
    def _run_sherlock(self):
        """Run Sherlock for username enumeration"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[2/6] Running Sherlock...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        sherlock_file = os.path.join(self.output_dir, "sherlock.txt")
        self._run_command_with_output(
            f"sherlock {self.target} --folderoutput {self.output_dir}",
            sherlock_file,
            "Username enumeration with Sherlock"
        )
    
    def _run_google_search(self):
        """Run Google search for the target"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[3/6] Running Google search...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        google_file = os.path.join(self.output_dir, "google_search.txt")
        self._run_command_with_output(
            f"googler --exact {self.target} -n 20",
            google_file,
            "Google search for target"
        )
    
    def _run_email_search(self):
        """Run email search if email is provided"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[4/6] Running email search...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        # Check if email is provided in user info
        user_info_file = os.path.join(self.output_dir, "user_info.json")
        email = None
        
        if os.path.exists(user_info_file):
            try:
                with open(user_info_file, 'r') as f:
                    user_info = json.load(f)
                
                email = user_info.get('email')
            except json.JSONDecodeError:
                pass
        
        if email:
            email_file = os.path.join(self.output_dir, "email_search.txt")
            self._run_command_with_output(
                f"holehe {email}",
                email_file,
                "Email search with holehe"
            )
        else:
            print(f"{Colors.YELLOW}[!] No email provided. Skipping email search.{Colors.RESET}")
    
    def _run_phone_search(self):
        """Run phone number search if phone is provided"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[5/6] Running phone number search...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        # Check if phone number is provided in user info
        user_info_file = os.path.join(self.output_dir, "user_info.json")
        phone = None
        
        if os.path.exists(user_info_file):
            try:
                with open(user_info_file, 'r') as f:
                    user_info = json.load(f)
                
                phone = user_info.get('phone')
            except json.JSONDecodeError:
                pass
        
        if phone:
            # Remove non-digit characters from phone number
            clean_phone = re.sub(r'[^\d]', '', phone)
            
            if clean_phone:
                phone_file = os.path.join(self.output_dir, "phone_search.txt")
                self._run_command_with_output(
                    f"phoneinfoga -n {clean_phone} -s all",
                    phone_file,
                    "Phone number search with phoneinfoga"
                )
            else:
                print(f"{Colors.YELLOW}[!] Invalid phone number format. Skipping phone search.{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[!] No phone number provided. Skipping phone search.{Colors.RESET}")
    
    def _run_social_scan(self):
        """Run social media scan"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[6/6] Running social media scan...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        social_file = os.path.join(self.output_dir, "social_scan.txt")
        
        # Run socialscan for username
        self._run_command_with_output(
            f"socialscan --username {self.target} --output json",
            social_file,
            "Social media scan with socialscan"
        )
    
    def _generate_summary(self):
        """Generate a clean summary of personal reconnaissance findings"""
        print(f"\n{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.MAGENTA}                   PERSONAL RECONNAISSANCE SUMMARY{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}Target: {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        
        # Display user info
        user_info_file = os.path.join(self.output_dir, "user_info.json")
        if os.path.exists(user_info_file):
            try:
                with open(user_info_file, 'r') as f:
                    user_info = json.load(f)
                
                for key, value in user_info.items():
                    if value:
                        print(f"{Colors.YELLOW}[+] {key.replace('_', ' ').title()}:{Colors.RESET} {value}")
            except json.JSONDecodeError:
                pass
        
        # Parse Sherlock results
        sherlock_file = os.path.join(self.output_dir, f"{self.target}.txt")
        if os.path.exists(sherlock_file):
            with open(sherlock_file, 'r') as f:
                sherlock_data = f.read()
            
            # Count found accounts
            found_accounts = sherlock_data.count('Found:')
            if found_accounts > 0:
                print(f"{Colors.YELLOW}[+] Social Media Accounts:{Colors.RESET} {found_accounts} found")
        
        # Parse Google search results
        google_file = os.path.join(self.output_dir, "google_search.txt")
        if os.path.exists(google_file):
            with open(google_file, 'r') as f:
                google_data = f.read()
            
            # Count search results
            search_results = len([line for line in google_data.split('\n') if line.strip()])
            if search_results > 0:
                print(f"{Colors.YELLOW}[+] Google Search Results:{Colors.RESET} {search_results} found")
        
        # Parse email search results
        email_file = os.path.join(self.output_dir, "email_search.txt")
        if os.path.exists(email_file):
            with open(email_file, 'r') as f:
                email_data = f.read()
            
            # Count email findings
            email_findings = len([line for line in email_data.split('\n') if line.strip()])
            if email_findings > 0:
                print(f"{Colors.YELLOW}[+] Email Findings:{Colors.RESET} {email_findings} found")
        
        # Parse phone search results
        phone_file = os.path.join(self.output_dir, "phone_search.txt")
        if os.path.exists(phone_file):
            with open(phone_file, 'r') as f:
                phone_data = f.read()
            
            # Count phone findings
            phone_findings = len([line for line in phone_data.split('\n') if line.strip()])
            if phone_findings > 0:
                print(f"{Colors.YELLOW}[+] Phone Findings:{Colors.RESET} {phone_findings} found")
        
        # Parse social scan results
        social_file = os.path.join(self.output_dir, "social_scan.txt")
        if os.path.exists(social_file):
            with open(social_file, 'r') as f:
                social_data = f.read()
            
            # Count social scan findings
            try:
                social_json = json.loads(social_data)
                if 'sites' in social_json:
                    social_findings = len(social_json['sites'])
                    if social_findings > 0:
                        print(f"{Colors.YELLOW}[+] Social Scan Findings:{Colors.RESET} {social_findings} found")
            except json.JSONDecodeError:
                pass
        
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
    
    def run(self):
        """Execute personal reconnaissance with comprehensive tools"""
        # Set up signal handler for EOF (Ctrl+D)
        signal.signal(signal.SIGINT, self._handle_eof)
        
        print(f"{Colors.CYAN}[+] Output will be saved in: {self.output_dir}{Colors.RESET}")
        
        # Get user information
        user_info = self._get_user_info()
        
        # Run all personal reconnaissance tools
        self._run_sherlock()
        self._run_google_search()
        self._run_email_search()
        self._run_phone_search()
        self._run_social_scan()
        
        # Generate summary
        self._generate_summary()
        
        print(f"\n{Colors.GREEN}[✓] Personal reconnaissance completed successfully!{Colors.RESET}")
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
            
        recon = PersonalRecon(target)
        recon.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.CYAN}Operation cancelled by user. Returning to reconnaissance menu...{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}An unexpected error occurred: {str(e)}{Colors.RESET}")
        sys.exit(1)