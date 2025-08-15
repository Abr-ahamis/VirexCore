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

class PhysicalRecon:
    def __init__(self, target):
        self.target = target  # This would be an organization name
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
    
    def _run_theharvester(self):
        """Run theHarvester for organization-wide information"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[1/4] Running theHarvester...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        harvester_file = os.path.join(self.output_dir, "theharvester.txt")
        self._run_command_with_output(
            f"theHarvester -d {self.target} -l 100 -b all",
            harvester_file,
            "Organization-wide OSINT gathering"
        )
    
    def _run_whois(self):
        """Run whois for domain registration information"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[2/4] Running whois...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        whois_file = os.path.join(self.output_dir, "whois.txt")
        self._run_command_with_output(
            f"whois {self.target}",
            whois_file,
            "Domain registration information lookup"
        )
    
    def _run_shodan(self):
        """Run Shodan for organization-wide information"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[3/4] Running Shodan...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        shodan_file = os.path.join(self.output_dir, "shodan.txt")
        self._run_command_with_output(
            f"shodan search --limit 100 org:{self.target}",
            shodan_file,
            "Organization-wide Shodan search"
        )
    
    def _generate_checklist(self):
        """Generate a physical security checklist"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[4/4] Generating physical security checklist...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        checklist = f"""# Physical Security Assessment Checklist
## Building Exterior
- [ ] Perimeter fencing is intact and secure
- [ ] Lighting is adequate around the building perimeter
- [ ] Surveillance cameras cover all entry points and perimeter
- [ ] Parking areas are monitored and secured
- [ ] Trash and recycling areas are secured
- [ ] Roof access points are secured
- [ ] Utility access points (electrical, HVAC, etc.) are secured
## Building Entry Points
- [ ] Main entrance is monitored and staffed during business hours
- [ ] All doors are solid core and in good condition
- [ ] Door locks are functioning properly
- [ ] Door hinges are protected from removal
- [ ] Windows are secured and unbreakable
- [ ] Emergency exits are alarmed and monitored
- [ ] Loading docks are secured and monitored
## Reception Area
- [ ] Receptionist is present during business hours
- [ ] Visitor sign-in procedure is in place
- [ ] Visitor badges are issued and visible
- [ ] Visitors are escorted at all times
- [ ] Waiting area is separated from secure areas
- [ ] Surveillance cameras monitor the reception area
## Internal Security
- [ ] Access control system is in place and functioning
- [ ] Security badges are required for access
- [ ] Sensitive areas require additional authentication
- [ ] Server room is locked and access is logged
- [ ] Surveillance cameras monitor sensitive areas
- [ ] Security patrols are conducted regularly
- [ ] Alarm system is tested regularly
## Employee Security
- [ ] Security awareness training is provided
- [ ] Clean desk policy is enforced
- [ ] Sensitive documents are properly stored
- [ ] Computer systems are locked when unattended
- [ ] Password policies are enforced
- [ ] Two-factor authentication is used where appropriate
- [ ] Employee termination procedures include access revocation
## Document and Media Security
- [ ] Sensitive documents are shredded when no longer needed
- [ ] Secure shredding containers are available
- [ ] Media destruction procedures are in place
- [ ] Document retention policies are followed
- [ ] Classified information is properly marked and stored
- [ ] Secure courier services are used for sensitive documents
## Incident Response
- [ ] Incident response plan is in place
- [ ] Security incidents are documented and reviewed
- [ ] Local law enforcement contact information is available
- [ ] Emergency response procedures are documented
- [ ] Backup systems are tested regularly
- [ ] Disaster recovery plan is in place
- [ ] Business continuity plan is tested regularly
## Recommendations
1. Conduct regular physical security assessments
2. Implement access control systems where needed
3. Provide ongoing security awareness training
4. Establish clear policies for visitors and contractors
5. Regularly test and update security procedures
6. Coordinate with local law enforcement for emergency response
7. Consider hiring a professional security assessment team
"""
        
        with open(os.path.join(self.output_dir, "physical_security_checklist.md"), 'w') as f:
            f.write(checklist)
        
        print(f"{Colors.GREEN}[+] Physical security checklist generated{Colors.RESET}")
    
    def _extract_whois_field(self, text, pattern):
        """Extract a field from whois output using regex"""
        matches = re.findall(pattern, text)
        return matches[0] if matches else None
    
    def _generate_summary(self):
        """Generate a clean summary of physical reconnaissance findings"""
        print(f"\n{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.MAGENTA}                   PHYSICAL RECONNAISSANCE SUMMARY{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}Target: {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        
        # Parse theHarvester results
        harvester_file = os.path.join(self.output_dir, "theharvester.txt")
        emails = []
        subdomains = []
        hosts = []
        
        if os.path.exists(harvester_file):
            with open(harvester_file, 'r') as f:
                harvester_data = f.read()
            
            # Extract emails, subdomains, and hosts
            emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', harvester_data)
            subdomains = re.findall(r'[\w\.-]+\.' + re.escape(self.target), harvester_data)
            hosts = re.findall(r'\d+\.\d+\.\d+\.\d+', harvester_data)
        
        if emails:
            print(f"{Colors.YELLOW}[+] Email Addresses:{Colors.RESET} {len(emails)} found")
        if subdomains:
            print(f"{Colors.YELLOW}[+] Subdomains:{Colors.RESET} {len(subdomains)} found")
        if hosts:
            print(f"{Colors.YELLOW}[+] Hosts:{Colors.RESET} {len(hosts)} found")
        
        # Parse whois results
        whois_file = os.path.join(self.output_dir, "whois.txt")
        if os.path.exists(whois_file):
            with open(whois_file, 'r') as f:
                whois_data = f.read()
            
            # Extract key information
            registrar = self._extract_whois_field(whois_data, r"Registrar: (.+)")
            creation_date = self._extract_whois_field(whois_data, r"Creation Date: (.+)")
            expiration_date = self._extract_whois_field(whois_data, r"Registry Expiry Date: (.+)")
            
            if registrar:
                print(f"{Colors.YELLOW}[+] Domain Registrar:{Colors.RESET} {registrar}")
            if creation_date:
                print(f"{Colors.YELLOW}[+] Domain Created:{Colors.RESET} {creation_date}")
            if expiration_date:
                print(f"{Colors.YELLOW}[+] Domain Expires:{Colors.RESET} {expiration_date}")
        
        # Parse Shodan results
        shodan_file = os.path.join(self.output_dir, "shodan.txt")
        services = []
        vulns = []
        
        if os.path.exists(shodan_file):
            try:
                with open(shodan_file, 'r') as f:
                    shodan_data = f.read()
                
                # Parse Shodan output
                shodan_json = json.loads(shodan_data)
                
                if 'matches' in shodan_json and shodan_json['matches']:
                    # Extract key information
                    for match in shodan_json['matches']:
                        ip = match.get('ip_str', '')
                        port = match.get('port', '')
                        service = match.get('product', '')
                        
                        if service:
                            services.append(f"{service} on {ip}:{port}")
                        
                        if 'vulns' in match:
                            for vuln in match['vulns']:
                                vulns.append(f"{vuln} on {ip}:{port}")
                
                if services:
                    print(f"{Colors.YELLOW}[+] Internet-Exposed Services:{Colors.RESET} {len(services)} found")
                if vulns:
                    print(f"{Colors.RED}[!] Known Vulnerabilities:{Colors.RESET} {len(vulns)} found")
                
            except json.JSONDecodeError:
                print(f"{Colors.YELLOW}[+] Shodan Information:{Colors.RESET} Search completed. See raw output for details.")
        
        print(f"{Colors.YELLOW}[+] Physical Security Checklist:{Colors.RESET} Generated in output directory")
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
    
    def run(self):
        """Execute physical reconnaissance with OSINT and guidance"""
        # Set up signal handler for EOF (Ctrl+D)
        signal.signal(signal.SIGINT, self._handle_eof)
        
        print(f"{Colors.CYAN}[+] Output will be saved in: {self.output_dir}{Colors.RESET}")
        
        # Run all physical reconnaissance tools
        self._run_theharvester()
        self._run_whois()
        self._run_shodan()
        self._generate_checklist()
        
        # Generate summary
        self._generate_summary()
        
        print(f"\n{Colors.GREEN}[✓] Physical reconnaissance completed successfully!{Colors.RESET}")
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
            
        recon = PhysicalRecon(target)
        recon.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.CYAN}Operation cancelled by user. Returning to reconnaissance menu...{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}An unexpected error occurred: {str(e)}{Colors.RESET}")
        sys.exit(1)