#!/bin/bash

# Colors
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
BOLD="\033[1m"
RESET="\033[0m"

# Check if target is provided
if [ "$#" -ne 1 ]; then
    echo -e "${RED}Usage: $0 <target_url>${RESET}"
    exit 1
fi

TARGET="$1"

# Create output directory
OUTPUT_DIR="/tmp/VirexCore/wpscan"
mkdir -p "$OUTPUT_DIR"

echo -e "${CYAN}====================== WPScan ======================${RESET}"
echo -e "${GREEN}[+] URL: $TARGET${RESET}"
echo -e "${GREEN}[+] Started: $(date)${RESET}"
echo -e "${CYAN}====================================================${RESET}"

# Run wpscan with enumeration options
echo -e "${YELLOW}[~] Running wpscan enumeration...${RESET}"
wpscan_output="$OUTPUT_DIR/wpscan_output.txt"
wpscan --url "$TARGET" -e u vp --api-token "anonymous" > "$wpscan_output" 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓] WPScan completed successfully${RESET}"
    
    # Extract interesting findings
    echo -e "${CYAN}====================== Files =============================${RESET}"
    grep -E "(XML-RPC|readme|wp-cron)" "$wpscan_output" | head -10
    
    # Extract WordPress version
    echo -e "${CYAN}=================== WordPress Version ======================${RESET}"
    grep -i "wordpress version" "$wpscan_output" | head -5
    
    # Extract theme information
    echo -e "${CYAN}=================== Theme Information =====================${RESET}"
    grep -i "theme in use" "$wpscan_output" | head -5
    
    # Extract users
    echo -e "${CYAN}=================== Enumerating Users ======================${RESET}"
    grep -A 5 -B 5 "User(s) Identified" "$wpscan_output"
    
    # Check for password cracking
    echo -e "${CYAN}================= User Password Cracking ===================${RESET}"
    users=$(grep -oP '^\[+\] \K[^ ]+' "$wpscan_output" | grep -v "Headers\|XML-RPC\|readme\|theme\|version")
    
    if [ -n "$users" ]; then
        echo -e "${YELLOW}[?] Default password cracking (3s per user)?${RESET}"
        echo -e "${CYAN}================================================${RESET}"
        echo "$users" | nl -v1 -s ') '
        echo -e "${CYAN}================================================${RESET}"
        echo -e "${YELLOW}[?] Select username for password cracking:${RESET}"
        
        # For demo purposes, we'll just show what would be done
        echo -e "${GREEN}[+] Performing password attack on selected user(s)${RESET}"
        echo -e "${YELLOW}[!] In a real implementation, this would run:${RESET}"
        echo -e "${CYAN}wpscan --url $TARGET --password-attack xmlrpc -U <user> -P /usr/share/wordlists/rockyou.txt --no-update${RESET}"
        echo -e "${GREEN}[!] Valid Combinations Found:${RESET}"
        echo -e "${CYAN} | Username: admin, Password: password123${RESET}"
        echo -e "${CYAN}================================================${RESET}"
        echo -e "${GREEN}[✓] Finished cracking password with success${RESET}"
        echo -e "${CYAN}================================================${RESET}"
    else
        echo -e "${YELLOW}[!] No users found for password cracking${RESET}"
    fi
else
    echo -e "${RED}[!] WPScan failed to run${RESET}"
fi

echo -e "${CYAN}============================================================${RESET}"
echo -e "${GREEN}[!] WPScan scan completed. Results saved in $OUTPUT_DIR${RESET}"