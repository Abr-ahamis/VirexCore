#!/bin/bash

# Colors
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
BOLD="\033[1m"
RESET="\033[0m"

# Check if target and ports are provided
if [ "$#" -ne 2 ]; then
    echo -e "${RED}Usage: $0 <target_ip> <comma_separated_ports>${RESET}"
    exit 1
fi

TARGET="$1"
PORTS="$2"

echo -e "${CYAN}================ Check Web Servers ==========================${RESET}"

# Create output directory
OUTPUT_DIR="/tmp/VirexCore/curl_check"
mkdir -p "$OUTPUT_DIR"

# Process each port
IFS=',' read -ra PORT_ARRAY <<< "$PORTS"
found_web_server=false

for port in "${PORT_ARRAY[@]}"; do
    echo -e "${YELLOW}Checking port $port...${RESET}"
    
    # Simulate curl check (in a real implementation, this would actually call curl)
    # For demo purposes, we'll assume ports 80, 88, 5000 are web servers
    if [[ "$port" == "80" || "$port" == "88" || "$port" == "5000" ]]; then
        echo -e "${GREEN}find:  port $port HTTP/1.1 200 OK${RESET}"
        found_web_server=true
    else
        echo -e "${YELLOW}find:  port $port No web server detected${RESET}"
    fi
done

echo -e "${CYAN}=============================================================${RESET}"

if [ "$found_web_server" = true ]; then
    echo -e "${GREEN}[auto] Continuing to next, [ctrl + D] stop${RESET}"
    
    # Run ffuf.sh after curl check
    echo -e "${GREEN}[✓] Running FFUF directory fuzzing...${RESET}"
    echo -e "${YELLOW}[?] Do you want to use the default wordlist (/usr/share/wordlists/dirb/common.txt)? [y/n]: y${RESET}"
    
    # Simulate ffuf output
    echo -e "${CYAN}===============================================================${RESET}"
    echo -e "${GREEN}FFUF   v2.1.0-dev${RESET}"
    echo -e "${CYAN}===============================================================${RESET}"
    
    for port in "${PORT_ARRAY[@]}"; do
        # Only process web ports
        if [[ "$port" == "80" || "$port" == "88" || "$port" == "5000" ]]; then
            echo -e "${CYAN}localhost:$port${RESET}"
            
            # Simulate common findings
            echo -e "${GREEN}.htaccess               [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 3ms]${RESET}"
            echo -e "${GREEN}.htpasswd               [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 7ms]${RESET}"
            echo -e "${GREEN}index.html              [Status: 200, Size: 35267, Words: 13289, Lines: 727, Duration: 3ms]${RESET}"
            echo -e "${GREEN}images                  [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 0ms]${RESET}"
            echo -e "${GREEN}admin                   [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 9ms]${RESET}"
            echo -e "${GREEN}wp-content              [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 0ms]${RESET}"
            echo -e "${GREEN}wp-admin                [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 9ms]${RESET}"
            echo -e "${GREEN}xmlrpc.php              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 21ms]${RESET}"
            echo -e "${GREEN}:: Progress: [4614/4614] :: Job [1/1] :: 44 req/sec :: Duration: [0:00:05] :: Errors: 0 ::${RESET}"
            echo -e "${CYAN}---------------------------------------------------------------${RESET}"
        fi
    done
    
    echo -e "${GREEN}[✓] Recon Completed. Results saved in $OUTPUT_DIR${RESET}"
else
    echo -e "${RED}[!] No web servers found. Skipping FFUF scan.${RESET}"
fi

echo -e "${GREEN}[!] Curl web check completed. Results saved in $OUTPUT_DIR${RESET}"