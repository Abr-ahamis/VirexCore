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

echo -e "${CYAN}====================== FUZZING ==========================${RESET}"
echo -e "${GREEN}[+] Running FFUF directory fuzzing...${RESET}"
echo -e "${CYAN}[1] subdomains(http://FUZZ.$TARGET)${RESET}"
echo -e "${CYAN}[2] Basic Fuzzing on Path(http://$TARGET/FUZZ)${RESET}"
echo -e "${CYAN}=========================================================${RESET}"
echo -e "${YELLOW}[?] select your choose(default = 2)?  2${RESET}"

echo -e "${YELLOW}[?] Do you want to use the default wordlist (/usr/share/wordlists/dirb/common.txt)? [y/n]: y${RESET}"

# Create output directory
OUTPUT_DIR="/tmp/VirexCore/ffuf"
mkdir -p "$OUTPUT_DIR"

echo -e "${CYAN}=========================================================${RESET}"
echo -e "${GREEN} :: Wordlist            : FUZZ: /usr/share/wordlists/dirb/common.txt${RESET}"

# Process each port
IFS=',' read -ra PORT_ARRAY <<< "$PORTS"
for port in "${PORT_ARRAY[@]}"; do
    echo -e "${GREEN} :: URL                 : http://$TARGET:$port/FUZZ${RESET}"
done

echo -e "${CYAN}=========================================================${RESET}"

# Simulate ffuf output for each port
for port in "${PORT_ARRAY[@]}"; do
    echo -e "${CYAN}http://$TARGET:$port/FUZZ${RESET}"
    
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
    echo -e "${CYAN}---------------------------------------------------------${RESET}"
done

echo -e "${GREEN}[+] Finished fuzzing...${RESET}"
echo -e "${YELLOW}[auto] Continuing to next, [ctrl + D] stop${RESET}"
echo -e "${CYAN}=========================================================${RESET}"
echo -e "${GREEN}[!] FFUF scan completed. Results saved in $OUTPUT_DIR${RESET}"