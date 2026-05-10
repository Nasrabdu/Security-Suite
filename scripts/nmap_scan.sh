#!/bin/bash
#
# Nmap Scanner Wrapper Script
# Quick access to 5 best Nmap commands
# Optimized for Kali Linux
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if Nmap is installed
if ! command -v nmap &> /dev/null; then
    echo -e "${RED}[!] Error: Nmap is not installed${NC}"
    echo -e "${YELLOW}[*] On Kali Linux, install with: sudo apt install nmap${NC}"
    exit 1
fi

# Function to display usage
usage() {
    cat << EOF
${BLUE}Nmap Scanner - 5 Best Commands${NC}

Usage: $0 <target> <scan_type> [options]

Scan Types:
  1, quick          Fast scan of top 100 ports
  2, intense        Comprehensive scan with OS/version detection
  3, comprehensive  Full port range scan (all 65535 ports)
  4, stealth        Evasive scan to avoid IDS/IPS
  5, vulnerability  NSE vulnerability scripts

Options:
  -o, --output FILE    Save results to file
  -j, --json          Export as JSON
  -h, --help          Show this help message

Examples:
  $0 example.com 1
  $0 192.168.1.1 vulnerability --json
  $0 https://example.com intense -o results.txt

EOF
    exit 0
}

# Parse arguments
if [ $# -lt 2 ]; then
    usage
fi

TARGET="$1"
SCAN_TYPE="$2"
shift 2

# Extract host from URL
HOST=$(echo "$TARGET" | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's|:.*$||')

# Default options
OUTPUT_FILE=""
JSON_OUTPUT=false

# Parse optional arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -j|--json)
            JSON_OUTPUT=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

# Generate output filename if not specified
if [ -z "$OUTPUT_FILE" ]; then
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    if [ "$JSON_OUTPUT" = true ]; then
        OUTPUT_FILE="nmap_${HOST}_${TIMESTAMP}.json"
    else
        OUTPUT_FILE="nmap_${HOST}_${TIMESTAMP}.txt"
    fi
fi

# Function to run Nmap command
run_nmap() {
    local cmd="$1"
    local name="$2"
    
    echo -e "${BLUE}[*] Running $name...${NC}"
    echo -e "${YELLOW}[*] Command: $cmd${NC}"
    echo -e "${YELLOW}[*] Target: $HOST${NC}"
    echo ""
    
    START_TIME=$(date +%s)
    
    if [ "$JSON_OUTPUT" = true ]; then
        # Run with XML output for JSON conversion
        eval "$cmd -oX - $HOST" > /tmp/nmap_temp.xml
        # Convert XML to JSON (requires Python)
        python3 << 'PYTHON_SCRIPT'
import xml.etree.ElementTree as ET
import json
import sys

try:
    tree = ET.parse('/tmp/nmap_temp.xml')
    root = tree.getroot()
    
    # Basic JSON structure
    result = {
        "scan_info": {},
        "hosts": [],
        "summary": {}
    }
    
    # Parse hosts
    for host in root.findall('.//host'):
        host_data = {"ports": [], "addresses": []}
        
        # Get addresses
        for addr in host.findall('.//address'):
            host_data["addresses"].append({
                "addr": addr.get('addr'),
                "type": addr.get('addrtype')
            })
        
        # Get ports
        for port in host.findall('.//port'):
            state = port.find('.//state')
            service = port.find('.//service')
            
            port_data = {
                "port": port.get('portid'),
                "protocol": port.get('protocol'),
                "state": state.get('state') if state is not None else "unknown"
            }
            
            if service is not None:
                port_data["service"] = {
                    "name": service.get('name'),
                    "product": service.get('product'),
                    "version": service.get('version')
                }
            
            host_data["ports"].append(port_data)
        
        result["hosts"].append(host_data)
    
    print(json.dumps(result, indent=2))
    
except Exception as e:
    print(json.dumps({"error": str(e)}), file=sys.stderr)
    sys.exit(1)
PYTHON_SCRIPT
        rm -f /tmp/nmap_temp.xml
    else
        # Regular text output
        eval "$cmd $HOST"
    fi
    
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    
    echo ""
    echo -e "${GREEN}[✓] $name completed in ${DURATION}s${NC}"
    echo ""
}

# Execute scan based on type
case "$SCAN_TYPE" in
    1|quick)
        NMAP_CMD="nmap -T4 -F"
        SCAN_NAME="Quick Scan"
        ;;
    2|intense)
        NMAP_CMD="nmap -T4 -A -v"
        SCAN_NAME="Intense Scan"
        ;;
    3|comprehensive)
        NMAP_CMD="nmap -sS -sV -O -p-"
        SCAN_NAME="Comprehensive Scan"
        echo -e "${YELLOW}[!] Warning: This scan may take a long time (scanning all 65535 ports)${NC}"
        ;;
    4|stealth)
        NMAP_CMD="nmap -sS -T2 -f --data-length 200"
        SCAN_NAME="Stealth Scan"
        ;;
    5|vulnerability)
        NMAP_CMD="nmap --script vuln -sV"
        SCAN_NAME="Vulnerability Scan"
        ;;
    *)
        echo -e "${RED}[!] Invalid scan type: $SCAN_TYPE${NC}"
        usage
        ;;
esac

# Add output file to command
if [ -n "$OUTPUT_FILE" ]; then
    if [ "$JSON_OUTPUT" = false ]; then
        NMAP_CMD="$NMAP_CMD -oN $OUTPUT_FILE"
    fi
fi

# Run the scan
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Nmap Security Scanner${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

run_nmap "$NMAP_CMD" "$SCAN_NAME"

# Save JSON output if requested
if [ "$JSON_OUTPUT" = true ] && [ -n "$OUTPUT_FILE" ]; then
    echo -e "${GREEN}[✓] Results saved to: $OUTPUT_FILE${NC}"
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}[✓] Scan Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
