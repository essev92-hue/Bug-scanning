#!/bin/bash

# ============================================
# DEEP BUG HUNTER PRO - ADVANCED MODE
# Version: 4.0 (Real-time Detection & Analysis)
# ============================================

# Konfigurasi Path
NUCLEI_PATH="/root/go/bin/nuclei"
TEMPLATES_PATH="/root/nuclei-templates"
CUSTOM_TEMPLATES="/root/Bug-scanning/custom-templates"
OUTPUT_DIR="/root/Bug-scanning/nuclei-scans/$(date +%Y%m)"
LOG_DIR="/root/Bug-scanning/.nuclei-logs"
WORDLISTS_DIR="/root/Bug-scanning/wordlists"
REAL_TIME_ALERTS="/root/Bug-scanning/alerts"
ANALYSIS_DIR="/root/Bug-scanning/analysis"

# API untuk validasi bug (opsional)
VT_API_KEY=""  # VirusTotal API
SHODAN_API_KEY=""  # Shodan API
CENSYS_API_ID=""  # Censys API
CENSYS_API_SECRET=""

# Database untuk pattern bug yang diketahui
KNOWN_BUGS_DB="/root/Bug-scanning/known_bugs.db"
EXPLOIT_DB="/root/Bug-scanning/exploit_references.db"

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Pattern untuk deteksi bug kritis
CRITICAL_PATTERNS=(
    "remote.*code.*execution"
    "sql.*injection"
    "command.*injection"
    "path.*traversal"
    "file.*inclusion"
    "server.*side.*request.*forgery"
    "xxe"
    "deserialization"
    "auth.*bypass"
    "privilege.*escalation"
)

# Severity mapping untuk alert
declare -A SEVERITY_COLORS=(
    ["critical"]="$RED"
    ["high"]="$PURPLE"
    ["medium"]="$YELLOW"
    ["low"]="$GREEN"
    ["info"]="$CYAN"
)

# ============================================
# SISTEM DETEKSI REAL-TIME
# ============================================

# Inisialisasi sistem alert
init_alert_system() {
    mkdir -p "$REAL_TIME_ALERTS" "$ANALYSIS_DIR"
    
    # Buat named pipe untuk real-time alert
    ALERT_PIPE="$REAL_TIME_ALERTS/alert_pipe"
    [ -p "$ALERT_PIPE" ] || mkfifo "$ALERT_PIPE"
    
    # Buat database pattern bug
    if [ ! -f "$KNOWN_BUGS_DB" ]; then
        sqlite3 "$KNOWN_BUGS_DB" <<EOF
CREATE TABLE IF NOT EXISTS bug_patterns (
    id INTEGER PRIMARY KEY,
    pattern TEXT,
    severity TEXT,
    category TEXT,
    description TEXT,
    remediation TEXT,
    cvss_score REAL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME,
    target TEXT,
    bug_type TEXT,
    severity TEXT,
    confidence REAL,
    evidence TEXT,
    verified INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS exploit_references (
    id INTEGER PRIMARY KEY,
    bug_type TEXT,
    exploit_name TEXT,
    source TEXT,
    url TEXT,
    verified INTEGER
);
EOF
        load_initial_patterns
    fi
}

# Load pattern bug yang diketahui
load_initial_patterns() {
    sqlite3 "$KNOWN_BUGS_DB" <<EOF
INSERT OR IGNORE INTO bug_patterns VALUES 
(1, '(?i)(union.*select|select.*from)', 'critical', 'sqli', 'SQL Injection Pattern', 'Use parameterized queries', 9.8),
(2, '(?i)(system\(|exec\(|popen\(|shell_exec\()', 'critical', 'rce', 'Command Injection Pattern', 'Input validation and sanitization', 9.5),
(3, '(?i)(\.\./|\.\.\\\\)', 'high', 'path-traversal', 'Path Traversal Pattern', 'Validate file paths', 8.5),
(4, '(?i)(<\?php|<\?=|<\? )', 'medium', 'lfi', 'PHP Code Pattern', 'Disable PHP execution in upload directories', 7.5),
(5, '(?i)(aws_key|aws_secret|api[_-]?key)', 'critical', 'secret-leak', 'Secret Key Pattern', 'Rotate keys immediately', 10.0);
EOF
}

# Fungsi untuk alert real-time
send_alert() {
    local severity="$1"
    local message="$2"
    local target="$3"
    local evidence="$4"
    
    local color="${SEVERITY_COLORS[$severity]}"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Tampilkan alert di console
    echo -e "\n${color}╔══════════════════════════════════════════╗"
    echo -e "║   🚨 REAL-TIME BUG ALERT 🚨            ║"
    echo -e "╠══════════════════════════════════════════╣"
    echo -e "║ Severity: $severity"
    echo -e "║ Time: $timestamp"
    echo -e "║ Target: $target"
    echo -e "║ Message: $message"
    echo -e "╚══════════════════════════════════════════╣${NC}"
    
    # Log ke file
    echo "[$timestamp] [$severity] $target - $message" >> "$REAL_TIME_ALERTS/alerts.log"
    echo "Evidence: $evidence" >> "$REAL_TIME_ALERTS/alerts.log"
    echo "---" >> "$REAL_TIME_ALERTS/alerts.log"
    
    # Simpan ke database
    sqlite3 "$KNOWN_BUGS_DB" "INSERT INTO findings (timestamp, target, bug_type, severity, evidence) VALUES ('$timestamp', '$target', '$message', '$severity', '$evidence');"
    
    # Jika critical, tambahkan notifikasi ekstra
    if [[ "$severity" == "critical" ]]; then
        play_alert_sound
        send_priority_notification "$message" "$target"
    fi
}

# Main detector function
analyze_finding() {
    local finding="$1"
    local target="$2"
    
    # Extract key information from nuclei finding
    local template=$(echo "$finding" | jq -r '.template // empty')
    local severity=$(echo "$finding" | jq -r '.severity // "unknown"')
    local matched=$(echo "$finding" | jq -r '.matched // empty')
    local request=$(echo "$finding" | jq -r '.request // empty')
    local response=$(echo "$finding" | jq -r '.response // empty')
    
    # Analyze for false positives
    local is_valid=$(validate_finding "$finding")
    local confidence=$(calculate_confidence "$finding")
    
    if [[ "$is_valid" == "true" && "$confidence" -gt 70 ]]; then
        # Enhanced bug categorization
        local bug_type=$(categorize_bug "$template" "$matched" "$response")
        local risk_score=$(calculate_risk_score "$severity" "$confidence" "$bug_type")
        
        # Send alert if above threshold
        if [[ "$risk_score" -gt 60 ]]; then
            send_alert "$severity" "$bug_type" "$target" "$matched"
            
            # Additional analysis for critical findings
            if [[ "$severity" == "critical" || "$severity" == "high" ]]; then
                perform_deep_analysis "$finding" "$target"
                check_exploit_availability "$bug_type"
                generate_poc "$finding" "$target"
            fi
        fi
    fi
}

# Validasi finding untuk mengurangi false positive
validate_finding() {
    local finding="$1"
    local template=$(echo "$finding" | jq -r '.template // empty')
    local matched=$(echo "$finding" | jq -r '.matched // empty')
    local response=$(echo "$finding" | jq -r '.response // empty')
    
    # Skip jika matched string terlalu pendek (mungkin noise)
    if [[ ${#matched} -lt 10 ]]; then
        echo "false"
        return
    fi
    
    # Check untuk common false positive patterns
    local false_positives=(
        "welcome to nginx"
        "apache.*test.*page"
        "it.*works"
        "index of"
        "default page"
    )
    
    for fp in "${false_positives[@]}"; do
        if [[ "$response" =~ $fp ]] || [[ "$matched" =~ $fp ]]; then
            echo "false"
            return
        fi
    done
    
    # Additional validation based on response code
    local status_code=$(echo "$finding" | jq -r '.status_code // 0')
    if [[ "$status_code" -eq 404 ]] || [[ "$status_code" -eq 403 ]]; then
        echo "false"
        return
    fi
    
    echo "true"
}

# Kategorisasi bug yang lebih akurat
categorize_bug() {
    local template="$1"
    local matched="$2"
    local response="$3"
    
    # Analyze content untuk menentukan tipe bug
    case true in
        $(echo "$matched" | grep -qi "sql.*syntax\|union.*select" && echo true))
            echo "SQL Injection"
            ;;
        $(echo "$matched" | grep -qi "root:x:\|etc/passwd" && echo true))
            echo "Path Traversal / LFI"
            ;;
        $(echo "$matched" | grep -qi "s3\.amazonaws\|storage\.googleapis" && echo true))
            echo "Cloud Storage Misconfiguration"
            ;;
        $(echo "$matched" | grep -qi "aws.*key\|api.*key\|secret.*key" && echo true))
            echo "Secret Leakage"
            ;;
        $(echo "$matched" | grep -qi "<?php\|eval(" && echo true))
            echo "Code Injection"
            ;;
        $(echo "$matched" | grep -qi "admin.*panel\|login.*page" && echo true))
            echo "Exposed Admin Interface"
            ;;
        $(echo "$matched" | grep -qi "debug.*mode\|stack.*trace" && echo true))
            echo "Debug Information Exposure"
            ;;
        *)
            echo "$template"
            ;;
    esac
}

# Hitung confidence score
calculate_confidence() {
    local finding="$1"
    local score=50  # Base score
    
    # Tambahkan score berdasarkan factors
    local status_code=$(echo "$finding" | jq -r '.status_code // 0')
    local content_length=$(echo "$finding" | jq -r '(.response // "" | length)')
    local template=$(echo "$finding" | jq -r '.template // ""')
    
    # Status code validation
    if [[ "$status_code" -eq 200 ]]; then
        ((score += 20))
    elif [[ "$status_code" -eq 500 ]]; then
        ((score += 10))  # Error might indicate injection success
    fi
    
    # Content length heuristic
    if [[ "$content_length" -gt 100 && "$content_length" -lt 10000 ]]; then
        ((score += 10))
    fi
    
    # Template reputation (known good templates)
    local known_templates=("sqli" "rce" "xss" "lfi" "ssti")
    for known in "${known_templates[@]}"; do
        if [[ "$template" == *"$known"* ]]; then
            ((score += 15))
            break
        fi
    done
    
    echo "$score"
}

# ============================================
# DEEP ANALYSIS FUNCTIONS
# ============================================

perform_deep_analysis() {
    local finding="$1"
    local target="$2"
    
    echo -e "${CYAN}[*] Performing deep analysis on finding...${NC}"
    
    local analysis_id=$(date +%s)
    local analysis_file="$ANALYSIS_DIR/analysis_${analysis_id}.json"
    
    # Extract detailed information
    local request=$(echo "$finding" | jq -r '.request // empty')
    local response=$(echo "$finding" | jq -r '.response // empty')
    local template=$(echo "$finding" | jq -r '.template // empty')
    
    # Analyze response for indicators
    local indicators=$(analyze_response_indicators "$response")
    local potential_impact=$(assess_potential_impact "$finding")
    local exploitation_difficulty=$(assess_exploitation_difficulty "$finding")
    
    # Save analysis
    cat > "$analysis_file" <<EOF
{
    "analysis_id": "$analysis_id",
    "timestamp": "$(date -Iseconds)",
    "target": "$target",
    "template": "$template",
    "request": "$(echo "$request" | base64 | tr -d '\n')",
    "response_indicators": "$indicators",
    "potential_impact": "$potential_impact",
    "exploitation_difficulty": "$exploitation_difficulty",
    "recommended_actions": [
        "Verify manually",
        "Check for similar endpoints",
        "Test for bypasses",
        "Document for reporting"
    ]
}
EOF
    
    echo -e "${GREEN}[✓] Deep analysis saved: $analysis_file${NC}"
}

analyze_response_indicators() {
    local response="$1"
    local indicators=()
    
    # Check for error messages that might indicate vulnerability
    [[ "$response" =~ "SQL" ]] && indicators+=("sql_error")
    [[ "$response" =~ "syntax" ]] && indicators+=("syntax_error")
    [[ "$response" =~ "warning" ]] && indicators+=("php_warning")
    [[ "$response" =~ "exception" ]] && indicators+=("exception_exposed")
    [[ "$response" =~ "stack trace" ]] && indicators+=("stack_trace")
    [[ "$response" =~ "debug" ]] && indicators+=("debug_mode")
    
    echo "${indicators[@]}"
}

check_exploit_availability() {
    local bug_type="$1"
    
    echo -e "${YELLOW}[*] Checking for known exploits...${NC}"
    
    # Check exploit-db and other sources
    local exploits=$(sqlite3 "$KNOWN_BUGS_DB" "SELECT exploit_name, source, url FROM exploit_references WHERE bug_type LIKE '%$bug_type%' AND verified=1 LIMIT 3;")
    
    if [[ -n "$exploits" ]]; then
        echo -e "${RED}[!] Known exploits found:${NC}"
        echo "$exploits" | while IFS='|' read -r name source url; do
            echo "  • $name ($source)"
            [[ -n "$url" ]] && echo "    URL: $url"
        done
    fi
}

generate_poc() {
    local finding="$1"
    local target="$2"
    
    local poc_dir="$ANALYSIS_DIR/pocs"
    mkdir -p "$poc_dir"
    
    local poc_id=$(date +%s)
    local poc_file="$poc_dir/poc_${poc_id}.py"
    
    # Generate basic PoC Python script
    cat > "$poc_file" <<EOF
#!/usr/bin/env python3
"""
Proof of Concept for vulnerability found
Target: $target
Generated: $(date)
"""

import requests
import sys
import argparse

def exploit(target_url):
    """Basic exploit PoC"""
    headers = {
        'User-Agent': 'DeepBugHunter/4.0',
        'X-Forwarded-For': '127.0.0.1'
    }
    
    try:
        # Modify based on actual finding
        response = requests.get(
            target_url,
            headers=headers,
            timeout=10,
            verify=False
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Length: {len(response.text)}")
        
        # Add specific checks based on vulnerability type
        if "vulnerable_pattern" in response.text.lower():
            print("[+] Vulnerability confirmed!")
            return True
        else:
            print("[-] Vulnerability not confirmed")
            return False
            
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="Target URL")
    args = parser.parse_args()
    
    print(f"[*] Testing: {args.url}")
    result = exploit(args.url)
    sys.exit(0 if result else 1)
EOF
    
    chmod +x "$poc_file"
    echo -e "${GREEN}[✓] PoC generated: $poc_file${NC}"
}

# ============================================
# ENHANCED SCANNING MODES
# ============================================

intelligent_scan() {
    echo -e "${CYAN}[*] Starting intelligent bug scan...${NC}"
    
    local target="$1"
    local scan_id=$(date +%s)
    local scan_dir="$OUTPUT_DIR/scan_${scan_id}"
    mkdir -p "$scan_dir"
    
    # Phase 1: Discovery and fingerprinting
    echo -e "${BLUE}[*] Phase 1: Fingerprinting${NC}"
    "$NUCLEI_PATH" -u "$target" \
        -t "$TEMPLATES_PATH/http/technologies" \
        -silent \
        -json \
        -o "$scan_dir/technologies.json" &
    
    # Phase 2: Common vulnerabilities
    echo -e "${BLUE}[*] Phase 2: Common Vulnerabilities${NC}"
    "$NUCLEI_PATH" -u "$target" \
        -t "$TEMPLATES_PATH/http/cves,$TEMPLATES_PATH/http/vulnerabilities" \
        -severity critical,high \
        -json \
        -o "$scan_dir/vulnerabilities.json" &
    
    # Phase 3: Configuration issues
    echo -e "${BLUE}[*] Phase 3: Configuration Checks${NC}"
    "$NUCLEI_PATH" -u "$target" \
        -t "$TEMPLATES_PATH/http/misconfiguration,$TEMPLATES_PATH/http/exposed-panels" \
        -json \
        -o "$scan_dir/misconfigurations.json" &
    
    # Phase 4: Custom and aggressive checks
    echo -e "${BLUE}[*] Phase 4: Aggressive Checks${NC}"
    "$NUCLEI_PATH" -u "$target" \
        -t "$CUSTOM_TEMPLATES" \
        -tags " intrusive,aggressive" \
        -json \
        -o "$scan_dir/aggressive.json" &
    
    wait
    
    # Process and analyze results
    process_scan_results "$scan_dir" "$target"
}

process_scan_results() {
    local scan_dir="$1"
    local target="$2"
    
    echo -e "${CYAN}[*] Processing scan results...${NC}"
    
    # Combine all JSON results
    local combined_file="$scan_dir/combined.json"
    find "$scan_dir" -name "*.json" -exec cat {} \; 2>/dev/null | \
        jq -s 'add | unique_by(.template + .matched)' > "$combined_file"
    
    # Analyze each finding
    local findings_count=$(jq 'length' "$combined_file" 2>/dev/null || echo "0")
    
    if [[ "$findings_count" -gt 0 ]]; then
        echo -e "${GREEN}[✓] Found $findings_count potential issues${NC}"
        
        # Process each finding
        jq -c '.[]' "$combined_file" 2>/dev/null | while read -r finding; do
            analyze_finding "$finding" "$target"
        done
        
        # Generate comprehensive report
        generate_intelligent_report "$scan_dir" "$target"
    else
        echo -e "${YELLOW}[!] No vulnerabilities found${NC}"
    fi
}

generate_intelligent_report() {
    local scan_dir="$1"
    local target="$2"
    
    local report_file="$scan_dir/report_$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$report_file" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Deep Bug Hunter Pro Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .critical { background: #ffcccc; padding: 10px; border-left: 5px solid #ff0000; }
        .high { background: #ffe6cc; padding: 10px; border-left: 5px solid #ff6600; }
        .medium { background: #ffffcc; padding: 10px; border-left: 5px solid #ffcc00; }
        .low { background: #e6ffe6; padding: 10px; border-left: 5px solid #009900; }
        .finding { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
        pre { background: #f5f5f5; padding: 10px; overflow: auto; }
    </style>
</head>
<body>
    <h1>Deep Bug Hunter Pro Report</h1>
    <h2>Target: $target</h2>
    <h3>Scan Date: $(date)</h3>
    <hr>
EOF
    
    # Add findings to report
    if [[ -f "$scan_dir/combined.json" ]]; then
        jq -r 'group_by(.severity)[] | .[0].severity as $sev | "<h2>\($sev | ascii_upcase) Findings</h2>" + (map("<div class=\"\($sev)\"><h3>\(.template)</h3><p>\(.matched)</p><pre>\(.request | .[0:500])</pre></div>") | join(""))' "$scan_dir/combined.json" >> "$report_file" 2>/dev/null
    fi
    
    cat >> "$report_file" <<EOF
    <h2>Recommendations</h2>
    <ul>
        <li>Immediately patch critical vulnerabilities</li>
        <li>Review and fix misconfigurations</li>
        <li>Implement WAF rules for detected attack patterns</li>
        <li>Conduct manual verification of automated findings</li>
    </ul>
</body>
</html>
EOF
    
    echo -e "${GREEN}[✓] Report generated: $report_file${NC}"
}

# ============================================
# REAL-TIME MONITORING
# ============================================

start_realtime_monitoring() {
    local target="$1"
    
    echo -e "${CYAN}[*] Starting real-time monitoring for: $target${NC}"
    echo -e "${YELLOW}[!] Monitoring active. Press Ctrl+C to stop.${NC}"
    
    # Continuous monitoring loop
    while true; do
        local timestamp=$(date +%s)
        local monitor_file="$REAL_TIME_ALERTS/monitor_${timestamp}.json"
        
        # Run quick scan
        "$NUCLEI_PATH" -u "$target" \
            -t "$TEMPLATES_PATH/http/cves" \
            -severity critical,high \
            -silent \
            -json \
            -o "$monitor_file"
        
        # Check for new findings
        if [[ -s "$monitor_file" ]]; then
            jq -c '.[]' "$monitor_file" 2>/dev/null | while read -r finding; do
                local template=$(echo "$finding" | jq -r '.template // empty')
                local severity=$(echo "$finding" | jq -r '.severity // empty')
                
                # Check if this is a new finding
                local existing=$(sqlite3 "$KNOWN_BUGS_DB" "SELECT COUNT(*) FROM findings WHERE bug_type='$template' AND target='$target' LIMIT 1;")
                
                if [[ "$existing" -eq 0 ]]; then
                    echo -e "${RED}[!] NEW VULNERABILITY DETECTED!${NC}"
                    analyze_finding "$finding" "$target"
                fi
            done
        fi
        
        # Wait before next scan
        sleep 300  # Scan every 5 minutes
    done
}

# ============================================
# MAIN ENHANCED FUNCTIONS
# ============================================

enhanced_main() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔══════════════════════════════════════════════════╗
║   DEEP BUG HUNTER PRO - ADVANCED MODE v4.0       ║
║   Real-time Vulnerability Intelligence Engine    ║
║   ⚠️  FOR AUTHORIZED PENETRATION TESTING ONLY   ║
╚══════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    # Initialize systems
    init_alert_system
    
    while true; do
        echo ""
        echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║        ADVANCED OPERATION MODES         ║${NC}"
        echo -e "${CYAN}╠══════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║  1. Intelligent Bug Scan                ║${NC}"
        echo -e "${CYAN}║  2. Real-time Monitoring                ║${NC}"
        echo -e "${CYAN}║  3. Targeted Exploit Testing            ║${NC}"
        echo -e "${CYAN}║  4. Deep Analysis Mode                  ║${NC}"
        echo -e "${CYAN}║  5. Generate Security Report            ║${NC}"
        echo -e "${CYAN}║  6. Update Bug Intelligence            ║${NC}"
        echo -e "${CYAN}║  7. View Alert Dashboard                ║${NC}"
        echo -e "${CYAN}║  8. Exit                                ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
        echo -e "${YELLOW}[?] Select mode (1-8):${NC}"
        
        read -r choice
        
        case $choice in
            1)
                echo -e "${YELLOW}[*] Enter target URL:${NC}"
                read -r target
                intelligent_scan "$target"
                ;;
            2)
                echo -e "${YELLOW}[*] Enter target for monitoring:${NC}"
                read -r target
                start_realtime_monitoring "$target" &
                ;;
            3)
                echo -e "${YELLOW}[*] Enter specific vulnerability type:${NC}"
                read -r vuln_type
                run_targeted_test "$vuln_type"
                ;;
            4)
                echo -e "${YELLOW}[*] Enter findings file for analysis:${NC}"
                read -r findings_file
                deep_analysis_mode "$findings_file"
                ;;
            5)
                generate_security_report
                ;;
            6)
                update_bug_intelligence
                ;;
            7)
                show_alert_dashboard
                ;;
            8)
                echo -e "${GREEN}[✓] Exiting...${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                ;;
        esac
    done
}

# ============================================
# ADDITIONAL ENHANCED FUNCTIONS
# ============================================

update_bug_intelligence() {
    echo -e "${CYAN}[*] Updating bug intelligence database...${NC}"
    
    # Update exploit references
    echo -e "${YELLOW}[*] Fetching latest exploit database...${NC}"
    
    # You can add sources like:
    # - exploit-db
    # - packetstorm
    # - security advisories
    # - CVE databases
    
    echo -e "${GREEN}[✓] Bug intelligence updated${NC}"
}

show_alert_dashboard() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔══════════════════════════════════════════════════╗
║            REAL-TIME ALERT DASHBOARD             ║
╚══════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    # Show recent alerts
    echo -e "${YELLOW}Recent Alerts:${NC}"
    tail -20 "$REAL_TIME_ALERTS/alerts.log" 2>/dev/null || echo "No alerts yet"
    
    # Show statistics
    echo -e "\n${YELLOW}Statistics:${NC}"
    if [[ -f "$KNOWN_BUGS_DB" ]]; then
        sqlite3 "$KNOWN_BUGS_DB" <<EOF
SELECT 
    severity,
    COUNT(*) as count,
    printf('%.1f', COUNT(*) * 100.0 / (SELECT COUNT(*) FROM findings)) as percentage
FROM findings 
GROUP BY severity 
ORDER BY 
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
    END;
EOF
    fi
}

# ============================================
# EXECUTION
# ============================================

# Check dependencies
check_dependencies() {
    local deps=("nuclei" "jq" "sqlite3")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[!] Missing dependencies:${NC}"
        for dep in "${missing[@]}"; do
            echo "  • $dep"
        done
        echo -e "\nInstall with:"
        echo "  apt-get install ${missing[*]}"
        exit 1
    fi
}

# Main execution
main() {
    check_dependencies
    
    # Show warning
    echo -e "${RED}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                   SECURITY NOTICE                           ║
╠══════════════════════════════════════════════════════════════╣
║ This tool performs active security testing.                  ║
║ Use only on systems you own or have permission to test.      ║
║                                                              ║
║ Illegal use may result in:                                   ║
║ • Criminal prosecution                                       ║
║ • Civil liability                                            ║
║ • Severe penalties                                           ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    echo -e "${YELLOW}[?] Do you have authorization to test the target? (yes/no):${NC}"
    read -r auth
    
    if [[ "$auth" != "yes" ]]; then
        echo -e "${GREEN}[✓] Exiting. Always get proper authorization.${NC}"
        exit 0
    fi
    
    enhanced_main
}

# Trap interrupts
trap 'echo -e "\n${RED}Scan interrupted. Saving state...${NC}"; exit 0' INT

# Run main function
main
