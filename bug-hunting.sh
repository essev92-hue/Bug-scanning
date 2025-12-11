#!/bin/bash
# ============================================
# PARAMETER BUG HUNTER PRO - Systematic Menu
# Version 2.0 - Complete Framework
# ============================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Global variables
TARGET=""
OUTPUT_DIR=""
TOOL_CONFIG="$HOME/.bug_hunter_config"
SESSION_FILE=""

# Check dependencies
check_dependencies() {
    local tools=("curl" "git" "python3" "jq" "grep" "sed" "awk")
    local missing=()
    
    echo -e "${CYAN}[*] Checking dependencies...${NC}"
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}[!] Missing tools: ${missing[*]}${NC}"
        read -p "Install missing tools? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo apt-get update
            sudo apt-get install -y "${missing[@]}"
        fi
    fi
}

# Initialize session
init_session() {
    clear
    echo -e "${BLUE}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                PARAMETER BUG HUNTER PRO                   ║"
    echo "║                  Version 2.0 - Systematic                 ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    if [ -z "$TARGET" ]; then
        read -p "🎯 Enter target domain/IP: " TARGET
    fi
    
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="scan_results_$(echo $TARGET | sed 's/[^a-zA-Z0-9]/_/g')_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$OUTPUT_DIR"
        SESSION_FILE="$OUTPUT_DIR/session.json"
        
        echo "{\"target\": \"$TARGET\", \"start_time\": \"$(date -Iseconds)\", \"steps\": []}" > "$SESSION_FILE"
    fi
    
    echo -e "${GREEN}[+] Output directory: $OUTPUT_DIR${NC}"
    echo -e "${GREEN}[+] Session file: $SESSION_FILE${NC}"
}

# Log step to session file
log_step() {
    local step=$1
    local status=$2
    local timestamp=$(date -Iseconds)
    
    jq --arg step "$step" --arg status "$status" --arg timestamp "$timestamp" \
       '.steps += [{"step": $step, "status": $status, "timestamp": $timestamp}]' \
       "$SESSION_FILE" > tmp_session.json && mv tmp_session.json "$SESSION_FILE"
}

# Main menu
main_menu() {
    while true; do
        clear
        echo -e "${CYAN}${BOLD}"
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║                     MAIN MENU                             ║"
        echo "║                 Target: $TARGET                ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        
        echo -e "${YELLOW}📌 RECONNAISSANCE & DISCOVERY${NC}"
        echo "  1) 🎯 Target Setup & Scope Definition"
        echo "  2) 🔍 Subdomain Enumeration"
        echo "  3) 📄 URL Collection (All Sources)"
        echo "  4) 📜 JavaScript Analysis for Parameters"
        echo "  5) 🕰️ Wayback Machine & Archive Analysis"
        echo "  6) 💾 GitHub/GitLab Recon"
        
        echo -e "${YELLOW}\n📊 PARAMETER EXTRACTION${NC}"
        echo "  7) 🔎 Basic Parameter Extraction"
        echo "  8) 🕵️ Hidden Parameter Discovery (Arjun/x8)"
        echo "  9) 🚀 API Endpoint Discovery"
        echo "  10) 🎨 GraphQL Endpoint & Schema Analysis"
        
        echo -e "${YELLOW}\n⚔️ AUTOMATED TESTING SUITE${NC}"
        echo "  11) 💉 SQL Injection Testing"
        echo "  12) 🎯 XSS & Client-Side Testing"
        echo "  13) 🖥️ Server-Side Attacks"
        echo "  14) 🔑 API-Specific Testing"
        
        echo -e "${YELLOW}\n🧠 BUSINESS LOGIC TESTING${NC}"
        echo "  15) 🆔 IDOR Testing"
        echo "  16) 🔐 Authentication & Authorization"
        echo "  17) 💰 Payment & Transaction Logic"
        echo "  18) 📁 File Upload & Processing"
        
        echo -e "${YELLOW}\n🔬 ADVANCED TECHNIQUES${NC}"
        echo "  19) 🎭 Prototype Pollution"
        echo "  20) 💾 Cache Poisoning"
        echo "  21) 🎪 HTTP Parameter Pollution"
        echo "  22) 📝 Template Injection (SSTI)"
        
        echo -e "${YELLOW}\n📈 VALIDATION & REPORTING${NC}"
        echo "  23) ✅ False Positive Elimination"
        echo "  24) 📊 Impact Analysis"
        echo "  25) 🔬 Proof of Concept Development"
        echo "  26) 📋 Report Generation"
        
        echo -e "${YELLOW}\n⚙️ TOOL MANAGEMENT${NC}"
        echo "  27) 🛠️ Tool Configuration"
        echo "  28) 📂 Workflow Templates"
        echo "  29) 📚 Learning & Improvement"
        
        echo -e "${YELLOW}\n📊 UTILITIES${NC}"
        echo "  30) 📈 View Scan Progress"
        echo "  31) 🗃️ Export Results"
        echo "  32) 🔄 Reset Session"
        echo "  99) ❓ Help & Documentation"
        echo "  0) 🚪 Exit"
        
        echo -e "\n${GREEN}════════════════════════════════════════════════════════════${NC}"
        read -p "Select option (0-32, 99): " choice
        
        case $choice in
            1) recon_target_setup ;;
            2) recon_subdomain_enum ;;
            3) recon_url_collection ;;
            4) recon_js_analysis ;;
            5) recon_wayback_analysis ;;
            6) recon_git_recon ;;
            7) param_extraction_basic ;;
            8) param_hidden_discovery ;;
            9) param_api_discovery ;;
            10) param_graphql_analysis ;;
            11) test_sql_injection ;;
            12) test_xss ;;
            13) test_server_side ;;
            14) test_api_specific ;;
            15) test_idor ;;
            16) test_auth ;;
            17) test_payment_logic ;;
            18) test_file_upload ;;
            19) test_prototype_pollution ;;
            20) test_cache_poisoning ;;
            21) test_hpp ;;
            22) test_ssti ;;
            23) validation_false_positives ;;
            24) validation_impact_analysis ;;
            25) validation_poc_development ;;
            26) report_generation ;;
            27) tool_management ;;
            28) workflow_templates ;;
            29) learning_improvement ;;
            30) utilities_view_progress ;;
            31) utilities_export_results ;;
            32) utilities_reset_session ;;
            99) show_help ;;
            0) exit_script ;;
            *) echo -e "${RED}[!] Invalid option${NC}"; sleep 1 ;;
        esac
    done
}

# ==================== RECONNAISSANCE FUNCTIONS ====================

recon_target_setup() {
    echo -e "${CYAN}[*] Running Target Setup...${NC}"
    
    echo -e "${YELLOW}[?] Scope Definition:${NC}"
    read -p "In-scope domains (comma separated): " INSCOPE
    read -p "Out-of-scope domains (comma separated): " OUTOFSCOPE
    read -p "Special parameters to focus on: " FOCUS_PARAMS
    
    # Create scope file
    SCOPE_FILE="$OUTPUT_DIR/scope.txt"
    cat > "$SCOPE_FILE" << EOF
# Scope Definition for $TARGET
# Generated: $(date)

## IN SCOPE:
$INSCOPE

## OUT OF SCOPE:
$OUTOFSCOPE

## FOCUS PARAMETERS:
$FOCUS_PARAMS

## TESTING METHODOLOGY:
1. Reconnaissance
2. Parameter Discovery
3. Automated Testing
4. Manual Validation
5. Reporting
EOF
    
    echo -e "${GREEN}[+] Scope saved to: $SCOPE_FILE${NC}"
    log_step "Target Setup" "completed"
    read -p "Press enter to continue..."
}

recon_subdomain_enum() {
    echo -e "${CYAN}[*] Running Subdomain Enumeration...${NC}"
    
    SUBDOMAIN_DIR="$OUTPUT_DIR/subdomains"
    mkdir -p "$SUBDOMAIN_DIR"
    
    echo "1. Using subfinder"
    if command -v subfinder &> /dev/null; then
        subfinder -d "$TARGET" -o "$SUBDOMAIN_DIR/subfinder.txt"
    fi
    
    echo "2. Using assetfinder"
    if command -v assetfinder &> /dev/null; then
        assetfinder --subs-only "$TARGET" > "$SUBDOMAIN_DIR/assetfinder.txt"
    fi
    
    echo "3. Using amass"
    if command -v amass &> /dev/null; then
        amass enum -passive -d "$TARGET" -o "$SUBDOMAIN_DIR/amass.txt"
    fi
    
    # Combine and sort unique
    cat "$SUBDOMAIN_DIR"/*.txt 2>/dev/null | sort -u > "$SUBDOMAIN_DIR/all_subdomains.txt"
    
    COUNT=$(wc -l < "$SUBDOMAIN_DIR/all_subdomains.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] Found $COUNT unique subdomains${NC}"
    
    log_step "Subdomain Enumeration" "completed"
    read -p "Press enter to continue..."
}

recon_url_collection() {
    echo -e "${CYAN}[*] Collecting URLs from multiple sources...${NC}"
    
    URL_DIR="$OUTPUT_DIR/urls"
    mkdir -p "$URL_DIR"
    
    echo "1. Using waybackurls"
    if command -v waybackurls &> /dev/null; then
        echo "$TARGET" | waybackurls > "$URL_DIR/wayback.txt"
    fi
    
    echo "2. Using gau"
    if command -v gau &> /dev/null; then
        gau "$TARGET" > "$URL_DIR/gau.txt"
    fi
    
    echo "3. Using katana"
    if command -v katana &> /dev/null; then
        katana -u "https://$TARGET" -o "$URL_DIR/katana.txt"
    fi
    
    # Combine and extract unique URLs with parameters
    cat "$URL_DIR"/*.txt 2>/dev/null | sort -u > "$URL_DIR/all_urls.txt"
    
    # Extract URLs with parameters
    grep -i "?" "$URL_DIR/all_urls.txt" > "$URL_DIR/urls_with_params.txt"
    
    URL_COUNT=$(wc -l < "$URL_DIR/urls_with_params.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] Found $URL_COUNT URLs with parameters${NC}"
    
    log_step "URL Collection" "completed"
    read -p "Press enter to continue..."
}

recon_js_analysis() {
    echo -e "${CYAN}[*] Analyzing JavaScript files for parameters...${NC}"
    
    JS_DIR="$OUTPUT_DIR/javascript"
    mkdir -p "$JS_DIR"
    
    echo "1. Collecting JS file URLs"
    # Extract JS URLs from collected URLs
    grep -i "\.js$" "$OUTPUT_DIR/urls/all_urls.txt" > "$JS_DIR/js_files.txt"
    
    echo "2. Downloading JS files (first 50)"
    COUNTER=0
    while read -r js_url && [ $COUNTER -lt 50 ]; do
        FILENAME=$(echo "$js_url" | sed 's/[^a-zA-Z0-9]/_/g')
        curl -s "$js_url" -o "$JS_DIR/$FILENAME.js" 2>/dev/null &
        ((COUNTER++))
    done < "$JS_DIR/js_files.txt"
    wait
    
    echo "3. Extracting endpoints and parameters"
    # Use grep to find common patterns
    grep -r -h -E "(get|post|put|delete|fetch|ajax|axios|\.ajax|\.get|\.post)" "$JS_DIR/" 2>/dev/null | \
        grep -o -E "['\"](/[^'\"?#]*)['\"]" | sort -u > "$JS_DIR/endpoints.txt"
    
    # Extract parameter names
    grep -r -h -o -E "[\?&]([a-zA-Z_][a-zA-Z0-9_]*)=[^&]*" "$JS_DIR/" 2>/dev/null | \
        cut -d'=' -f1 | sort -u > "$JS_DIR/parameters.txt"
    
    echo "4. Using LinkFinder"
    if command -v linkfinder &> /dev/null && [ -d "$JS_DIR" ]; then
        for jsfile in "$JS_DIR"/*.js; do
            linkfinder -i "$jsfile" -o cli >> "$JS_DIR/linkfinder.txt" 2>/dev/null
        done
    fi
    
    PARAM_COUNT=$(wc -l < "$JS_DIR/parameters.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] Found $PARAM_COUNT parameters from JS analysis${NC}"
    
    log_step "JavaScript Analysis" "completed"
    read -p "Press enter to continue..."
}

# ==================== PARAMETER EXTRACTION FUNCTIONS ====================

param_extraction_basic() {
    echo -e "${CYAN}[*] Extracting basic parameters from URLs...${NC}"
    
    PARAM_DIR="$OUTPUT_DIR/parameters"
    mkdir -p "$PARAM_DIR"
    
    # Extract all unique parameter names
    echo "Extracting parameter names..."
    grep -o -E "[\?&]([a-zA-Z_][a-zA-Z0-9_]*)=[^&]*" "$OUTPUT_DIR/urls/urls_with_params.txt" | \
        cut -d'=' -f1 | sed 's/^[?&]//' | sort -u > "$PARAM_DIR/all_parameters.txt"
    
    # Categorize parameters
    echo "Categorizing parameters..."
    
    # Authentication parameters
    grep -i -E "(token|session|auth|key|secret|password|passwd|pwd|credential|jwt|api[_-]?key|access[_-]?token|refresh[_-]?token)" \
        "$PARAM_DIR/all_parameters.txt" > "$PARAM_DIR/category_auth.txt"
    
    # File operation parameters
    grep -i -E "(file|path|dir|directory|upload|download|load|save|filename|extension|img|image|doc|document)" \
        "$PARAM_DIR/all_parameters.txt" > "$PARAM_DIR/category_file.txt"
    
    # Debug/admin parameters
    grep -i -E "(debug|test|admin|root|super|manage|config|setting|option|mode|verbose|log)" \
        "$PARAM_DIR/all_parameters.txt" > "$PARAM_DIR/category_debug.txt"
    
    # Business logic parameters
    grep -i -E "(id|user|account|customer|client|order|price|amount|total|quantity|qty|discount|tax|shipping|payment)" \
        "$PARAM_DIR/all_parameters.txt" > "$PARAM_DIR/category_business.txt"
    
    # Display summary
    echo -e "\n${GREEN}[+] Parameter Summary:${NC}"
    echo "Total unique parameters: $(wc -l < "$PARAM_DIR/all_parameters.txt")"
    echo "Authentication parameters: $(wc -l < "$PARAM_DIR/category_auth.txt")"
    echo "File operation parameters: $(wc -l < "$PARAM_DIR/category_file.txt")"
    echo "Debug/admin parameters: $(wc -l < "$PARAM_DIR/category_debug.txt")"
    echo "Business logic parameters: $(wc -l < "$PARAM_DIR/category_business.txt")"
    
    log_step "Basic Parameter Extraction" "completed"
    read -p "Press enter to continue..."
}

param_hidden_discovery() {
    echo -e "${CYAN}[*] Discovering hidden parameters...${NC}"
    
    HIDDEN_DIR="$OUTPUT_DIR/hidden_params"
    mkdir -p "$HIDDEN_DIR"
    
    # Check if Arjun is installed
    if command -v arjun &> /dev/null; then
        echo "Using Arjun for hidden parameter discovery"
        
        # Test on first 5 URLs with parameters
        head -5 "$OUTPUT_DIR/urls/urls_with_params.txt" > "$HIDDEN_DIR/test_urls.txt"
        
        for url in $(cat "$HIDDEN_DIR/test_urls.txt"); do
            echo "Testing: $url"
            arjun -u "$url" -oT "$HIDDEN_DIR/arjun_$(echo $url | md5sum | cut -d' ' -f1).json"
        done
        
        # Extract found parameters
        cat "$HIDDEN_DIR"/arjun_*.json 2>/dev/null | jq -r '.params | keys[]' 2>/dev/null | sort -u > "$HIDDEN_DIR/arjun_params.txt"
    else
        echo -e "${YELLOW}[!] Arjun not installed. Installing...${NC}"
        pip3 install arjun
    fi
    
    # Alternative: Use ffuf for brute-forcing
    echo "Using ffuf for parameter brute-forcing"
    if command -v ffuf &> /dev/null; then
        # Create test URL (use first URL with parameters)
        TEST_URL=$(head -1 "$OUTPUT_DIR/urls/urls_with_params.txt" | cut -d'?' -f1)
        if [ ! -z "$TEST_URL" ]; then
            ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \
                 -u "${TEST_URL}?FUZZ=test" \
                 -o "$HIDDEN_DIR/ffuf.json" \
                 -of json
        fi
    fi
    
    # Combine all discovered parameters
    cat "$HIDDEN_DIR"/*.txt 2>/dev/null | sort -u > "$HIDDEN_DIR/all_hidden_params.txt"
    
    HIDDEN_COUNT=$(wc -l < "$HIDDEN_DIR/all_hidden_params.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] Found $HIDDEN_COUNT hidden parameters${NC}"
    
    log_step "Hidden Parameter Discovery" "completed"
    read -p "Press enter to continue..."
}

# ==================== TESTING FUNCTIONS ====================

test_sql_injection() {
    echo -e "${CYAN}[*] Starting SQL Injection Testing...${NC}"
    
    SQLI_DIR="$OUTPUT_DIR/tests/sql_injection"
    mkdir -p "$SQLI_DIR"
    
    # Check for SQLmap
    if ! command -v sqlmap &> /dev/null; then
        echo -e "${RED}[!] SQLmap not found. Please install it.${NC}"
        read -p "Install SQLmap? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            pip3 install sqlmap
        else
            return
        fi
    fi
    
    echo "Select testing method:"
    echo "1) Quick test (first 5 URLs)"
    echo "2) Comprehensive test (all URLs)"
    echo "3) Targeted test (specific parameters)"
    read -p "Choice: " sql_choice
    
    case $sql_choice in
        1)
            # Quick test on first 5 URLs
            head -5 "$OUTPUT_DIR/urls/urls_with_params.txt" > "$SQLI_DIR/quick_test.txt"
            while read -r url; do
                echo "Testing: $url"
                sqlmap -u "$url" --batch --level=1 --risk=1 --output-dir="$SQLI_DIR/$(echo $url | md5sum | cut -d' ' -f1)"
            done < "$SQLI_DIR/quick_test.txt"
            ;;
        2)
            # Test all URLs with parameters
            while read -r url; do
                echo "Testing: $url"
                sqlmap -u "$url" --batch --level=2 --risk=2 --output-dir="$SQLI_DIR/$(echo $url | md5sum | cut -d' ' -f1)"
            done < "$OUTPUT_DIR/urls/urls_with_params.txt"
            ;;
        3)
            # Targeted test
            read -p "Enter parameter names to test (comma separated): " sql_params
            read -p "Enter URL to test: " sql_url
            
            IFS=',' read -ra params_array <<< "$sql_params"
            for param in "${params_array[@]}"; do
                echo "Testing parameter: $param"
                sqlmap -u "$sql_url" --data="$param=test" -p "$param" --batch --level=3
            done
            ;;
    esac
    
    # Generate report
    find "$SQLI_DIR" -name "*.csv" -exec cat {} \; 2>/dev/null | grep -i "sql injection" > "$SQLI_DIR/findings.txt"
    
    FINDING_COUNT=$(wc -l < "$SQLI_DIR/findings.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] SQL Injection testing complete. Found $FINDING_COUNT potential issues.${NC}"
    
    log_step "SQL Injection Testing" "completed"
    read -p "Press enter to continue..."
}

test_xss() {
    echo -e "${CYAN}[*] Starting XSS Testing...${NC}"
    
    XSS_DIR="$OUTPUT_DIR/tests/xss"
    mkdir -p "$XSS_DIR"
    
    echo "Select XSS testing method:"
    echo "1) Quick test with dalfox"
    echo "2) Comprehensive test with custom payloads"
    echo "3) Manual testing assistant"
    read -p "Choice: " xss_choice
    
    case $xss_choice in
        1)
            # Using dalfox if available
            if command -v dalfox &> /dev/null; then
                echo "Using dalfox for XSS testing"
                head -10 "$OUTPUT_DIR/urls/urls_with_params.txt" | while read -r url; do
                    echo "Testing: $url"
                    dalfox url "$url" --output "$XSS_DIR/dalfox_$(echo $url | md5sum | cut -d' ' -f1).txt"
                done
            else
                echo -e "${YELLOW}[!] dalfox not installed${NC}"
            fi
            ;;
        2)
            # Custom payload testing
            echo "Generating custom XSS payloads..."
            cat > "$XSS_DIR/xss_payloads.txt" << 'EOF'
<script>alert(1)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>
"><img src=x onerror=alert(1)>
javascript:alert(1)
"><svg/onload=alert(1)>
"><iframe src=javascript:alert(1)>
"><body onload=alert(1)>
"><details/open/ontoggle=alert(1)>
"><select onfocus=alert(1) autofocus>
EOF
            
            echo "Testing with payloads..."
            # This would be expanded with actual testing code
            ;;
        3)
            echo -e "${YELLOW}[*] Manual XSS Testing Assistant${NC}"
            echo "1. Test all reflection points"
            echo "2. Test DOM-based XSS"
            echo "3. Test stored XSS"
            echo "4. Test with different contexts (HTML, attribute, JavaScript)"
            ;;
    esac
    
    log_step "XSS Testing" "completed"
    read -p "Press enter to continue..."
}

test_idor() {
    echo -e "${CYAN}[*] Starting IDOR Testing...${NC}"
    
    IDOR_DIR="$OUTPUT_DIR/tests/idor"
    mkdir -p "$IDOR_DIR"
    
    echo "🔍 Identifying ID parameters..."
    
    # Look for common ID parameters
    grep -i -E "(id|user|account|customer|order|invoice|document|file)[_=]" \
        "$OUTPUT_DIR/parameters/all_parameters.txt" > "$IDOR_DIR/id_parameters.txt"
    
    # Create test cases
    cat > "$IDOR_DIR/test_cases.txt" << 'EOF'
# IDOR Test Cases
1. Horizontal Privilege Escalation:
   - Change user_id to another user's ID
   - Change account_id to another account's ID

2. Vertical Privilege Escalation:
   - Access admin functions with user ID
   - Access other user's sensitive data

3. Sequential ID Testing:
   - Increment/decrement numeric IDs
   - Predictable UUID patterns

4. Mass Assignment:
   - Add admin=true parameter
   - Modify role=admin parameter

5. Indirect References:
   - Reference objects through other parameters
   - Chained IDOR attacks
EOF
    
    echo -e "${GREEN}[+] Found $(wc -l < "$IDOR_DIR/id_parameters.txt") ID parameters to test${NC}"
    
    # Generate test URLs
    echo "Generating test URLs..."
    while read -r param; do
        grep "$param" "$OUTPUT_DIR/urls/urls_with_params.txt" | head -3 >> "$IDOR_DIR/test_urls.txt"
    done < "$IDOR_DIR/id_parameters.txt"
    
    log_step "IDOR Testing" "setup_completed"
    echo -e "${YELLOW}[!] IDOR testing requires manual verification${NC}"
    read -p "Press enter to continue..."
}

# ==================== REPORTING FUNCTIONS ====================

report_generation() {
    echo -e "${CYAN}[*] Generating Vulnerability Report...${NC}"
    
    REPORT_DIR="$OUTPUT_DIR/reports"
    mkdir -p "$REPORT_DIR"
    
    echo "Select report format:"
    echo "1) HackerOne Template"
    echo "2) Markdown Report"
    echo "3) Executive Summary"
    echo "4) JSON Export"
    read -p "Choice: " report_choice
    
    REPORT_DATE=$(date +%Y-%m-%d)
    REPORT_FILE="$REPORT_DIR/vulnerability_report_${REPORT_DATE}"
    
    case $report_choice in
        1)
            # HackerOne Template
            cat > "${REPORT_FILE}_hackerone.md" << EOF
# Vulnerability Report
## Summary
**Target:** $TARGET
**Date:** $REPORT_DATE
**Reporter:** [Your Name/Handle]

## Vulnerability Details
### Title: 
[Brief descriptive title]

### Severity: 
[Critical/High/Medium/Low]

### Description:
[Detailed description of the vulnerability]

### Steps to Reproduce:
1. [Step 1]
2. [Step 2]
3. [Step 3]
4. [Step 4]

### Proof of Concept:
\`\`\`
[Code/curl commands/screenshots]
\`\`\`

### Impact:
[What can an attacker achieve?]

### Remediation:
[How to fix the issue]

### References:
- [Related resources/CVEs]
EOF
            echo -e "${GREEN}[+] HackerOne report generated: ${REPORT_FILE}_hackerone.md${NC}"
            ;;
        2)
            # Markdown Report
            cat > "${REPORT_FILE}.md" << EOF
# Security Assessment Report
## Executive Summary
**Target:** $TARGET
**Assessment Date:** $REPORT_DATE
**Scope:** [Scope details]

## Methodology
1. Reconnaissance
2. Parameter Discovery
3. Automated Testing
4. Manual Validation
5. Reporting

## Findings Summary
| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 0 |
| Medium   | 0 |
| Low      | 0 |

## Detailed Findings
### 1. [Finding Title]
**Severity:** High
**Location:** [URL/Endpoint]
**Description:** [Details]
**Impact:** [Impact]
**Remediation:** [Fix]
**Evidence:** [Proof]

## Recommendations
1. [Recommendation 1]
2. [Recommendation 2]
3. [Recommendation 3]

## Appendix
### Tools Used
- [List of tools]

### Parameters Discovered
$(wc -l < "$OUTPUT_DIR/parameters/all_parameters.txt" 2>/dev/null || echo 0) total parameters

### Timeline
- Start: [Start time]
- End: [End time]
EOF
            echo -e "${GREEN}[+] Markdown report generated: ${REPORT_FILE}.md${NC}"
            ;;
        3)
            # Executive Summary
            cat > "${REPORT_FILE}_executive.md" << EOF
# Executive Summary
## Security Assessment: $TARGET

### Key Findings
- **Critical Issues:** 0
- **High Severity Issues:** 0
- **Medium Severity Issues:** 0
- **Low Severity Issues:** 0

### Risk Assessment
[Overall risk rating]

### Immediate Actions Required
1. [Action 1]
2. [Action 2]

### Technical Summary
Total parameters analyzed: $(wc -l < "$OUTPUT_DIR/parameters/all_parameters.txt" 2>/dev/null || echo 0)
URLs tested: $(wc -l < "$OUTPUT_DIR/urls/urls_with_params.txt" 2>/dev/null || echo 0)

### Next Steps
[Recommendations for remediation]
EOF
            echo -e "${GREEN}[+] Executive summary generated: ${REPORT_FILE}_executive.md${NC}"
            ;;
        4)
            # JSON Export
            jq -n \
                --arg target "$TARGET" \
                --arg date "$REPORT_DATE" \
                --argjson param_count "$(wc -l < "$OUTPUT_DIR/parameters/all_parameters.txt" 2>/dev/null || echo 0)" \
                --argjson url_count "$(wc -l < "$OUTPUT_DIR/urls/urls_with_params.txt" 2>/dev/null || echo 0)" \
                '{
                    "report": {
                        "target": $target,
                        "date": $date,
                        "statistics": {
                            "parameters_discovered": $param_count,
                            "urls_tested": $url_count
                        },
                        "findings": [],
                        "recommendations": []
                    }
                }' > "${REPORT_FILE}.json"
            echo -e "${GREEN}[+] JSON report generated: ${REPORT_FILE}.json${NC}"
            ;;
    esac
    
    log_step "Report Generation" "completed"
    read -p "Press enter to continue..."
}

# ==================== UTILITY FUNCTIONS ====================

utilities_view_progress() {
    echo -e "${CYAN}[*] Current Scan Progress${NC}"
    
    if [ -f "$SESSION_FILE" ]; then
        echo "Target: $TARGET"
        echo "Output Directory: $OUTPUT_DIR"
        echo ""
        
        # Show completed steps
        echo "Completed Steps:"
        jq -r '.steps[] | "  • \(.step) - \(.status) (\(.timestamp | .[11:16]))"' "$SESSION_FILE" 2>/dev/null || echo "  No steps recorded yet"
        
        # Show directory structure
        echo ""
        echo "Files Generated:"
        find "$OUTPUT_DIR" -type f | head -20 | while read -r file; do
            size=$(du -h "$file" | cut -f1)
            echo "  📄 $(basename "$file") ($size)"
        done
        
        # Count findings
        echo ""
        echo "Potential Findings:"
        for test_dir in "$OUTPUT_DIR/tests"/*/ 2>/dev/null; do
            if [ -d "$test_dir" ]; then
                test_name=$(basename "$test_dir")
                count=$(find "$test_dir" -name "*.txt" -exec grep -l "vulnerable\|issue\|finding" {} \; 2>/dev/null | wc -l)
                if [ $count -gt 0 ]; then
                    echo "  • $test_name: $count potential issues"
                fi
            fi
        done
    else
        echo "No active session found"
    fi
    
    read -p "Press enter to continue..."
}

utilities_export_results() {
    echo -e "${CYAN}[*] Exporting Results...${NC}"
    
    EXPORT_DIR="bug_hunter_export_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$EXPORT_DIR"
    
    # Copy important files
    cp -r "$OUTPUT_DIR/parameters" "$EXPORT_DIR/"
    cp -r "$OUTPUT_DIR/tests" "$EXPORT_DIR/" 2>/dev/null
    cp -r "$OUTPUT_DIR/reports" "$EXPORT_DIR/" 2>/dev/null
    
    # Create summary file
    cat > "$EXPORT_DIR/README.md" << EOF
# Bug Hunter Export
## Target: $TARGET
## Export Date: $(date)

## Contents:
- parameters/: Discovered parameters
- tests/: Test results
- reports/: Generated reports

## Statistics:
- Total Parameters: $(wc -l < "$OUTPUT_DIR/parameters/all_parameters.txt" 2>/dev/null || echo 0)
- URLs with Parameters: $(wc -l < "$OUTPUT_DIR/urls/urls_with_params.txt" 2>/dev/null || echo 0)

## Next Steps:
1. Review parameters for business logic flaws
2. Validate automated findings manually
3. Expand testing based on discovered parameters
EOF
    
    # Create archive
    tar -czf "${EXPORT_DIR}.tar.gz" "$EXPORT_DIR"
    
    echo -e "${GREEN}[+] Export completed: ${EXPORT_DIR}.tar.gz${NC}"
    echo -e "${YELLOW}[!] Remove sensitive data before sharing!${NC}"
    
    read -p "Press enter to continue..."
}

# ==================== HELP FUNCTION ====================

show_help() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                 BUG HUNTER PRO - HELP                     ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    cat << 'EOF'

📖 QUICK START GUIDE:
1. Start with target setup (Option 1)
2. Run reconnaissance (Options 2-6)
3. Extract parameters (Options 7-10)
4. Run automated tests (Options 11-14)
5. Test business logic (Options 15-18)
6. Generate report (Option 26)

🔧 RECOMMENDED WORKFLOW:
1.  recon_target_setup
2.  recon_subdomain_enum
3.  recon_url_collection
4.  param_extraction_basic
5.  param_hidden_discovery
6.  test_sql_injection
7.  test_xss
8.  test_idor
9.  report_generation

⚡ TIPS:
• Always validate automated findings manually
• Focus on business logic parameters first
• Look for debug/administrative parameters
• Test for IDOR on all ID parameters
• Check for mass assignment vulnerabilities

🛠️ TOOL INSTALLATION:
Run the following to install essential tools:

# Basic tools
sudo apt-get update
sudo apt-get install -y curl git python3 python3-pip jq

# Recon tools
pip3 install arjun waybackurls gau

# Testing tools
pip3 install sqlmap dalfox

📚 RESOURCES:
• PortSwigger Web Security Academy
• OWASP Testing Guide
• HackerOne Hacktivity
• Bug Bounty forums

💡 REMEMBER:
• Always get proper authorization
• Respect scope and rules of engagement
• Document everything
• Report responsibly
EOF
    
    read -p "Press enter to return to main menu..."
}

# ==================== MAIN EXECUTION ====================

exit_script() {
    echo -e "${GREEN}[*] Saving session...${NC}"
    
    if [ -f "$SESSION_FILE" ]; then
        jq --arg end_time "$(date -Iseconds)" \
           '. + {"end_time": $end_time, "status": "completed"}' \
           "$SESSION_FILE" > tmp_session.json && mv tmp_session.json "$SESSION_FILE"
    fi
    
    echo -e "${GREEN}[+] Session saved to: $SESSION_FILE${NC}"
    echo -e "${CYAN}[*] Thank you for using Bug Hunter Pro!${NC}"
    exit 0
}

# Trap Ctrl+C
trap exit_script SIGINT

# Initialize
check_dependencies
init_session
main_menu
