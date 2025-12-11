#!/bin/bash

# ============================================
# DEEP BUG HUNTER - AI POWERED SCANNER
# Versi: 3.0 (AI Bug Analysis)
# ============================================

# Konfigurasi Path
NUCLEI_PATH="$HOME/go/bin/nuclei"
TEMPLATES_PATH="/home/userland/nuclei-templates"
OUTPUT_DIR="$HOME/nuclei-scans"
LOG_DIR="$HOME/nuclei-logs"
AI_ANALYSIS_DIR="$HOME/nuclei-ai-analysis"

# AI Configuration
USE_OPENAI=false
OPENAI_API_KEY=""
OPENAI_MODEL="gpt-3.5-turbo"
USE_LOCAL_AI=true
LOCAL_AI_MODEL="llama3.2:3b"  # Untuk Ollama
CRITICAL_SCORE_THRESHOLD=8.0

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
clear
echo -e "${CYAN}"
cat << "EOF"
╔══════════════════════════════════════════╗
║   DEEP BUG HUNTER - AI POWERED SCANNER   ║
║   Version: 3.0 (AI Bug Analysis)         ║
║   Author: AI Security Researcher         ║
╚══════════════════════════════════════════╝
EOF
echo -e "${NC}"

# ============================================
# AI ANALYSIS FUNCTIONS
# ============================================

# Fungsi untuk analisis bug dengan AI
ai_analyze_bugs() {
    local scan_file="$1"
    local target="$2"
    
    echo -e "${PURPLE}[AI] Menganalisis hasil scan dengan AI...${NC}"
    
    if [ ! -f "$scan_file" ] || [ ! -s "$scan_file" ]; then
        echo -e "${YELLOW}[AI] Tidak ada findings untuk dianalisis${NC}"
        return
    fi
    
    # Buat prompt untuk AI
    local ai_prompt=$(create_ai_prompt "$scan_file" "$target")
    local analysis_file="${AI_ANALYSIS_DIR}/ai_analysis_$(date +%Y%m%d_%H%M%S).txt"
    
    echo -e "${CYAN}[AI] Menganalisis $(wc -l < "$scan_file") findings...${NC}"
    
    if [ "$USE_LOCAL_AI" = true ] && command -v ollama &> /dev/null; then
        # Gunakan Ollama (local AI)
        ai_local_analysis "$ai_prompt" "$analysis_file"
    elif [ "$USE_OPENAI" = true ] && [ -n "$OPENAI_API_KEY" ]; then
        # Gunakan OpenAI API
        ai_openai_analysis "$ai_prompt" "$analysis_file"
    else
        # Gunakan rule-based analysis
        ai_rule_based_analysis "$scan_file" "$analysis_file"
    fi
    
    if [ -f "$analysis_file" ] && [ -s "$analysis_file" ]; then
        echo -e "${GREEN}[AI] Analisis selesai!${NC}"
        display_ai_analysis "$analysis_file"
    fi
}

# Buat prompt untuk AI
create_ai_prompt() {
    local scan_file="$1"
    local target="$2"
    
    local scan_content
    if [[ "$scan_file" == *.json ]]; then
        scan_content=$(jq -c '.[] | {template, severity, host, matched_at, description}' "$scan_file" 2>/dev/null | head -20)
    else
        scan_content=$(head -20 "$scan_file")
    fi
    
    cat << EOF
ANALYZE THESE SECURITY FINDINGS AND IDENTIFY REAL BUGS:

TARGET: $target
SCAN RESULTS:
$scan_content

INSTRUCTIONS:
1. Classify each finding as: CRITICAL_BUG, HIGH_RISK, MEDIUM_RISK, LOW_RISK, or FALSE_POSITIVE
2. For each CRITICAL/HIGH bug, explain:
   - Why it's a real bug
   - Potential impact
   - Exploitation method
   - CVSS score estimate (1-10)
   - Remediation steps
3. Focus on:
   - Remote Code Execution (RCE)
   - SQL Injection
   - Authentication Bypass
   - Information Disclosure
   - Business Logic Flaws
4. Filter out false positives and informational findings

OUTPUT FORMAT:
## CRITICAL BUGS (CVSS 9.0-10.0)
1. [Finding Name] - CVSS: X.X
   - Impact: 
   - Exploit: 
   - Fix: 

## HIGH RISK BUGS (CVSS 7.0-8.9)
...

## FALSE POSITIVES
- [Reason for false positive]

## RECOMMENDATIONS
1. Immediate fixes
2. Security improvements
EOF
}

# Analisis dengan AI lokal (Ollama)
ai_local_analysis() {
    local prompt="$1"
    local output_file="$2"
    
    echo -e "${BLUE}[AI] Menggunakan model lokal: $LOCAL_AI_MODEL${NC}"
    
    ollama run "$LOCAL_AI_MODEL" "$prompt" > "$output_file" 2>/dev/null
    
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}[AI] Ollama tidak tersedia, menggunakan rule-based${NC}"
        return 1
    fi
}

# Analisis dengan OpenAI
ai_openai_analysis() {
    local prompt="$1"
    local output_file="$2"
    
    echo -e "${BLUE}[AI] Menggunakan OpenAI API${NC}"
    
    curl -s https://api.openai.com/v1/chat/completions \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -d "{
            \"model\": \"$OPENAI_MODEL\",
            \"messages\": [{\"role\": \"user\", \"content\": \"$prompt\"}],
            \"temperature\": 0.3,
            \"max_tokens\": 2000
        }" | jq -r '.choices[0].message.content' > "$output_file"
}

# Rule-based analysis (fallback)
ai_rule_based_analysis() {
    local scan_file="$1"
    local analysis_file="$2"
    
    echo -e "${YELLOW}[AI] Menggunakan rule-based analysis${NC}"
    
    # Critical keywords
    local critical_patterns=("rce" "remote.*code.*execution" "sql.*injection" "auth.*bypass" "privilege.*escalation" "file.*upload" "command.*injection")
    local high_patterns=("xss" "cross.*site.*scripting" "idor" "insecure.*direct.*object.*reference" "ssrf" "xxe")
    local medium_patterns=("csrf" "clickjacking" "open.*redirect" "cors" "information.*disclosure")
    
    local findings=""
    
    # Analyze each line
    while IFS= read -r line; do
        local bug_level="LOW"
        local score=3.0
        
        # Check for critical patterns
        for pattern in "${critical_patterns[@]}"; do
            if [[ "$line" =~ $pattern ]]; then
                bug_level="CRITICAL"
                score=9.5
                break
            fi
        done
        
        # Check for high patterns
        if [ "$bug_level" = "LOW" ]; then
            for pattern in "${high_patterns[@]}"; do
                if [[ "$line" =~ $pattern ]]; then
                    bug_level="HIGH"
                    score=7.5
                    break
                fi
            done
        fi
        
        # Check for medium patterns
        if [ "$bug_level" = "LOW" ]; then
            for pattern in "${medium_patterns[@]}"; do
                if [[ "$line" =~ $pattern ]]; then
                    bug_level="MEDIUM"
                    score=5.0
                    break
                fi
            done
        fi
        
        # Check CVEs
        if [[ "$line" =~ CVE-[0-9]{4}-[0-9]+ ]]; then
            bug_level="CRITICAL"
            score=9.0
        fi
        
        if [ "$bug_level" != "LOW" ]; then
            findings+="[$bug_level - CVSS: $score] $line\n"
        fi
    done < "$scan_file"
    
    # Write analysis
    cat > "$analysis_file" << EOF
## AI SECURITY ANALYSIS (RULE-BASED)
Target: $(basename "$scan_file")
Analysis Date: $(date)

## FINDINGS CLASSIFICATION
$(if [ -n "$findings" ]; then echo -e "$findings"; else echo "No critical/high bugs found"; fi)

## RECOMMENDATIONS
1. Prioritize fixes based on CVSS scores
2. Validate all critical findings manually
3. Implement WAF rules for detected vulnerabilities
4. Schedule regular security assessments

## FALSE POSITIVE CHECK
- Information-only findings marked as LOW
- Technology detection not considered bugs
- Missing headers considered LOW unless critical context
EOF
}

# Tampilkan hasil analisis AI
display_ai_analysis() {
    local analysis_file="$1"
    
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════╗"
    echo "║          AI BUG ANALYSIS REPORT          ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Highlight critical sections
    while IFS= read -r line; do
        if [[ "$line" =~ CRITICAL.*BUG|CVSS.*9|CVSS.*10 ]]; then
            echo -e "${RED}$line${NC}"
        elif [[ "$line" =~ HIGH.*RISK|CVSS.*7|CVSS.*8 ]]; then
            echo -e "${YELLOW}$line${NC}"
        elif [[ "$line" =~ MEDIUM.*RISK|CVSS.*4|CVSS.*6 ]]; then
            echo -e "${BLUE}$line${NC}"
        elif [[ "$line" =~ RECOMMENDATION|FIX|IMPACT ]]; then
            echo -e "${GREEN}$line${NC}"
        else
            echo "$line"
        fi
    done < "$analysis_file"
    
    echo ""
    echo -e "${CYAN}[AI] Full report: $analysis_file${NC}"
}

# ============================================
# ENHANCED SCANNING WITH AI
# ============================================

# Smart Quick Scan with AI Analysis
smart_quick_scan() {
    echo -e "${YELLOW}[*] Masukkan target:${NC}"
    read -r target
    
    if [ -z "$target" ]; then
        echo -e "${RED}[!] Target tidak boleh kosong${NC}"
        return
    fi
    
    if [[ ! "$target" =~ ^https?:// ]]; then
        target="http://$target"
        echo -e "${YELLOW}[*] Added http://${NC}"
    fi
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$OUTPUT_DIR/smart_scan_$timestamp.txt"
    
    echo -e "${BLUE}[*] Smart scanning $target...${NC}"
    
    # Phase 1: Technology detection
    echo -e "${CYAN}[1/3] Detecting technologies...${NC}"
    "$NUCLEI_PATH" -u "$target" \
        -t "$TEMPLATES_PATH/http/technologies" \
        -silent -nc -o "${output_file}.tech"
    
    # Phase 2: Critical vulnerabilities
    echo -e "${CYAN}[2/3] Scanning for critical bugs...${NC}"
    "$NUCLEI_PATH" -u "$target" \
        -t "$TEMPLATES_PATH/http/cves" \
        -t "$TEMPLATES_PATH/http/vulnerabilities" \
        -severity critical,high \
        -rate-limit 30 \
        -stats -si 5 -nc -o "${output_file}.vuln"
    
    # Phase 3: Common misconfigurations
    echo -e "${CYAN}[3/3] Checking misconfigurations...${NC}"
    "$NUCLEI_PATH" -u "$target" \
        -t "$TEMPLATES_PATH/http/misconfiguration" \
        -t "$TEMPLATES_PATH/http/exposed-panels" \
        -severity medium,low \
        -rate-limit 50 \
        -stats -si 5 -nc -o "${output_file}.config"
    
    # Combine results
    cat "${output_file}.tech" "${output_file}.vuln" "${output_file}.config" > "$output_file" 2>/dev/null
    rm -f "${output_file}.tech" "${output_file}.vuln" "${output_file}.config"
    
    echo -e "${GREEN}[✓] Scan completed${NC}"
    
    # AI Analysis
    ai_analyze_bugs "$output_file" "$target"
}

# Targeted Bug Hunting
targeted_bug_hunt() {
    echo -e "${YELLOW}[*] Pilih bug type:${NC}"
    echo "1. Injection Attacks (SQLi, RCE, etc)"
    echo "2. Authentication Bypass"
    echo "3. Information Disclosure"
    echo "4. Business Logic Flaws"
    echo "5. API Security"
    echo "6. Custom Pattern"
    
    read -r bug_type
    
    echo -e "${YELLOW}[*] Target:${NC}"
    read -r target
    
    if [[ ! "$target" =~ ^https?:// ]]; then
        target="http://$target"
    fi
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$OUTPUT_DIR/targeted_hunt_$timestamp.txt"
    
    case $bug_type in
        1)
            echo -e "${RED}[*] Hunting injection bugs...${NC}"
            "$NUCLEI_PATH" -u "$target" \
                -t "$TEMPLATES_PATH/http/vulnerabilities" \
                -tags "sqli,rce,injection" \
                -severity critical,high \
                -rate-limit 20 \
                -stats -nc -o "$output_file"
            ;;
        2)
            echo -e "${RED}[*] Hunting auth bypass...${NC}"
            "$NUCLEI_PATH" -u "$target" \
                -t "$TEMPLATES_PATH/http/vulnerabilities" \
                -tags "auth,bypass,jwt" \
                -severity critical,high \
                -rate-limit 20 \
                -stats -nc -o "$output_file"
            ;;
        3)
            echo -e "${BLUE}[*] Hunting info disclosure...${NC}"
            "$NUCLEI_PATH" -u "$target" \
                -t "$TEMPLATES_PATH/http/misconfiguration" \
                -tags "information,disclosure,debug" \
                -severity medium,high \
                -rate-limit 30 \
                -stats -nc -o "$output_file"
            ;;
        4)
            echo -e "${PURPLE}[*] Hunting logic flaws...${NC}"
            "$NUCLEI_PATH" -u "$target" \
                -t "$TEMPLATES_PATH/http/vulnerabilities" \
                -tags "logic,idor,business" \
                -severity high,medium \
                -rate-limit 25 \
                -stats -nc -o "$output_file"
            ;;
        5)
            echo -e "${CYAN}[*] Hunting API bugs...${NC}"
            "$NUCLEI_PATH" -u "$target" \
                -t "$TEMPLATES_PATH/http/vulnerabilities" \
                -tags "api,graphql,rest" \
                -severity critical,high,medium \
                -rate-limit 20 \
                -stats -nc -o "$output_file"
            ;;
        6)
            echo -e "${YELLOW}[*] Masukkan custom tags (comma separated):${NC}"
            read -r custom_tags
            "$NUCLEI_PATH" -u "$target" \
                -t "$TEMPLATES_PATH/http/vulnerabilities" \
                -tags "$custom_tags" \
                -severity critical,high,medium \
                -rate-limit 20 \
                -stats -nc -o "$output_file"
            ;;
        *)
            echo -e "${RED}[!] Invalid choice${NC}"
            return
            ;;
    esac
    
    # AI Analysis
    ai_analyze_bugs "$output_file" "$target"
}

# Zero-Day Hunting Mode
zero_day_hunt() {
    echo -e "${RED}[⚠] ZERO-DAY HUNTING MODE${NC}"
    echo -e "${YELLOW}[!] This mode uses aggressive scanning${NC}"
    
    echo -e "${YELLOW}[*] Target:${NC}"
    read -r target
    
    if [[ ! "$target" =~ ^https?:// ]]; then
        target="http://$target"
    fi
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$OUTPUT_DIR/zeroday_hunt_$timestamp.json"
    
    # Aggressive scanning
    echo -e "${RED}[*] Starting aggressive scan...${NC}"
    
    "$NUCLEI_PATH" -u "$target" \
        -t "$TEMPLATES_PATH" \
        -severity critical,high,medium \
        -rate-limit 10 \
        -concurrency 3 \
        -timeout 30 \
        -retries 2 \
        -headless \
        -interactions \
        -stats \
        -si 3 \
        -j \
        -o "$output_file"
    
    echo -e "${GREEN}[✓] Aggressive scan completed${NC}"
    
    # Deep AI Analysis
    echo -e "${PURPLE}[AI] Deep analysis for zero-day potential...${NC}"
    ai_zero_day_analysis "$output_file" "$target"
}

# Special AI analysis for zero-day hunting
ai_zero_day_analysis() {
    local scan_file="$1"
    local target="$2"
    
    local analysis_file="${AI_ANALYSIS_DIR}/zeroday_analysis_$(date +%Y%m%d_%H%M%S).txt"
    
    # Create special zero-day hunting prompt
    local prompt=$(cat << EOF
ZERO-DAY VULNERABILITY HUNTING ANALYSIS

TARGET: $target
SCAN RESULTS (first 30 findings):
$(jq -c '.[] | {template, severity, description, matched_at}' "$scan_file" 2>/dev/null | head -30)

LOOK FOR:
1. UNUSUAL PATTERNS that could indicate zero-day
2. CUSTOM/BUSINESS LOGIC flaws
3. CHAINING possibilities between vulnerabilities
4. NEW attack vectors
5. Configuration combinations that create new risks

ANALYZE FOR:
- Potential for exploit chain (multiple low → critical)
- Uncommon parameter combinations
- API endpoint unusual behaviors
- Authentication flow abnormalities
- Data processing edge cases

RATE ZERO-DAY POTENTIAL (0-10) for each finding with:
- Novelty score (how new is this pattern)
- Impact score (potential damage)
- Exploitability score (ease of exploitation)
- Wormable potential (can it spread)

OUTPUT:
## ZERO-DAY CANDIDATES
1. [Finding] - Overall Score: X/10
   - Novelty: X/10
   - Impact: X/10  
   - Exploitability: X/10
   - Wormable: Yes/No
   - Evidence: 
   - Exploitation Path:

## EXPLOIT CHAINS
- Chain 1: [Vuln A] + [Vuln B] → [Critical Impact]

## PRIORITY ACTIONS
1. Immediate investigation needed
2. Proof-of-concept development
3. Vendor notification
EOF
)
    
    if [ "$USE_LOCAL_AI" = true ] && command -v ollama &> /dev/null; then
        ollama run "$LOCAL_AI_MODEL" "$prompt" > "$analysis_file"
    else
        ai_rule_based_analysis "$scan_file" "$analysis_file"
        echo -e "\n## ZERO-DAY ASSESSMENT (RULE-BASED)" >> "$analysis_file"
        echo "- Check for recent CVE patterns (last 90 days)" >> "$analysis_file"
        echo "- Look for template signatures with low usage counts" >> "$analysis_file"
        echo "- Analyze parameter variations in findings" >> "$analysis_file"
    fi
    
    display_ai_analysis "$analysis_file"
}

# ============================================
# MAIN MENU WITH AI FEATURES
# ============================================

main_menu() {
    while true; do
        echo ""
        echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║         AI-POWERED BUG HUNTER            ║${NC}"
        echo -e "${CYAN}╠══════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║  1. Smart Quick Scan (with AI Analysis)  ║${NC}"
        echo -e "${CYAN}║  2. Targeted Bug Hunting                 ║${NC}"
        echo -e "${CYAN}║  3. Zero-Day Hunting Mode                ║${NC}"
        echo -e "${CYAN}║  4. Deep Scan + AI Report                ║${NC}"
        echo -e "${CYAN}║  5. Analyze Previous Scan (AI)           ║${NC}"
        echo -e "${CYAN}║  6. Configure AI Settings                ║${NC}"
        echo -e "${CYAN}║  7. Test AI Integration                  ║${NC}"
        echo -e "${CYAN}║  8. Exit                                 ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
        echo -e "${YELLOW}[?] Pilih (1-8):${NC}"
        
        read -r choice
        
        case $choice in
            1) smart_quick_scan ;;
            2) targeted_bug_hunt ;;
            3) zero_day_hunt ;;
            4) deep_scan_ai ;;
            5) analyze_previous_scan ;;
            6) configure_ai ;;
            7) test_ai_integration ;;
            8) 
                echo -e "${GREEN}[✓] Exit${NC}"
                exit 0
                ;;
            *) echo -e "${RED}[!] Invalid${NC}" ;;
        esac
        
        echo ""
        echo -e "${YELLOW}Press Enter to continue...${NC}"
        read -r
        clear
        echo -e "${CYAN}"
        cat << "EOF"
╔══════════════════════════════════════════╗
║   DEEP BUG HUNTER - AI POWERED SCANNER   ║
║   Version: 3.0 (AI Bug Analysis)         ║
║   Author: AI Security Researcher         ║
╚══════════════════════════════════════════╝
EOF
        echo -e "${NC}"
    done
}

# ============================================
# SUPPORTING FUNCTIONS
# ============================================

deep_scan_ai() {
    echo -e "${YELLOW}[*] Target:${NC}"
    read -r target
    
    if [[ ! "$target" =~ ^https?:// ]]; then
        target="http://$target"
    fi
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$OUTPUT_DIR/deep_ai_scan_$timestamp.json"
    
    echo -e "${BLUE}[*] Deep scanning with AI reporting...${NC}"
    
    "$NUCLEI_PATH" -u "$target" \
        -t "$TEMPLATES_PATH" \
        -severity critical,high,medium,low \
        -rate-limit 30 \
        -concurrency 5 \
        -timeout 20 \
        -stats \
        -si 10 \
        -j \
        -o "$output_file"
    
    ai_analyze_bugs "$output_file" "$target"
}

analyze_previous_scan() {
    echo -e "${YELLOW}[*] Pilih scan file:${NC}"
    
    files=()
    i=1
    for file in "$OUTPUT_DIR"/*.txt "$OUTPUT_DIR"/*.json; do
        if [ -f "$file" ]; then
            files[i]="$file"
            echo "$i. $(basename "$file")"
            ((i++))
        fi
    done
    
    if [ ${#files[@]} -eq 0 ]; then
        echo -e "${RED}[!] No previous scans${NC}"
        return
    fi
    
    echo -e "${YELLOW}[?] Pilih file (1-$((i-1))):${NC}"
    read -r choice
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -lt $i ]; then
        selected_file="${files[choice]}"
        echo -e "${YELLOW}[*] Target URL:${NC}"
        read -r target
        ai_analyze_bugs "$selected_file" "$target"
    else
        echo -e "${RED}[!] Invalid choice${NC}"
    fi
}

configure_ai() {
    echo -e "${CYAN}=== AI CONFIGURATION ===${NC}"
    echo "1. Enable OpenAI API"
    echo "2. Enable Local AI (Ollama)"
    echo "3. Set Critical Score Threshold"
    echo "4. Test AI Connection"
    echo "5. Back"
    
    read -r choice
    
    case $choice in
        1)
            echo -e "${YELLOW}[*] OpenAI API Key:${NC}"
            read -r OPENAI_API_KEY
            USE_OPENAI=true
            echo -e "${GREEN}[✓] OpenAI enabled${NC}"
            ;;
        2)
            if command -v ollama &> /dev/null; then
                USE_LOCAL_AI=true
                echo -e "${GREEN}[✓] Local AI enabled${NC}"
                echo -e "${YELLOW}[*] Available models:${NC}"
                ollama list
                echo -e "${YELLOW}[*] Model to use:${NC}"
                read -r LOCAL_AI_MODEL
            else
                echo -e "${RED}[!] Ollama not installed${NC}"
                echo "Install: curl -fsSL https://ollama.com/install.sh | sh"
            fi
            ;;
        3)
            echo -e "${YELLOW}[*] Critical threshold (1-10):${NC}"
            read -r CRITICAL_SCORE_THRESHOLD
            echo -e "${GREEN}[✓] Threshold set to $CRITICAL_SCORE_THRESHOLD${NC}"
            ;;
        4)
            test_ai_integration
            ;;
        5) return ;;
        *) echo -e "${RED}[!] Invalid${NC}" ;;
    esac
}

test_ai_integration() {
    echo -e "${CYAN}=== AI INTEGRATION TEST ===${NC}"
    
    # Test local AI
    if [ "$USE_LOCAL_AI" = true ] && command -v ollama &> /dev/null; then
        echo -e "${BLUE}[*] Testing Ollama...${NC}"
        if ollama run llama3.2:3b "Hello" &> /dev/null; then
            echo -e "${GREEN}[✓] Ollama working${NC}"
        else
            echo -e "${RED}[!] Ollama error${NC}"
        fi
    fi
    
    # Test rule-based AI
    echo -e "${BLUE}[*] Testing rule-based analysis...${NC}"
    test_data="/tmp/test_ai_data.txt"
    echo "[CVE-2024-12345] SQL Injection found" > "$test_data"
    echo "[info] Nginx detected" >> "$test_data"
    
    ai_rule_based_analysis "$test_data" "/tmp/test_output.txt"
    
    if [ -s "/tmp/test_output.txt" ]; then
        echo -e "${GREEN}[✓] Rule-based AI working${NC}"
        echo "Sample analysis:"
        head -5 "/tmp/test_output.txt"
    fi
    
    rm -f "$test_data" "/tmp/test_output.txt"
}

# ============================================
# SETUP
# ============================================

setup() {
    echo -e "${YELLOW}[*] Setting up AI Bug Hunter...${NC}"
    
    mkdir -p "$OUTPUT_DIR" "$LOG_DIR" "$AI_ANALYSIS_DIR"
    
    # Check Nuclei
    if [ ! -f "$NUCLEI_PATH" ]; then
        echo -e "${RED}[!] Nuclei not found${NC}"
        exit 1
    fi
    
    # Check templates
    if [ ! -d "$TEMPLATES_PATH" ]; then
        echo -e "${YELLOW}[!] Cloning templates...${NC}"
        git clone https://github.com/projectdiscovery/nuclei-templates.git "$TEMPLATES_PATH"
    fi
    
    # Check Ollama for local AI
    if command -v ollama &> /dev/null; then
        echo -e "${GREEN}[✓] Ollama detected${NC}"
        USE_LOCAL_AI=true
    else
        echo -e "${YELLOW}[!] Ollama not installed (optional)${NC}"
        echo "For local AI: curl -fsSL https://ollama.com/install.sh | sh"
    fi
    
    template_count=$(find "$TEMPLATES_PATH" -name "*.yaml" | wc -l)
    echo -e "${GREEN}[✓] Ready with $template_count templates${NC}"
    echo -e "${GREEN}[✓] AI Analysis: $(if [ "$USE_LOCAL_AI" = true ]; then echo "Local"; else echo "Rule-based"; fi)${NC}"
}

# ============================================
# MAIN
# ============================================

main() {
    setup
    echo ""
    echo -e "${PURPLE}[AI] Bug analysis engine initialized${NC}"
    echo -e "${YELLOW}[*] AI will classify and prioritize real bugs${NC}"
    echo ""
    main_menu
}

trap 'echo -e "\n${RED}Interrupted${NC}"; exit' INT
main
