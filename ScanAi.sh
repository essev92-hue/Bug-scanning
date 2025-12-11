#!/bin/bash

# ============================================
# DEEP BUG HUNTER - AI AGGRESSIVE MODE v4.0
# Version: 4.0 (AI-Powered Real-Time Detection)
# ============================================

# Konfigurasi Path
NUCLEI_PATH="$HOME/go/bin/nuclei"
TEMPLATES_PATH="/home/userland/nuclei-templates"
CUSTOM_TEMPLATES="$HOME/custom-templates"
OUTPUT_DIR="$HOME/nuclei-scans/$(date +%Y%m)"
LOG_DIR="$HOME/.nuclei-logs"
WORDLISTS_DIR="$HOME/wordlists"
AI_MODEL_DIR="$HOME/.ai-models"

# AI Configuration
AI_ENABLED=true
AI_CONFIDENCE_THRESHOLD=0.85
REAL_TIME_ALERTS=true
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
DISCORD_WEBHOOK=""
SLACK_WEBHOOK=""

# Proxy untuk rotasi
PROXY_LIST=(
    ""
)

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
ORANGE='\033[0;33m'
NC='\033[0m'

# User-Agent rotasi
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    "curl/7.68.0"
    "Googlebot/2.1 (+http://www.google.com/bot.html)"
)

# Banner
clear
echo -e "${CYAN}"
cat << "EOF"
╔══════════════════════════════════════════════════╗
║   DEEP BUG HUNTER - AI MODE v4.0                 ║
║   AI-Powered Real-Time Vulnerability Detection   ║
║   ⚠️  FOR AUTHORIZED TESTING ONLY               ║
╚══════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# ============================================
# FUNGSI UTILITAS
# ============================================

# Random delay untuk menghindari deteksi
random_delay() {
    local min=${1:-1}
    local max=${2:-5}
    local delay=$((RANDOM % (max - min + 1) + min))
    sleep $delay
}

# Rotasi User-Agent
get_random_ua() {
    local idx=$((RANDOM % ${#USER_AGENTS[@]}))
    echo "${USER_AGENTS[$idx]}"
}

# Rotasi Proxy
get_random_proxy() {
    if [ ${#PROXY_LIST[@]} -gt 0 ]; then
        local idx=$((RANDOM % ${#PROXY_LIST[@]}))
        echo "${PROXY_LIST[$idx]}"
    else
        echo ""
    fi
}

# Validasi target dalam scope
validate_target() {
    local target=$1
    
    # Whitelist domain/ip (sesuaikan)
    local whitelist=(
        "example.com"
        "test.local"
        "192.168.*"
        "10.0.*"
    )
    
    for allowed in "${whitelist[@]}"; do
        if [[ "$target" == *"$allowed"* ]] || [[ "$allowed" == *"*" && "$target" =~ ^${allowed//\*/.*} ]]; then
            echo -e "${GREEN}[✓] Target dalam scope${NC}"
            return 0
        fi
    done
    
    echo -e "${RED}[✗] Target diluar scope!${NC}"
    echo -e "${YELLOW}Lanjutkan? (y/N):${NC}"
    read -r confirm
    [[ "$confirm" =~ ^[Yy]$ ]] && return 0 || return 1
}

# ============================================
# AI MODULE - SIMPLIFIED VERSION
# ============================================

# Initialize AI Models
init_ai_models() {
    echo -e "${CYAN}[*] Initializing AI Models...${NC}"
    
    mkdir -p "$AI_MODEL_DIR"
    
    # Check if required Python packages are installed
    if ! command -v python3 &> /dev/null; then
        echo -e "${YELLOW}[!] Python3 not found. Using simple heuristic AI.${NC}"
        AI_ENABLED=true  # Masih pakai simple AI
        return
    fi
    
    # Check for basic Python libraries
    if python3 -c "import json, re" 2>/dev/null; then
        echo -e "${GREEN}[✓] AI libraries available${NC}"
    else
        echo -e "${YELLOW}[!] Python libraries available${NC}"
    fi
    
    echo -e "${GREEN}[✓] AI System Ready${NC}"
}

# Simple AI Analysis (tanpa machine learning kompleks)
ai_analyze_finding() {
    local finding="$1"
    
    # Convert to lowercase untuk case-insensitive matching
    local finding_lower=$(echo "$finding" | tr '[:upper:]' '[:lower:]')
    
    # Heuristic analysis
    local score=0
    local max_score=10
    
    # Check for SQL Injection patterns
    if [[ $finding_lower =~ (union.*select|select.*from|insert.*into|update.*set|delete.*from) ]]; then
        score=$((score + 3))
    fi
    
    if [[ $finding_lower =~ (sql.*error|mysql.*error|syntax.*error|database.*error) ]]; then
        score=$((score + 2))
    fi
    
    if [[ $finding_lower =~ (\'or\'\'=\'|\'or1=1|\'or\'1\'=\'1) ]]; then
        score=$((score + 3))
    fi
    
    # Check for XSS patterns
    if [[ $finding_lower =~ (<script>|alert\(|onclick=|onload=|onerror=) ]]; then
        score=$((score + 3))
    fi
    
    if [[ $finding_lower =~ (javascript:|vbscript:|data:text/html) ]]; then
        score=$((score + 2))
    fi
    
    # Check for Command Injection
    if [[ $finding_lower =~ (\;\&|\&\&|\|\||\`.*\`|\$\(.*\)) ]]; then
        score=$((score + 3))
    fi
    
    if [[ $finding_lower =~ (bin/bash|bin/sh|cmd.exe|powershell) ]]; then
        score=$((score + 2))
    fi
    
    # Check for Path Traversal
    if [[ $finding_lower =~ (\.\./|\.\.\\|etc/passwd|etc/shadow|windows/win.ini) ]]; then
        score=$((score + 3))
    fi
    
    # Check for SSRF
    if [[ $finding_lower =~ (127.0.0.1|localhost|169.254.169.254|metadata.google.internal) ]]; then
        score=$((score + 2))
    fi
    
    # Check for LFI/RFI
    if [[ $finding_lower =~ (include.*php|require.*php|file=.*php|page=.*php) ]]; then
        score=$((score + 2))
    fi
    
    # Calculate confidence percentage
    local confidence=$((score * 10))
    
    # Debug output
    if [ "${DEBUG:-false}" = "true" ]; then
        echo -e "${BLUE}[AI Debug] Score: $score/$max_score, Confidence: $confidence%${NC}"
    fi
    
    # Return result based on threshold
    if [ $confidence -ge $((AI_CONFIDENCE_THRESHOLD * 100)) ]; then
        echo "true:$confidence"
    else
        echo "false:$confidence"
    fi
}

# Real-Time Alert System
send_real_time_alert() {
    local severity="$1"
    local template="$2"
    local url="$3"
    local confidence="$4"
    
    if [ "$REAL_TIME_ALERTS" = false ]; then
        return
    fi
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local message="🚨 *VULNERABILITY DETECTED* 🚨

📅 *Time:* $timestamp
⚠️ *Severity:* $severity
🔍 *Type:* $template
🌐 *URL:* $url
🎯 *AI Confidence:* ${confidence}%
📊 *Status:* Requires Verification"

    echo -e "${RED}════════════════════════════════════════════════${NC}"
    echo -e "${RED}🚨 REAL-TIME ALERT: ${template}${NC}"
    echo -e "${RED}📍 URL: ${url}${NC}"
    echo -e "${RED}⚠️  Severity: ${severity}${NC}"
    echo -e "${RED}🎯 AI Confidence: ${confidence}%${NC}"
    echo -e "${RED}════════════════════════════════════════════════${NC}"
    
    # Send to Telegram
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d chat_id="$TELEGRAM_CHAT_ID" \
            -d text="$message" \
            -d parse_mode="Markdown" > /dev/null &
    fi
    
    # Send to Discord
    if [ -n "$DISCORD_WEBHOOK" ]; then
        discord_msg="{\"content\":\"**VULNERABILITY DETECTED**\\n**Time:** $timestamp\\n**Severity:** $severity\\n**Type:** $template\\n**URL:** $url\\n**Confidence:** ${confidence}%\"}"
        curl -s -H "Content-Type: application/json" -X POST -d "$discord_msg" "$DISCORD_WEBHOOK" > /dev/null &
    fi
    
    # Send to Slack
    if [ -n "$SLACK_WEBHOOK" ]; then
        slack_msg="{\"text\":\"🚨 *Vulnerability Detected*\\n• *Time:* $timestamp\\n• *Severity:* $severity\\n• *Type:* $template\\n• *URL:* $url\\n• *Confidence:* ${confidence}%\"}"
        curl -s -X POST -H 'Content-type: application/json' --data "$slack_msg" "$SLACK_WEBHOOK" > /dev/null &
    fi
    
    # Local notification (for desktop)
    if command -v notify-send &> /dev/null; then
        notify-send -u critical "Deep Bug Hunter Alert" \
            "Severity: $severity\nType: $template\nURL: $url\nConfidence: ${confidence}%" &
    fi
    
    # Play alert sound
    if command -v paplay &> /dev/null; then
        paplay /usr/share/sounds/ubuntu/notifications/Mallet.ogg 2>/dev/null &
    elif command -v afplay &> /dev/null; then
        afplay /System/Library/Sounds/Ping.aiff 2>/dev/null &
    elif command -v beep &> /dev/null; then
        beep -f 1000 -l 500 &
    fi
}

# AI-Enhanced Scan with Real-Time Analysis
ai_enhanced_scan() {
    local target="$1"
    local mode="$2"
    
    echo -e "${CYAN}[*] Starting AI-Enhanced Scan...${NC}"
    echo -e "${GREEN}[AI] Real-time analysis: ENABLED${NC}"
    echo -e "${GREEN}[AI] Confidence threshold: ${AI_CONFIDENCE_THRESHOLD}${NC}"
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$OUTPUT_DIR/ai_scan_$timestamp.json"
    
    echo -e "${YELLOW}[*] Target: $target${NC}"
    echo -e "${YELLOW}[*] Output: $output_file${NC}"
    
    # Start Nuclei with streaming output
    "$NUCLEI_PATH" -u "$target" \
        -t "$TEMPLATES_PATH" \
        -t "$CUSTOM_TEMPLATES" \
        -severity critical,high,medium,low \
        -rate-limit 100 \
        -concurrency 20 \
        -json \
        -silent \
        -o "$output_file" &
    
    nuclei_pid=$!
    
    echo -e "${CYAN}[*] Monitoring scan in real-time...${NC}"
    echo -e "${CYAN}[*] Press Ctrl+C to stop monitoring${NC}"
    
    # Monitor file for new findings
    tail -f "$output_file" 2>/dev/null | while read -r line; do
        if [ -n "$line" ]; then
            # Parse JSON finding menggunakan jq atau Python
            if command -v jq &> /dev/null; then
                template=$(echo "$line" | jq -r '.template // "unknown"' 2>/dev/null || echo "unknown")
                severity=$(echo "$line" | jq -r '.severity // "info"' 2>/dev/null || echo "info")
                matched=$(echo "$line" | jq -r '.matched // ""' 2>/dev/null || echo "")
            else
                # Simple parsing tanpa jq
                template=$(echo "$line" | grep -o '"template":"[^"]*"' | cut -d'"' -f4)
                severity=$(echo "$line" | grep -o '"severity":"[^"]*"' | cut -d'"' -f4)
                matched=$(echo "$line" | grep -o '"matched":"[^"]*"' | cut -d'"' -f4)
            fi
            
            if [ -n "$template" ] && [ "$template" != "unknown" ]; then
                echo -e "${BLUE}[AI] Analyzing: ${template}${NC}"
                
                # AI Analysis
                ai_result=$(ai_analyze_finding "$line")
                ai_decision=$(echo "$ai_result" | cut -d':' -f1)
                ai_confidence=$(echo "$ai_result" | cut -d':' -f2)
                
                if [ "$ai_decision" = "true" ]; then
                    # Send real-time alert
                    send_real_time_alert "$severity" "$template" "$matched" "$ai_confidence"
                    
                    echo -e "${GREEN}[AI ✓] Verified: ${template} (${ai_confidence}% confidence)${NC}"
                else
                    echo -e "${ORANGE}[AI ?] Low confidence: ${template} (${ai_confidence}% confidence)${NC}"
                fi
            fi
        fi
    done &
    
    monitor_pid=$!
    
    # Wait for nuclei to complete
    wait $nuclei_pid 2>/dev/null
    
    # Stop monitoring
    kill $monitor_pid 2>/dev/null
    
    echo -e "${GREEN}[✓] AI Scan completed${NC}"
    echo -e "${GREEN}[✓] Results saved to: $output_file${NC}"
    
    # Generate summary
    if [ -f "$output_file" ]; then
        show_ai_summary "$output_file"
    fi
}

# Show AI Summary
show_ai_summary() {
    local file="$1"
    
    echo -e "${CYAN}\n╔══════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║         AI SCAN SUMMARY               ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
    
    if [ -f "$file" ] && [ -s "$file" ]; then
        total_count=0
        ai_verified=0
        
        while read -r line; do
            if [ -n "$line" ]; then
                total_count=$((total_count + 1))
                
                # Simple check if line contains vulnerability indicators
                if echo "$line" | grep -qi "sql\|xss\|rce\|injection\|traversal"; then
                    ai_verified=$((ai_verified + 1))
                fi
            fi
        done < "$file"
        
        echo -e "Total Findings: ${RED}$total_count${NC}"
        echo -e "AI Verified: ${GREEN}$ai_verified${NC}"
        
        if [ $total_count -gt 0 ]; then
            percentage=$((ai_verified * 100 / total_count))
            echo -e "Confidence Rate: ${BLUE}$percentage%${NC}"
        fi
        
        # Show top findings
        echo -e "\n${YELLOW}Top Findings:${NC}"
        grep -i "template" "$file" | head -5 | while read -r line; do
            template=$(echo "$line" | grep -o '"template":"[^"]*"' | cut -d'"' -f4)
            if [ -n "$template" ]; then
                echo "  • $template"
            fi
        done
        
    else
        echo -e "${GREEN}[✓] No vulnerabilities found${NC}"
    fi
}

# ============================================
# SCAN MODES
# ============================================

# Mode 1: AI Smart Scan
ai_smart_scan() {
    echo -e "${CYAN}[*] AI SMART SCAN MODE${NC}"
    echo -e "${YELLOW}[*] Masukkan target:${NC}"
    read -r target
    
    if [ -z "$target" ]; then
        echo -e "${RED}[!] Target tidak boleh kosong${NC}"
        return
    fi
    
    validate_target "$target" || return
    
    # Add protocol jika belum ada
    if [[ ! "$target" =~ ^https?:// ]]; then
        echo -e "${YELLOW}[?] Protocol (http/https):${NC}"
        read -r proto
        case $proto in
            https) target="https://$target" ;;
            *) target="http://$target" ;;
        esac
    fi
    
    ai_enhanced_scan "$target" "smart"
}

# Mode 2: Fast Aggressive Scan
fast_aggressive_scan() {
    echo -e "${RED}[!] FAST AGGRESSIVE MODE${NC}"
    echo -e "${YELLOW}[*] Masukkan target:${NC}"
    read -r target
    
    validate_target "$target" || return
    
    if [[ ! "$target" =~ ^https?:// ]]; then
        target="http://$target"
    fi
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$OUTPUT_DIR/fast_$timestamp.json"
    
    echo -e "${PURPLE}[*] Parameters:${NC}"
    echo "  • Rate: 150 req/sec"
    echo "  • Concurrency: 25"
    echo "  • All templates"
    
    "$NUCLEI_PATH" -u "$target" \
        -t "$TEMPLATES_PATH" \
        -severity critical,high,medium,low \
        -rate-limit 150 \
        -concurrency 25 \
        -timeout 10 \
        -retries 2 \
        -stats \
        -json \
        -o "$output_file"
    
    echo -e "${GREEN}[✓] Scan completed${NC}"
    show_ai_summary "$output_file"
}

# Mode 3: Stealth Mode
stealth_scan() {
    echo -e "${GREEN}[*] STEALTH MODE${NC}"
    echo -e "${YELLOW}Mode ini menghindari deteksi WAF/IDS${NC}"
    
    echo -e "${YELLOW}[*] Masukkan target:${NC}"
    read -r target
    
    validate_target "$target" || return
    
    if [[ ! "$target" =~ ^https?:// ]]; then
        target="https://$target"
    fi
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$OUTPUT_DIR/stealth_$timestamp.json"
    
    # Randomize user agent
    ua=$(get_random_ua)
    
    echo -e "${PURPLE}[*] Stealth parameters:${NC}"
    echo "  • User-Agent: ${ua:0:50}..."
    echo "  • Rate: 5 req/sec"
    echo "  • Random delays"
    
    "$NUCLEI_PATH" -u "$target" \
        -t "$TEMPLATES_PATH" \
        -H "User-Agent: $ua" \
        -rate-limit 5 \
        -concurrency 2 \
        -timeout 30 \
        -retries 1 \
        -passive \
        -no-metadata \
        -json \
        -o "$output_file"
    
    echo -e "${GREEN}[✓] Stealth scan completed${NC}"
    show_ai_summary "$output_file"
}

# Mode 4: Custom Template Scan
custom_template_scan() {
    echo -e "${PURPLE}[*] CUSTOM TEMPLATE SCAN${NC}"
    
    echo -e "${YELLOW}[*] Masukkan target:${NC}"
    read -r target
    
    validate_target "$target" || return
    
    if [[ ! "$target" =~ ^https?:// ]]; then
        target="http://$target"
    fi
    
    echo -e "${YELLOW}[*] Pilih template category:${NC}"
    echo "  1. SQL Injection"
    echo "  2. XSS"
    echo "  3. Command Injection"
    echo "  4. Path Traversal"
    echo "  5. All Custom"
    
    read -r choice
    case $choice in
        1) templates="$CUSTOM_TEMPLATES/sql" ;;
        2) templates="$CUSTOM_TEMPLATES/xss" ;;
        3) templates="$CUSTOM_TEMPLATES/rce" ;;
        4) templates="$CUSTOM_TEMPLATES/traversal" ;;
        5) templates="$CUSTOM_TEMPLATES" ;;
        *) templates="$CUSTOM_TEMPLATES" ;;
    esac
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$OUTPUT_DIR/custom_$timestamp.json"
    
    "$NUCLEI_PATH" -u "$target" \
        -t "$templates" \
        -rate-limit 50 \
        -json \
        -o "$output_file"
    
    echo -e "${GREEN}[✓] Custom scan completed${NC}"
    show_ai_summary "$output_file"
}

# ============================================
# SETUP & CONFIGURATION
# ============================================

aggressive_setup() {
    echo -e "${RED}[!] SETUP MODE${NC}"
    
    # Create directories
    mkdir -p "$OUTPUT_DIR" "$LOG_DIR" "$CUSTOM_TEMPLATES" "$WORDLISTS_DIR" "$AI_MODEL_DIR"
    
    # Check Nuclei
    if [ ! -f "$NUCLEI_PATH" ]; then
        echo -e "${RED}[!] Nuclei not found at $NUCLEI_PATH${NC}"
        echo -e "${YELLOW}[?] Install Nuclei? (y/n):${NC}"
        read -r install
        if [[ "$install" =~ ^[Yy]$ ]]; then
            go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        fi
    else
        echo -e "${GREEN}[✓] Nuclei found${NC}"
        "$NUCLEI_PATH" -version
    fi
    
    # Update templates
    echo -e "${YELLOW}[*] Updating templates...${NC}"
    if [ -d "$TEMPLATES_PATH/.git" ]; then
        cd "$TEMPLATES_PATH" && git pull
        cd - >/dev/null
    else
        echo -e "${YELLOW}[*] Cloning templates...${NC}"
        git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "$TEMPLATES_PATH"
    fi
    
    # Create basic custom templates
    create_basic_templates
    
    # Count templates
    count=$(find "$TEMPLATES_PATH" -name "*.yaml" | wc -l 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] $count templates loaded${NC}"
    
    echo -e "${GREEN}[✓] Setup completed${NC}"
}

create_basic_templates() {
    echo -e "${YELLOW}[*] Creating basic templates...${NC}"
    
    # SQL Injection template
    cat > "$CUSTOM_TEMPLATES/basic-sqli.yaml" << EOF
id: basic-sqli
info:
  name: Basic SQL Injection
  author: DeepBugHunter
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}?id=1'"
      - "{{BaseURL}}?id=1' OR '1'='1"
      - "{{BaseURL}}?id=1' UNION SELECT NULL--"

    matchers:
      - type: word
        words:
          - "sql"
          - "syntax"
          - "mysql"
          - "database"
        condition: or
EOF

    # XSS template
    cat > "$CUSTOM_TEMPLATES/basic-xss.yaml" << EOF
id: basic-xss
info:
  name: Basic XSS
  author: DeepBugHunter
  severity: medium

requests:
  - method: GET
    path:
      - "{{BaseURL}}?q=<script>alert(1)</script>"
      - "{{BaseURL}}?q=\" onmouseover=\"alert(1)\""

    matchers:
      - type: word
        words:
          - "<script>"
          - "onmouseover"
          - "alert(1)"
        condition: or
EOF

    echo -e "${GREEN}[✓] Basic templates created${NC}"
}

# Configure AI Settings
configure_ai_settings() {
    echo -e "${CYAN}[*] AI Configuration${NC}"
    
    echo -e "${YELLOW}[?] Enable AI (true/false) [current: $AI_ENABLED]:${NC}"
    read -r ai_enabled
    if [ -n "$ai_enabled" ]; then
        AI_ENABLED="$ai_enabled"
    fi
    
    echo -e "${YELLOW}[?] AI Confidence Threshold (0.0-1.0) [current: $AI_CONFIDENCE_THRESHOLD]:${NC}"
    read -r threshold
    if [ -n "$threshold" ]; then
        AI_CONFIDENCE_THRESHOLD="$threshold"
    fi
    
    echo -e "${YELLOW}[?] Enable Real-Time Alerts (true/false) [current: $REAL_TIME_ALERTS]:${NC}"
    read -r alerts
    if [ -n "$alerts" ]; then
        REAL_TIME_ALERTS="$alerts"
    fi
    
    echo -e "${YELLOW}[?] Telegram Bot Token (kosongkan untuk skip):${NC}"
    read -r token
    if [ -n "$token" ]; then
        TELEGRAM_BOT_TOKEN="$token"
    fi
    
    echo -e "${YELLOW}[?] Telegram Chat ID:${NC}"
    read -r chat_id
    if [ -n "$chat_id" ]; then
        TELEGRAM_CHAT_ID="$chat_id"
    fi
    
    echo -e "${GREEN}[✓] AI settings updated${NC}"
}

# ============================================
# MENU UTAMA
# ============================================

main_menu() {
    while true; do
        clear
        echo -e "${CYAN}"
        cat << "EOF"
╔══════════════════════════════════════════════════╗
║   DEEP BUG HUNTER - AI MODE v4.0                 ║
║   AI-Powered Real-Time Vulnerability Detection   ║
╚══════════════════════════════════════════════════╝
EOF
        echo -e "${NC}"
        
        echo ""
        echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║          MAIN MENU                   ║${NC}"
        echo -e "${CYAN}╠══════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║  1. AI Smart Scan (Recommended)      ║${NC}"
        echo -e "${CYAN}║  2. Fast Aggressive Scan            ║${NC}"
        echo -e "${CYAN}║  3. Stealth Mode                    ║${NC}"
        echo -e "${CYAN}║  4. Custom Template Scan            ║${NC}"
        echo -e "${CYAN}║  5. Configure AI Settings           ║${NC}"
        echo -e "${CYAN}║  6. Setup & Update Tools            ║${NC}"
        echo -e "${CYAN}║  7. Test AI Detection               ║${NC}"
        echo -e "${CYAN}║  8. Exit                            ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
        
        echo -e "${YELLOW}[?] Pilih mode (1-8):${NC}"
        read -r choice
        choice=${choice:-0}
        
        case $choice in
            1) ai_smart_scan ;;
            2) fast_aggressive_scan ;;
            3) stealth_scan ;;
            4) custom_template_scan ;;
            5) configure_ai_settings ;;
            6) aggressive_setup ;;
            7) test_ai_detection ;;
            8) 
                echo -e "${GREEN}[✓] Keluar...${NC}"
                exit 0
                ;;
            *) echo -e "${RED}[!] Pilihan tidak valid${NC}" ;;
        esac
        
        echo -e "\n${YELLOW}Tekan Enter untuk melanjutkan...${NC}"
        read -r
    done
}

# Test AI Detection
test_ai_detection() {
    echo -e "${CYAN}[*] Testing AI Detection...${NC}"
    
    # Test cases
    test_cases=(
        '{"template":"sql-injection","severity":"high","matched":"http://test.com?id=1\\'"'"' OR \\'"'"'1\\'"'"'=\\'"'"'1"}'
        '{"template":"xss","severity":"medium","matched":"http://test.com?q=<script>alert(1)</script>"}'
        '{"template":"info","severity":"info","matched":"http://test.com/version"}'
        '{"template":"path-traversal","severity":"high","matched":"http://test.com/../../etc/passwd"}'
    )
    
    for i in "${!test_cases[@]}"; do
        test_case="${test_cases[$i]}"
        echo -e "${BLUE}[TEST $((i+1))] Analyzing...${NC}"
        echo "Input: $(echo "$test_case" | cut -c1-50)..."
        
        result=$(ai_analyze_finding "$test_case")
        ai_decision=$(echo "$result" | cut -d':' -f1)
        ai_confidence=$(echo "$result" | cut -d':' -f2)
        
        if [ "$ai_decision" = "true" ]; then
            echo -e "${GREEN}[RESULT] AI says: TRUE (${ai_confidence}% confidence)${NC}"
        else
            echo -e "${ORANGE}[RESULT] AI says: FALSE (${ai_confidence}% confidence)${NC}"
        fi
        echo "---"
    done
}

# ============================================
# MAIN EXECUTION
# ============================================

main() {
    # Show warning
    clear
    echo -e "${RED}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                         ⚠️  WARNING ⚠️                          ║
╠═══════════════════════════════════════════════════════════════════╣
║ This tool is for AUTHORIZED security testing only.                ║
║                                                                   ║
║ By continuing, you confirm:                                       ║
║ 1. You have permission to test the target                         ║
║ 2. You accept all legal responsibility                            ║
║ 3. You will not use this for illegal purposes                     ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    echo -e "${YELLOW}[?] Terima syarat dan ketentuan? (y/n):${NC}"
    read -r accept
    
    if [[ ! "$accept" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}[✓] Keluar dengan aman${NC}"
        exit 0
    fi
    
    # Initialize
    init_ai_models
    aggressive_setup
    
    # Start main menu
    main_menu
}

# Trap interrupt
trap 'echo -e "\n${RED}Interrupted${NC}"; exit' INT

# Check root
if [[ $EUID -eq 0 ]]; then
    echo -e "${YELLOW}[!] Running as root - be careful${NC}"
fi

# Start
main
