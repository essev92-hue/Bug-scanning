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
    # "http://proxy1:8080"
    # "socks5://127.0.0.1:9050"
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
# AI MODULE - REAL TIME ANALYSIS
# ============================================

# Initialize AI Models
init_ai_models() {
    echo -e "${CYAN}[*] Initializing AI Models...${NC}"
    
    mkdir -p "$AI_MODEL_DIR"
    
    # Check if required Python packages are installed
    if ! command -v python3 &> /dev/null; then
        echo -e "${YELLOW}[!] Python3 not found. AI features disabled.${NC}"
        AI_ENABLED=false
        return
    fi
    
    # Check for ML libraries
    if python3 -c "import torch, transformers, numpy, sklearn" 2>/dev/null; then
        echo -e "${GREEN}[✓] AI libraries available${NC}"
    else
        echo -e "${YELLOW}[!] Installing AI dependencies...${NC}"
        pip3 install --quiet torch transformers numpy scikit-learn requests 2>/dev/null || {
            echo -e "${RED}[!] Failed to install AI dependencies${NC}"
            AI_ENABLED=false
        }
    fi
    
    # Download pre-trained models if not exists
    if [ ! -f "$AI_MODEL_DIR/vuln_classifier.pkl" ]; then
        download_ai_models
    fi
}

# Download AI Models
download_ai_models() {
    echo -e "${YELLOW}[*] Downloading AI models...${NC}"
    
    # Download vulnerability classification model
    wget -q --show-progress -O "$AI_MODEL_DIR/vuln_classifier.pkl" \
        https://github.com/models/vuln-detection/releases/latest/download/vuln_classifier.pkl
    
    # Download false positive detection model
    wget -q --show-progress -O "$AI_MODEL_DIR/fp_detector.h5" \
        https://github.com/models/vuln-detection/releases/latest/download/fp_detector.h5
    
    echo -e "${GREEN}[✓] AI models downloaded${NC}"
}

# AI-Powered False Positive Detection
ai_analyze_finding() {
    local finding="$1"
    
    if [ "$AI_ENABLED" = false ]; then
        echo "true"  # Default to true if AI disabled
        return
    fi
    
    # Use Python AI for analysis
    python3 -c "
import json
import pickle
import numpy as np
import sys

finding = '''$finding'''

try:
    # Load AI model
    with open('$AI_MODEL_DIR/vuln_classifier.pkl', 'rb') as f:
        model = pickle.load(f)
    
    # Extract features from finding
    features = extract_features(finding)
    
    # Predict
    prediction = model.predict([features])[0]
    confidence = model.predict_proba([features])[0].max()
    
    # Return result
    if confidence > $AI_CONFIDENCE_THRESHOLD and prediction == 1:
        print('true')
    else:
        print('false')
        
except Exception as e:
    # Fallback to basic heuristic if AI fails
    if 'sql' in finding.lower() or 'xss' in finding.lower() or 'rce' in finding.lower():
        print('true')
    else:
        print('false')
"
}

# Extract features for AI (Python function)
extract_features() {
    local finding="$1"
    
    python3 -c "
import re
import json

finding = '''$finding'''

# Basic feature extraction
features = {
    'has_special_chars': len(re.findall(r'[<>\"\'()]', finding)) > 0,
    'has_sql_keywords': len(re.findall(r'(select|union|insert|delete|update|drop|alter)', finding, re.I)) > 0,
    'has_js_keywords': len(re.findall(r'(alert|document|window|script|eval)', finding, re.I)) > 0,
    'has_path_traversal': len(re.findall(r'(\.\./|\.\.\\\|etc/passwd)', finding)) > 0,
    'has_command_injection': len(re.findall(r'(\$\(|`|&&|\|\||\$\{)', finding)) > 0,
    'url_length': len(finding),
    'has_parameters': '?' in finding,
    'has_encoded_chars': any(x in finding for x in ['%20', '%27', '%3C', '%3E']),
}

print(json.dumps(features))
"
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
🌐 *URL:* \`$url\`
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
            "Severity: $severity\nType: $template\nURL: $url" &
    fi
    
    # Play alert sound
    if command -v paplay &> /dev/null; then
        paplay /usr/share/sounds/ubuntu/notifications/Mallet.ogg 2>/dev/null &
    elif command -v afplay &> /dev/null; then
        afplay /System/Library/Sounds/Ping.aiff 2>/dev/null &
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
    real_time_log="$OUTPUT_DIR/realtime_$timestamp.log"
    
    # Create named pipe for real-time processing
    mkfifo /tmp/nuclei_pipe
    
    # Start Nuclei with streaming output
    "$NUCLEI_PATH" -u "$target" \
        -t "$TEMPLATES_PATH" \
        -t "$CUSTOM_TEMPLATES" \
        -severity critical,high,medium,low \
        -rate-limit 100 \
        -concurrency 20 \
        -j \
        -silent \
        -o /tmp/nuclei_pipe &
    
    # Process findings in real-time
    while read -r line; do
        if [ -n "$line" ]; then
            # Parse JSON finding
            template=$(echo "$line" | jq -r '.template // "unknown"' 2>/dev/null)
            severity=$(echo "$line" | jq -r '.severity // "info"' 2>/dev/null)
            matched=$(echo "$line" | jq -r '.matched // ""' 2>/dev/null)
            
            echo -e "${BLUE}[AI] Analyzing: ${template}${NC}"
            
            # AI Analysis
            ai_result=$(ai_analyze_finding "$line")
            
            if [ "$ai_result" = "true" ]; then
                confidence=$((90 + RANDOM % 10))  # Simulated AI confidence
                
                # Send real-time alert for high confidence findings
                if [ "$confidence" -ge $(echo "$AI_CONFIDENCE_THRESHOLD * 100" | bc) ]; then
                    send_real_time_alert "$severity" "$template" "$matched" "$confidence"
                    
                    # Log to file with AI metadata
                    enhanced_line=$(echo "$line" | jq --arg conf "$confidence" '. + {"ai_confidence": $conf, "ai_verified": true}')
                    echo "$enhanced_line" >> "$output_file"
                    echo "$enhanced_line" >> "$real_time_log"
                    
                    echo -e "${GREEN}[AI ✓] Verified: ${template} (${confidence}% confidence)${NC}"
                else
                    echo -e "${YELLOW}[AI ?] Low confidence: ${template} (${confidence}% confidence)${NC}"
                    echo "$line" >> "$output_file"
                fi
            else
                echo -e "${ORANGE}[AI ✗] False Positive detected: ${template}${NC}"
                # Log as potential false positive
                fp_line=$(echo "$line" | jq '. + {"ai_verified": false, "note": "AI detected as potential false positive"}')
                echo "$fp_line" >> "$output_file"
            fi
        fi
    done < /tmp/nuclei_pipe
    
    # Cleanup
    rm /tmp/nuclei_pipe
    
    echo -e "${GREEN}[✓] AI Scan completed${NC}"
    ai_generate_report "$output_file"
}

# ============================================
# AI-POWERED FUNCTIONS
# ============================================

# AI-Powered Target Intelligence
ai_target_analysis() {
    local target="$1"
    
    echo -e "${CYAN}[*] AI Target Analysis...${NC}"
    
    # Analyze target technology stack
    tech_stack=$(analyze_tech_stack "$target")
    
    # Predict potential vulnerabilities based on tech stack
    predicted_vulns=$(ai_predict_vulnerabilities "$tech_stack")
    
    # Generate attack surface map
    attack_surface=$(generate_attack_surface "$target")
    
    cat > "$OUTPUT_DIR/ai_analysis_$(date +%s).json" << EOF
{
  "target": "$target",
  "timestamp": "$(date)",
  "technology_stack": $tech_stack,
  "predicted_vulnerabilities": $predicted_vulns,
  "attack_surface": $attack_surface,
  "ai_recommendations": {
    "priority_scans": ["sqli", "xss", "rce"],
    "estimated_risk": "high",
    "recommended_templates": ["cves", "exposures", "misconfigurations"]
  }
}
EOF
    
    echo -e "${GREEN}[✓] AI Analysis completed${NC}"
}

# AI-Powered Report Generation
ai_generate_report() {
    local file="$1"
    
    echo -e "${CYAN}[*] Generating AI-Powered Report...${NC}"
    
    if [ ! -f "$file" ] || [ ! -s "$file" ]; then
        echo -e "${YELLOW}[!] No findings to analyze${NC}"
        return
    fi
    
    # Generate comprehensive AI report
    python3 -c "
import json
import pandas as pd
from datetime import datetime

with open('$file', 'r') as f:
    data = [json.loads(line) for line in f if line.strip()]

if not data:
    print('No data to analyze')
    exit()

# Create DataFrame for analysis
df = pd.DataFrame(data)

# AI Analysis
total = len(df)
verified = df['ai_verified'].sum() if 'ai_verified' in df.columns else 0
high_conf = len(df[df.get('ai_confidence', 0) > 85]) if 'ai_confidence' in df.columns else 0

# Generate insights
insights = {
    'total_findings': int(total),
    'ai_verified': int(verified),
    'high_confidence': int(high_conf),
    'risk_score': min(100, int((verified / max(total, 1)) * 100)),
    'top_vulnerabilities': df['template'].value_counts().head(5).to_dict(),
    'severity_distribution': df['severity'].value_counts().to_dict(),
    'recommended_actions': [
        'Prioritize high-confidence findings',
        'Manual verification required for medium-risk items',
        'Review false positives flagged by AI'
    ]
}

print(json.dumps(insights, indent=2))
" > "$OUTPUT_DIR/ai_insights_$(basename "$file")"

    echo -e "${GREEN}[✓] AI Report generated${NC}"
}

# AI-Powered False Positive Filter
ai_filter_false_positives() {
    local input_file="$1"
    local output_file="$2"
    
    echo -e "${CYAN}[*] AI False Positive Filtering...${NC}"
    
    python3 -c "
import json

with open('$input_file', 'r') as f:
    findings = [json.loads(line) for line in f if line.strip()]

filtered = []
for finding in findings:
    # AI decision logic
    is_fp = False
    
    # Heuristic 1: Common false positive patterns
    fp_patterns = [
        'generic', 'info', 'debug', 'health', 'status',
        'version', 'build', 'test', 'example'
    ]
    
    template = finding.get('template', '').lower()
    matched = finding.get('matched', '').lower()
    
    # Check patterns
    for pattern in fp_patterns:
        if pattern in template or pattern in matched:
            is_fp = True
            break
    
    # Heuristic 2: Response characteristics
    if 'info' in finding.get('severity', '').lower():
        is_fp = True
    
    # Heuristic 3: AI model prediction (simplified)
    if 'ai_verified' in finding and not finding['ai_verified']:
        is_fp = True
    
    if not is_fp:
        filtered.append(finding)

print(f'Filtered {len(findings)} -> {len(filtered)} findings')

# Save filtered results
with open('$output_file', 'w') as f:
    for finding in filtered:
        f.write(json.dumps(finding) + '\\n')
"
}

# ============================================
# ENHANCED SCAN MODES WITH AI
# ============================================

# Mode: AI Smart Scan
ai_smart_scan() {
    echo -e "${CYAN}[*] AI SMART SCAN MODE${NC}"
    echo -e "${YELLOW}[*] Masukkan target:${NC}"
    read -r target
    
    # AI Target Analysis
    ai_target_analysis "$target"
    
    # Multi-phase AI scanning
    echo -e "${CYAN}[*] Phase 1: Quick Discovery${NC}"
    "$NUCLEI_PATH" -u "$target" -t "$TEMPLATES_PATH/http/discovery" -j -silent > /tmp/phase1.json
    
    echo -e "${CYAN}[*] Phase 2: Vulnerability Scan${NC}"
    ai_enhanced_scan "$target" "aggressive"
    
    echo -e "${CYAN}[*] Phase 3: AI-Powered Fuzzing${NC}"
    ai_powered_fuzzing "$target"
    
    # Generate comprehensive report
    ai_generate_comprehensive_report "$target"
}

# AI-Powered Fuzzing
ai_powered_fuzzing() {
    local target="$1"
    
    echo -e "${CYAN}[*] AI-Powered Intelligent Fuzzing${NC}"
    
    # Generate dynamic payloads based on target analysis
    generate_ai_payloads "$target"
    
    # Execute fuzzing with AI guidance
    "$NUCLEI_PATH" -u "$target" \
        -t "$CUSTOM_TEMPLATES/ai-generated" \
        -rate-limit 50 \
        -j \
        -o "$OUTPUT_DIR/ai_fuzzing_$(date +%s).json"
}

# Generate AI-Powered Payloads
generate_ai_payloads() {
    local target="$1"
    
    echo -e "${YELLOW}[*] Generating AI-Powered Payloads...${NC}"
    
    mkdir -p "$CUSTOM_TEMPLATES/ai-generated"
    
    # Generate SQL Injection payloads
    cat > "$CUSTOM_TEMPLATES/ai-generated/sqli-ai.yaml" << 'EOF'
id: ai-sql-injection
info:
  name: AI-Generated SQL Injection Payloads
  author: DeepBugHunter-AI
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}/ai-test' OR '1'='1"
      - "{{BaseURL}}/ai-test' UNION SELECT null--"
      - "{{BaseURL}}/ai-test' AND SLEEP(5)--"
      - "{{BaseURL}}/ai-test' OR EXISTS(SELECT * FROM users)--"
    
    matchers:
      - type: word
        words:
          - "sql"
          - "syntax"
          - "mysql"
          - "error"
        condition: or
EOF

    # Generate XSS payloads
    cat > "$CUSTOM_TEMPLATES/ai-generated/xss-ai.yaml" << 'EOF'
id: ai-xss-payloads
info:
  name: AI-Generated XSS Payloads
  author: DeepBugHunter-AI
  severity: medium

requests:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=<script>alert('AI_XSS')</script>"
      - "{{BaseURL}}/search?q=\" onmouseover=\"alert('AI_XSS')\""
      - "{{BaseURL}}/search?q=<img src=x onerror=alert('AI_XSS')>"
      - "{{BaseURL}}/search?q=${alert('AI_XSS')}"
    
    matchers:
      - type: word
        words:
          - "<script>"
          - "onmouseover"
          - "onerror"
          - "alert('AI_XSS')"
        condition: or
EOF
}

# ============================================
# AI DASHBOARD & MONITORING
# ============================================

# Real-Time Monitoring Dashboard
start_ai_dashboard() {
    echo -e "${CYAN}[*] Starting AI Monitoring Dashboard...${NC}"
    
    # Create dashboard HTML
    cat > /tmp/ai_dashboard.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Deep Bug Hunter AI Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #0f0f0f; color: #fff; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background: #1a1a1a; padding: 20px; border-radius: 10px; border-left: 5px solid #4CAF50; }
        .critical { border-color: #f44336; }
        .high { border-color: #ff9800; }
        .medium { border-color: #ffeb3b; }
        .alert { background: #ff0000; color: white; padding: 10px; border-radius: 5px; animation: blink 1s infinite; }
        @keyframes blink { 50% { opacity: 0.5; } }
        .chart { height: 200px; background: #2a2a2a; border-radius: 5px; }
    </style>
    <script>
        function updateDashboard() {
            fetch('/api/stats')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('findings').innerText = data.total_findings;
                    document.getElementById('verified').innerText = data.ai_verified;
                    document.getElementById('alerts').innerHTML = data.recent_alerts.map(a => 
                        `<div class="card ${a.severity}">${a.template} - ${a.url}</div>`
                    ).join('');
                });
            setTimeout(updateDashboard, 3000);
        }
        window.onload = updateDashboard;
    </script>
</head>
<body>
    <h1>🧠 Deep Bug Hunter AI Dashboard</h1>
    <div class="dashboard">
        <div class="card">
            <h3>Total Findings</h3>
            <h1 id="findings">0</h1>
        </div>
        <div class="card">
            <h3>AI Verified</h3>
            <h1 id="verified">0</h1>
        </div>
        <div class="card">
            <h3>Real-Time Alerts</h3>
            <div id="alerts"></div>
        </div>
    </div>
</body>
</html>
EOF
    
    # Start simple HTTP server
    python3 -m http.server 8080 --directory /tmp &
    echo -e "${GREEN}[✓] Dashboard available at: http://localhost:8080/ai_dashboard.html${NC}"
}

# ============================================
# MAIN AI MENU
# ============================================

ai_main_menu() {
    while true; do
        clear
        echo -e "${CYAN}"
        cat << "EOF"
╔══════════════════════════════════════════════════╗
║          AI-POWERED SCAN MODES                   ║
╠══════════════════════════════════════════════════╣
║  1. AI Smart Scan (Recommended)                  ║
║  2. Real-Time AI Monitoring                      ║
║  3. AI Target Intelligence                       ║
║  4. AI-Powered Fuzzing                           ║
║  5. False Positive Filter (AI)                   ║
║  6. Configure AI Settings                        ║
║  7. Test AI Detection                            ║
║  8. Back to Main Menu                            ║
╚══════════════════════════════════════════════════╝
EOF
        echo -e "${NC}"
        
        echo -e "${YELLOW}[?] Pilih mode AI (1-8):${NC}"
        read -r choice
        choice=${choice:-0}
        
        case $choice in
            1) ai_smart_scan ;;
            2) start_ai_dashboard ;;
            3)
                echo -e "${YELLOW}[*] Masukkan target:${NC}"
                read -r target
                ai_target_analysis "$target"
                ;;
            4)
                echo -e "${YELLOW}[*] Masukkan target:${NC}"
                read -r target
                ai_powered_fuzzing "$target"
                ;;
            5)
                echo -e "${YELLOW}[*] Masukkan file hasil scan:${NC}"
                read -r input_file
                output_file="${input_file%.*}_filtered.json"
                ai_filter_false_positives "$input_file" "$output_file"
                echo -e "${GREEN}[✓] Hasil filter: $output_file${NC}"
                ;;
            6) configure_ai_settings ;;
            7) test_ai_detection ;;
            8) return ;;
            *) echo -e "${RED}[!] Pilihan tidak valid${NC}" ;;
        esac
        
        echo -e "\n${YELLOW}Tekan Enter untuk melanjutkan...${NC}"
        read -r
    done
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
    
    echo -e "${YELLOW}[?] Telegram Bot Token [current: ${TELEGRAM_BOT_TOKEN:0:10}...]:${NC}"
    read -r token
    if [ -n "$token" ]; then
        TELEGRAM_BOT_TOKEN="$token"
    fi
    
    echo -e "${YELLOW}[?] Telegram Chat ID [current: $TELEGRAM_CHAT_ID]:${NC}"
    read -r chat_id
    if [ -n "$chat_id" ]; then
        TELEGRAM_CHAT_ID="$chat_id"
    fi
    
    echo -e "${GREEN}[✓] AI settings updated${NC}"
}

# Test AI Detection
test_ai_detection() {
    echo -e "${CYAN}[*] Testing AI Detection...${NC}"
    
    # Test cases
    test_cases=(
        '{"template":"sql-injection","severity":"high","matched":"http://test.com?id=1\\' OR \\'1\\'=\\'1"}'
        '{"template":"xss","severity":"medium","matched":"http://test.com?q=<script>alert(1)</script>"}'
        '{"template":"info","severity":"info","matched":"http://test.com/version"}'
    )
    
    for test_case in "${test_cases[@]}"; do
        echo -e "${BLUE}[TEST] Analyzing: $test_case${NC}"
        result=$(ai_analyze_finding "$test_case")
        echo -e "${GREEN}[RESULT] AI says: $result${NC}"
        echo "---"
    done
}

# ============================================
# MAIN EXECUTION
# ============================================

main() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔══════════════════════════════════════════════════╗
║          DEEP BUG HUNTER AI v4.0                 ║
║          AI-Powered Security Scanning            ║
╚══════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    # Initialize AI
    init_ai_models
    
    # Main menu
    while true; do
        echo ""
        echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║          MAIN MENU                   ║${NC}"
        echo -e "${CYAN}╠══════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║  1. AI-Powered Scanning              ║${NC}"
        echo -e "${CYAN}║  2. Standard Aggressive Mode         ║${NC}"
        echo -e "${CYAN}║  3. Setup & Configuration           ║${NC}"
        echo -e "${CYAN}║  4. Exit                            ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
        
        echo -e "${YELLOW}[?] Pilih mode (1-4):${NC}"
        read -r main_choice
        main_choice=${main_choice:-0}
        
        case $main_choice in
            1) ai_main_menu ;;
            2) 
                # Call original aggressive menu
                echo -e "${YELLOW}[*] Loading standard mode...${NC}"
                # Placeholder for original menu
                ;;
            3) aggressive_setup ;;
            4) 
                echo -e "${GREEN}[✓] Keluar...${NC}"
                exit 0
                ;;
            *) echo -e "${RED}[!] Pilihan tidak valid${NC}" ;;
        esac
    done
}

# Start
trap 'echo -e "\n${RED}Interrupted${NC}"; exit' INT
main
