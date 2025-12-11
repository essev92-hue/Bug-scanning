#!/bin/bash

# ============================================
# DEEP BUG HUNTER - AGGRESSIVE MODE (Termux / UserLAnd friendly)
# Version: 3.0 (Adapted)
# ============================================

# Konfigurasi Path
NUCLEI_PATH="${HOME}/go/bin/nuclei"
TEMPLATES_PATH="${HOME}/nuclei-templates"                 # gunakan direktori standar
CUSTOM_TEMPLATES="${HOME}/Bug-scanning/custom-templates"
OUTPUT_DIR="${HOME}/Bug-scanning/nuclei-scans/$(date +%Y%m)"
LOG_DIR="${HOME}/Bug-scanning/.nuclei-logs"
WORDLISTS_DIR="${HOME}/Bug-scanning/wordlists"

# Browser detection (headless)
PREFIX_BIN="${PREFIX:-/data/data/com.termux/files/usr/bin}"
BROWSER_CANDIDATES=(
  "/data/data/com.termux/files/usr/lib/chromium/headless_shell"
  "/data/data/com.termux/files/usr/lib/chromium/chrome"
  "/data/data/com.termux/files/usr/lib/chromium/chrome-wrapper"
  "/usr/bin/headless_shell"
  "/usr/bin/chromium"
  "/usr/bin/google-chrome"
  "$PREFIX_BIN/headless_shell"
  "$PREFIX_BIN/chrome"
  "$PREFIX_BIN/chromium"
)

BROWSER_CMD=""
HEADLESS_AVAILABLE=false

# Proxy untuk rotasi (jika perlu)
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
║   DEEP BUG HUNTER - AGGRESSIVE MODE v3.0         ║
║   Advanced Vulnerability Discovery Engine        ║
║   ⚠️  FOR AUTHORIZED TESTING ONLY               ║
╚══════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# ============================================
# Helper / Setup
# ============================================

random_delay() {
    local min=${1:-1}
    local max=${2:-5}
    local delay=$((RANDOM % (max - min + 1) + min))
    sleep $delay
}

get_random_ua() {
    local idx=$((RANDOM % ${#USER_AGENTS[@]}))
    echo "${USER_AGENTS[$idx]}"
}

get_random_proxy() {
    if [ ${#PROXY_LIST[@]} -gt 0 ]; then
        local idx=$((RANDOM % ${#PROXY_LIST[@]}))
        echo "${PROXY_LIST[$idx]}"
    else
        echo ""
    fi
}

# create directories
ensure_dirs() {
    mkdir -p "$OUTPUT_DIR" "$LOG_DIR" "$CUSTOM_TEMPLATES" "$WORDLISTS_DIR" "$TEMPLATES_PATH"
}

# detect browser headless capability
detect_headless_browser() {
    for candidate in "${BROWSER_CANDIDATES[@]}"; do
        if [ -x "$candidate" ]; then
            BROWSER_CMD="$candidate"
            HEADLESS_AVAILABLE=true
            break
        fi
    done

    # fallback: if chromium binary folder exists, try common filenames
    if [ -d "/data/data/com.termux/files/usr/lib/chromium" ] && [ "$HEADLESS_AVAILABLE" = false ]; then
        if [ -x "/data/data/com.termux/files/usr/lib/chromium/headless_shell" ]; then
            BROWSER_CMD="/data/data/com.termux/files/usr/lib/chromium/headless_shell"
            HEADLESS_AVAILABLE=true
        elif [ -x "/data/data/com.termux/files/usr/lib/chromium/chrome" ]; then
            BROWSER_CMD="/data/data/com.termux/files/usr/lib/chromium/chrome"
            HEADLESS_AVAILABLE=true
        fi
    fi

    if [ "$HEADLESS_AVAILABLE" = true ]; then
        echo -e "${GREEN}[✓] Headless browser ditemukan: $BROWSER_CMD${NC}"
        # ensure a simple symlink so other tools can call "chromium"
        if [ ! -x "$PREFIX_BIN/chromium" ]; then
            ln -sf "$BROWSER_CMD" "$PREFIX_BIN/chromium" 2>/dev/null || true
        fi
    else
        echo -e "${YELLOW}[!] Headless browser tidak ditemukan -> headless mode akan dinonaktifkan${NC}"
    fi
}

# basic function to map category to template folder (best-effort)
get_template_path() {
    local category=$1
    case "$category" in
        cves) echo "$TEMPLATES_PATH/cves" ;;
        vulnerabilities) echo "$TEMPLATES_PATH/vulnerabilities" ;;
        exposed-panels) echo "$TEMPLATES_PATH/exposures" ;;
        misconfiguration) echo "$TEMPLATES_PATH/misconfiguration" ;;
        default-logins) echo "$TEMPLATES_PATH/credentials" ;;
        exposures) echo "$TEMPLATES_PATH/exposures" ;;
        file) echo "$TEMPLATES_PATH/files" ;;
        headers) echo "$TEMPLATES_PATH/http/headers" ;;
        subdomain-takeover) echo "$TEMPLATES_PATH/takeovers" ;;
        *) echo "$TEMPLATES_PATH" ;;
    esac
}

# dummy analyzer stub to avoid missing function crashes
analyze_fuzz_results() {
    local dir="$1"
    echo -e "${CYAN}[*] Analyzing fuzz results in $dir (stub)${NC}"
    # add any analysis you need here
}

# validate target scope
validate_target() {
    local target=$1
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

# build nuclei command with environment awareness
build_nuclei_cmd() {
    local out="$1"
    local target="$2"
    local extra_flags=("$@") # unused but place-holder for future
    local base_cmd=("$NUCLEI_PATH" -u "$target" -t "$TEMPLATES_PATH" -t "$CUSTOM_TEMPLATES" -severity critical,high,medium,low,info -rate-limit 150 -concurrency 25 -timeout 5 -retries 3 -system-resolvers -stats -si 5 -j -o "$out")

    # if headless available, add -headless and pass browser path via env if needed
    if [ "$HEADLESS_AVAILABLE" = true ]; then
        base_cmd+=("-headless")
        # if using headless_shell specifically, Nuclei/Rod may find it; otherwise set env var
        export ROD_BROWSER="$BROWSER_CMD"
    fi

    echo "${base_cmd[@]}"
}

# ============================================
# MODE SCAN AGGRESIF
# ============================================

fast_aggressive_scan() {
    echo -e "${RED}[!] MODE AGGRESIF AKTIF${NC}"
    echo -e "${YELLOW}[*] Masukkan target:${NC}"
    read -r target

    validate_target "$target" || return

    if [[ ! "$target" =~ ^https?:// ]]; then
        echo -e "${YELLOW}[?] Protocol (http/https/both):${NC}"
        read -r proto
        case $proto in
            https) target="https://$target" ;;
            both) target="http://$target,https://$target" ;;
            *) target="http://$target" ;;
        esac
    fi

    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$OUTPUT_DIR/aggressive_$timestamp.json"

    echo -e "${PURPLE}[*] Parameters aggressive:${NC}"
    echo "  • Rate: 150 req/sec"
    echo "  • Concurrency: 25"
    echo "  • Timeout: 5s"
    echo "  • Retries: 3"
    echo "  • All templates"

    random_delay 2 5

    # build and run nuclei command (safer invocation)
    cmd=$(build_nuclei_cmd "$output_file" "$target")
    echo -e "${CYAN}[*] Running: $cmd${NC}"
    eval "$cmd"

    show_advanced_summary "$output_file"
}

deep_recon_scan() {
    echo -e "${RED}[!] DEEP RECON MODE${NC}"
    echo -e "${YELLOW}[*] Masukkan target/domain:${NC}"
    read -r target

    validate_target "$target" || return

    timestamp=$(date +"%Y%m%d_%H%M%S")
    recon_dir="$OUTPUT_DIR/recon_$timestamp"
    mkdir -p "$recon_dir"

    echo -e "${CYAN}[*] FASE 1: Discovery${NC}"
    "$NUCLEI_PATH" -u "$target" -t "$TEMPLATES_PATH/http/discovery" -t "$TEMPLATES_PATH/http/technologies" -severity info -rate-limit 100 -stats -j -o "$recon_dir/discovery.json"

    echo -e "${CYAN}[*] FASE 2: Technology Detection${NC}"
    "$NUCLEI_PATH" -u "$target" -tags "tech" -rate-limit 50 -j -o "$recon_dir/technologies.json"

    echo -e "${CYAN}[*] FASE 3: Intensive Vulnerability Scan${NC}"
    categories=("cves" "vulnerabilities" "exposed-panels" "misconfiguration" "default-logins" "exposures" "file" "headers" "subdomain-takeover")
    for category in "${categories[@]}"; do
        echo -e "${BLUE}[>] Scanning: $category${NC}"
        template_path=$(get_template_path "$category")
        if [ -n "$template_path" ] && [ -d "$template_path" ]; then
            "$NUCLEI_PATH" -u "$target" -t "$template_path" -rate-limit 80 -concurrency 15 -timeout 8 -j -o "$recon_dir/${category}.json" -silent
            random_delay 1 3
        else
            echo -e "${YELLOW}[!] Template path missing for $category: $template_path${NC}"
        fi
    done

    echo -e "${CYAN}[*] FASE 4: Custom Payloads${NC}"
    if [ -d "$CUSTOM_TEMPLATES" ]; then
        "$NUCLEI_PATH" -u "$target" -t "$CUSTOM_TEMPLATES" -rate-limit 60 -concurrency 10 -j -o "$recon_dir/custom_payloads.json"
    fi

    echo -e "${CYAN}[*] FASE 5: Analysis${NC}"
    if command -v jq &> /dev/null; then
        cat "$recon_dir"/*.json 2>/dev/null | jq -s 'add' > "$recon_dir/final_report.json"
    fi
    generate_report "$recon_dir"
}

intensive_fuzzing() {
    echo -e "${RED}[!] INTENSIVE FUZZING MODE${NC}"
    echo -e "${YELLOW}[*] Masukkan target URL:${NC}"
    read -r target

    validate_target "$target" || return

    echo -e "${YELLOW}[*] Path untuk fuzzing (default: /FUZZ):${NC}"
    read -r fuzz_path
    fuzz_path=${fuzz_path:-"/FUZZ"}

    timestamp=$(date +"%Y%m%d_%H%M%S")
    fuzz_dir="$OUTPUT_DIR/fuzz_$timestamp"
    mkdir -p "$fuzz_dir"

    declare -A wordlists=(
        ["dir"]="directory-list-2.3-medium.txt"
        ["params"]="parameter-names.txt"
        ["files"]="raft-large-files.txt"
        ["apis"]="api-endpoints.txt"
    )

    for wl in "${!wordlists[@]}"; do
        if [ ! -f "$WORDLISTS_DIR/${wordlists[$wl]}" ]; then
            echo -e "${YELLOW}[!] Downloading ${wordlists[$wl]} to $WORDLISTS_DIR${NC}"
            # Add your download command here if desired, e.g. wget/curl
        fi
    done

    echo -e "${CYAN}[*] Directory Fuzzing${NC}"
    # If headless available we include -headless, else run non-headless fuzz
    if [ "$HEADLESS_AVAILABLE" = true ]; then
        "$NUCLEI_PATH" -u "$target" -t "$TEMPLATES_PATH/http/fuzzing" -var "FUZZ=$fuzz_path" -rate-limit 200 -concurrency 30 -timeout 3 -headless -j -o "$fuzz_dir/directories.json"
    else
        "$NUCLEI_PATH" -u "$target" -t "$TEMPLATES_PATH/http/fuzzing" -var "FUZZ=$fuzz_path" -rate-limit 200 -concurrency 30 -timeout 3 -j -o "$fuzz_dir/directories.json"
    fi

    echo -e "${CYAN}[*] Parameter Fuzzing${NC}"
    "$NUCLEI_PATH" -u "$target" -tags "fuzz,ssrf,redirect,ssti,sqli" -rate-limit 150 -concurrency 20 -timeout 5 -j -o "$fuzz_dir/parameters.json"

    echo -e "${CYAN}[*] Header Injection${NC}"
    "$NUCLEI_PATH" -u "$target" -t "$TEMPLATES_PATH/http/headers" -rate-limit 100 -concurrency 15 -j -o "$fuzz_dir/headers.json"

    analyze_fuzz_results "$fuzz_dir"
}

stealth_scan() {
    echo -e "${GREEN}[*] STEALTH MODE${NC}"
    echo -e "${YELLOW}Mode ini menghindari deteksi WAF/IDS${NC}"
    echo -e "${YELLOW}[*] Masukkan target:${NC}"
    read -r target

    validate_target "$target" || return

    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$OUTPUT_DIR/stealth_$timestamp.json"

    ua=$(get_random_ua)
    proxy=$(get_random_proxy)

    echo -e "${PURPLE}[*] Stealth parameters:${NC}"
    echo "  • User-Agent: ${ua:0:50}..."
    echo "  • Rate: 10 req/sec"
    echo "  • Random delays: 3-10s"
    echo "  • Proxy: ${proxy:-none}"

    cmd="$NUCLEI_PATH -u \"$target\" -t \"$TEMPLATES_PATH\" -H \"User-Agent: $ua\" -rate-limit 10 -concurrency 3 -timeout 15 -retries 1 -stats -si 30 -j -passive -no-metadata"

    if [ -n "$proxy" ]; then
        cmd="$cmd -proxy $proxy"
    fi

    cmd="$cmd -o \"$output_file\""

    echo -e "${CYAN}[*] Starting stealth scan...${NC}"
    eval "$cmd" &
    pid=$!

    while kill -0 $pid 2>/dev/null; do
        sleep $((RANDOM % 7 + 3))
        echo -n "."
    done

    wait $pid

    echo -e "\n${GREEN}[✓] Stealth scan completed${NC}"
    show_advanced_summary "$output_file"
}

# ============================================
# ANALYTICS & REPORTING
# ============================================

show_advanced_summary() {
    local file="$1"
    echo -e "${CYAN}\n╔══════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║         SCAN RESULTS SUMMARY         ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"

    if [ -f "$file" ] && [ -s "$file" ]; then
        if command -v jq &> /dev/null; then
            total=$(jq 'length' "$file")
            echo -e "Total Findings: ${RED}$total${NC}"

            echo -e "\n${YELLOW}Severity Distribution:${NC}"
            jq -r '.[].severity' "$file" 2>/dev/null | sort | uniq -c | while read count severity; do
                case $severity in
                    critical) color="$RED" ;;
                    high) color="$PURPLE" ;;
                    medium) color="$YELLOW" ;;
                    low) color="$GREEN" ;;
                    info) color="$CYAN" ;;
                    *) color="$NC" ;;
                esac
                echo -e "  $color$severity${NC}: $count"
            done

            echo -e "\n${YELLOW}Top Vulnerability Types:${NC}"
            jq -r '.[].template' "$file" 2>/dev/null | sort | uniq -c | sort -rn | head -5 | while read count template; do
                echo "  $template ($count)"
            done

            echo -e "\n${RED}Critical Findings:${NC}"
            jq -r '.[] | select(.severity=="critical") | "  • \(.template): \(.matched)"' "$file" 2>/dev/null | head -3
        else
            count=$(wc -l < "$file" 2>/dev/null)
            echo -e "Total Findings: $count"
        fi

        echo -e "\n${GREEN}Full report: $file${NC}"

        if [ "$total" -gt 0 ]; then
            echo -e "${YELLOW}[!] Potensi exploit ditemukan${NC}"
            echo "Gunakan tools tambahan untuk verifikasi:"
            echo "  • Manual testing"
            echo "  • Metasploit modules"
            echo "  • Custom exploits"
        fi
    else
        echo -e "${GREEN}[✓] No vulnerabilities found${NC}"
    fi
}

generate_report() {
    local dir="$1"
    echo -e "${CYAN}[*] Generating HTML report...${NC}"

    mkdir -p "$dir"
    cat > "$dir/report.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Deep Bug Hunter Report</title>
    <style>
        body { font-family: Arial; margin: 40px; }
        .critical { color: #ff0000; font-weight: bold; }
        .high { color: #ff6600; }
        .medium { color: #ffcc00; }
        .low { color: #009900; }
        .info { color: #0066cc; }
    </style>
</head>
<body>
    <h1>Deep Bug Hunter Report</h1>
    <p>Generated: $(date)</p>
EOF

    if command -v jq &> /dev/null; then
        for json in "$dir"/*.json; do
            if [ -f "$json" ]; then
                echo "<h2>$(basename "$json")</h2>" >> "$dir/report.html"
                jq -r '.[] | "<div class=\"\(.severity)\">[\(.severity)] \(.template)<br>\(.matched)</div><hr>"' "$json" >> "$dir/report.html" 2>/dev/null
            fi
        done
    fi

    cat >> "$dir/report.html" << EOF
</body>
</html>
EOF

    echo -e "${GREEN}[✓] Report: $dir/report.html${NC}"
}

# ============================================
# SETUP AGGRESIF
# ============================================

aggressive_setup() {
    echo -e "${RED}[!] AGGRESSIVE MODE SETUP${NC}"
    ensure_dirs

    echo -e "${YELLOW}[*] Checking Nuclei version...${NC}"
    current_ver=$("$NUCLEI_PATH" -version 2>/dev/null | head -1)
    echo "Current: $current_ver"

    echo -e "${YELLOW}[*] Updating templates...${NC}"
    if [ -d "$TEMPLATES_PATH/.git" ]; then
        cd "$TEMPLATES_PATH" && git pull --force
        cd - >/dev/null
    else
        rm -rf "$TEMPLATES_PATH"
        git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "$TEMPLATES_PATH"
    fi

    echo -e "${YELLOW}[*] Fetching exploit templates...${NC}"
    exploit_repos=(
        "https://github.com/projectdiscovery/nuclei-templates"
        "https://github.com/geeknik/nuclei-templates"
    )
    for repo in "${exploit_repos[@]}"; do
        echo "  → $repo"
    done

    count=$(find "$TEMPLATES_PATH" -name "*.yaml" 2>/dev/null | wc -l || echo 0)
    echo -e "${GREEN}[✓] $count templates loaded${NC}"

    create_custom_templates
}

create_custom_templates() {
    echo -e "${YELLOW}[*] Creating custom aggressive templates...${NC}"
    mkdir -p "$CUSTOM_TEMPLATES"
    cat > "$CUSTOM_TEMPLATES/aggressive-headers.yaml" << 'EOF'
id: aggressive-headers
info:
  name: Aggressive Security Headers Check
  author: DeepBugHunter
  severity: info
  description: Aggressive security headers detection with bypass attempts

requests:
  - method: GET
    path:
      - "{{BaseURL}}"

    headers:
      X-Forwarded-For: 127.0.0.1
      X-Real-IP: 127.0.0.1
      X-Client-IP: 127.0.0.1
      X-Originating-IP: 127.0.0.1
      X-Remote-IP: 127.0.0.1
      X-Remote-Addr: 127.0.0.1

    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "Server:"
          - "X-Powered-By:"
        condition: or

      - type: regex
        part: header
        regex:
          - "(?i)server:.*(apache|nginx|iis|tomcat)"
EOF

    cat > "$CUSTOM_TEMPLATES/aggressive-path-traversal.yaml" << 'EOF'
id: aggressive-path-traversal
info:
  name: Aggressive Path Traversal
  author: DeepBugHunter
  severity: high
  description: Aggressive path traversal payloads

requests:
  - method: GET
    path:
      - "{{BaseURL}}/../../../../../../etc/passwd"
      - "{{BaseURL}}/..%2f..%2f..%2fetc%2fpasswd"
      - "{{BaseURL}}/....//....//....//etc/passwd"
      - "{{BaseURL}}/%2e%2e/%2e%2e/etc/passwd"

    matchers:
      - type: word
        words:
          - "root:x:"
          - "daemon:x:"
        condition: or
EOF

    echo -e "${GREEN}[✓] Custom templates created${NC}"
}

# ============================================
# MENU UTAMA AGGRESIF
# ============================================

aggressive_menu() {
    while true; do
        echo ""
        echo -e "${RED}╔══════════════════════════════════════╗${NC}"
        echo -e "${RED}║       AGGRESSIVE SCAN MODES         ║${NC}"
        echo -e "${RED}╠══════════════════════════════════════╣${NC}"
        echo -e "${RED}║  1. Fast & Aggressive Scan          ║${NC}"
        echo -e "${RED}║  2. Deep Recon + Exploitation       ║${NC}"
        echo -e "${RED}║  3. Intensive Fuzzing               ║${NC}"
        echo -e "${RED}║  4. Stealth Mode (Slow/Low)         ║${NC}"
        echo -e "${RED}║  5. Custom Target List Scan         ║${NC}"
        echo -e "${RED}║  6. Bruteforce & Enumeration        ║${NC}"
        echo -e "${RED}║  7. Update & Upgrade Tools          ║${NC}"
        echo -e "${RED}║  8. Generate Consolidated Report    ║${NC}"
        echo -e "${RED}║  9. Exit to Safe Mode               ║${NC}"
        echo -e "${RED}╚══════════════════════════════════════╝${NC}"
        echo -e "${YELLOW}[?] Select mode (1-9):${NC}"

        read -r choice
        case $choice in
            1) fast_aggressive_scan ;;
            2) deep_recon_scan ;;
            3) intensive_fuzzing ;;
            4) stealth_scan ;;
            5)
                echo -e "${YELLOW}[*] Masukkan file target list:${NC}"
                read -r target_file
                if [ -f "$target_file" ]; then
                    echo -e "${RED}[!] Scanning $(wc -l < "$target_file") targets${NC}"
                    # Implement multi-target scan (left as-is)
                fi
                ;;
            6)
                echo -e "${RED}[!] Bruteforce mode${NC}"
                # Implement brute force
                ;;
            7) aggressive_setup ;;
            8)
                echo -e "${YELLOW}[*] Generating consolidated report...${NC}"
                find "$OUTPUT_DIR" -name "*.json" -exec cat {} \; 2>/dev/null | jq -s 'add' > "$OUTPUT_DIR/consolidated.json"
                ;;
            9)
                echo -e "${GREEN}[✓] Returning to safe mode${NC}"
                return
                ;;
            *) echo -e "${RED}[!] Invalid${NC}" ;;
        esac

        echo ""
        echo -e "${YELLOW}Press Enter to continue...${NC}"
        read -r
        clear
        echo -e "${CYAN}"
        cat << "EOF"
╔══════════════════════════════════════════════════╗
║   DEEP BUG HUNTER - AGGRESSIVE MODE v3.0         ║
║   Advanced Vulnerability Discovery Engine        ║
╚══════════════════════════════════════════════════╝
EOF
        echo -e "${NC}"
    done
}

# ============================================
# DISCLAIMER & WARNING
# ============================================

show_warning() {
    clear
    echo -e "${RED}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                         ⚠️  WARNING ⚠️                          ║
╠═══════════════════════════════════════════════════════════════════╣
║ This tool is for AUTHORIZED security testing only.                ║
║                                                                   ║
║ ILLEGAL activities include:                                       ║
║ • Scanning targets without written permission                     ║
║ • Accessing systems you don't own                                 ║
║ • Extracting data without consent                                 ║
║                                                                   ║
║ Legal consequences:                                               ║
║ • Criminal charges (CFAA, Computer Fraud Act)                     ║
║ • Civil lawsuits                                                  ║
║ • Imprisonment                                                    ║
║                                                                   ║
║ By continuing, you confirm:                                       ║
║ 1. You have permission to test the target                         ║
║ 2. You accept all legal responsibility                            ║
║ 3. You will not use this for illegal purposes                     ║
╚═══════════════════════════════════════════════════════════════════╝${NC}
EOF

    echo -e "${YELLOW}[?] Accept terms? (yes/NO):${NC}"
    read -r accept
    if [[ "$accept" != "yes" ]]; then
        echo -e "${GREEN}[✓] Exiting safely${NC}"
        exit 0
    fi
}

# ============================================
# MAIN
# ============================================
main() {
    show_warning
    detect_headless_browser
    aggressive_setup

    echo ""
    echo -e "${RED}[!] Aggressive mode ready${NC}"
    echo -e "${YELLOW}[*] Select operation mode:${NC}"
    echo "  1. Aggressive Mode (Dangerous)"
    echo "  2. Safe Mode (Original)"
    echo "  3. Exit"

    read -r mode
    case $mode in
        1) aggressive_menu ;;
        2)
            echo -e "${GREEN}[✓] Switching to safe mode${NC}"
            ;;
        3) exit 0 ;;
        *) echo -e "${RED}[!] Invalid${NC}" ;;
    esac
}

trap 'echo -e "\n${RED}Interrupted${NC}"; exit' INT

if [[ $EUID -eq 0 ]]; then
    echo -e "${YELLOW}[!] Running as root - be careful${NC}"
fi

main
