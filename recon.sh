#!/usr/bin/env bash
# =============================================================================
# recon.sh — Bug Bounty Recon Automation Script
# Author   : Generated for authorized security testing only
# Platform : macOS Apple Silicon (arm64)
# Purpose  : Passive/light-active recon — NO exploits, NO brute force
# Usage    : ./recon.sh [OPTIONS] <target.com>
# =============================================================================

set -euo pipefail

# =============================================================================
# SECTION 1: COLORS & FORMATTING
# =============================================================================
BOLD="\033[1m"
RESET="\033[0m"
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
BLUE="\033[1;34m"
MAGENTA="\033[1;35m"
DIM="\033[2m"

banner() {
  echo -e "${CYAN}${BOLD}"
  echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
  echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
  echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
  echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
  echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
  echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
  echo -e "${DIM}  Bug Bounty Recon Automation — Authorized Testing Only${RESET}"
  echo ""
}

log_phase() {
  echo ""
  echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${BLUE}${BOLD}  [PHASE] $1${RESET}"
  echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

log_info()    { echo -e "${CYAN}  [*]${RESET} $1"; }
log_success() { echo -e "${GREEN}  [✔]${RESET} $1"; }
log_warn()    { echo -e "${YELLOW}  [!]${RESET} $1"; }
log_error()   { echo -e "${RED}  [✘]${RESET} $1"; }
log_skip()    { echo -e "${DIM}  [-] SKIP: $1${RESET}"; }

# =============================================================================
# SECTION 2: DEFAULT FLAGS & CONFIG
# =============================================================================
RUN_NUCLEI=true
FAST_MODE=false
DEEP_MODE=false
TARGET=""

# Rate limit defaults (requests per second / thread counts)
HTTPX_THREADS=50
HTTPX_RATE=150
KATANA_DEPTH=3
KATANA_CONCURRENCY=10
HAKRAWLER_DEPTH=3
GAU_THREADS=5
NMAP_TIMING=3   # T3 = normal, not aggressive
TOOL_TIMEOUT_SECONDS=300

# Interesting endpoint keywords to grep for
INTERESTING_KEYWORDS="api|admin|login|auth|debug|dev|staging|upload|file|redirect|callback|token|json|config"

# =============================================================================
# SECTION 3: HELP TEXT
# =============================================================================
usage() {
  echo -e "${BOLD}USAGE${RESET}"
  echo "  ./recon.sh [OPTIONS] <target.com>"
  echo ""
  echo -e "${BOLD}OPTIONS${RESET}"
  echo "  --no-nuclei   Skip nuclei vulnerability scanning"
  echo "  --fast        Reduce thread counts and skip deep crawls"
  echo "  --deep        Increase crawl depth, more thorough enumeration"
  echo "  --help        Show this help message"
  echo ""
  echo -e "${BOLD}EXAMPLES${RESET}"
  echo "  ./recon.sh example.com"
  echo "  ./recon.sh --no-nuclei example.com"
  echo "  ./recon.sh --fast example.com"
  echo "  ./recon.sh --deep example.com"
  echo ""
  echo -e "${YELLOW}${BOLD}  ⚠  Only run this script against domains you are explicitly authorized to test.${RESET}"
  echo ""
  exit 0
}

# =============================================================================
# SECTION 4: ARGUMENT PARSING
# =============================================================================
parse_args() {
  if [[ $# -eq 0 ]]; then
    log_error "No arguments provided."
    echo ""
    usage
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --help|-h)      usage ;;
      --no-nuclei)    RUN_NUCLEI=false; shift ;;
      --fast)         FAST_MODE=true; shift ;;
      --deep)         DEEP_MODE=true; shift ;;
      --*)            log_error "Unknown flag: $1"; usage ;;
      *)
        if [[ -z "$TARGET" ]]; then
          TARGET="$1"
        else
          log_error "Unexpected argument: $1"
          usage
        fi
        shift
        ;;
    esac
  done

  if [[ -z "$TARGET" ]]; then
    log_error "No target domain specified."
    usage
  fi
}

# =============================================================================
# SECTION 5: DOMAIN VALIDATION
# Validates basic domain format — does NOT make network requests
# =============================================================================
validate_domain() {
  # Allow: example.com, sub.example.com, example.co.uk
  local domain_regex='^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
  if [[ ! "$TARGET" =~ $domain_regex ]]; then
    log_error "Invalid domain format: '$TARGET'"
    log_error "Expected format: example.com or sub.example.com"
    exit 1
  fi
  log_success "Target domain validated: ${BOLD}$TARGET${RESET}"
}

# =============================================================================
# SECTION 6: TOOL CHECK
# Checks all required tools are installed before running any phase.
# nuclei is only required when --no-nuclei is NOT passed.
# REQUIRED_TOOLS is finalized in main() after parse_args() runs.
# =============================================================================
REQUIRED_TOOLS=(subfinder assetfinder httpx gau hakrawler katana nmap)
MISSING_TOOLS=()

check_tools() {
  log_phase "Checking Required Tools"
  local all_ok=true

  for tool in "${REQUIRED_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
      log_success "$tool found at $(command -v "$tool")"
    else
      log_error "$tool NOT FOUND"
      MISSING_TOOLS+=("$tool")
      all_ok=false
    fi
  done

  if [[ "$all_ok" == false ]]; then
    echo ""
    log_warn "Missing tools detected: ${MISSING_TOOLS[*]}"
    log_warn "Install them before proceeding (macOS / Go):"
    echo -e "  ${DIM}brew install nmap${RESET}"
    echo -e "  ${DIM}go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest${RESET}"
    echo -e "  ${DIM}go install github.com/tomnomnom/assetfinder@latest${RESET}"
    echo -e "  ${DIM}go install github.com/projectdiscovery/httpx/cmd/httpx@latest${RESET}"
    echo -e "  ${DIM}go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest${RESET}"
    echo -e "  ${DIM}go install github.com/lc/gau/v2/cmd/gau@latest${RESET}"
    echo -e "  ${DIM}go install github.com/hakluke/hakrawler@latest${RESET}"
    echo -e "  ${DIM}go install github.com/projectdiscovery/katana/cmd/katana@latest${RESET}"
    echo -e "  ${DIM}# Ensure ~/go/bin is in your PATH: export PATH=\$PATH:\$HOME/go/bin${RESET}"
    exit 1
  fi

  log_success "All required tools are installed."
}

# =============================================================================
# SECTION 7: OUTPUT DIRECTORY SETUP
# =============================================================================
OUTPUT_DIR=""
setup_output() {
  local timestamp
  timestamp=$(date +"%Y%m%d-%H%M")
  OUTPUT_DIR="recon-${TARGET}-${timestamp}"
  mkdir -p "$OUTPUT_DIR"
  log_success "Output directory created: ${BOLD}$OUTPUT_DIR${RESET}"
}

# Output file paths — populated in main() after OUTPUT_DIR is set
SUBS_RAW=""
SUBS_FILE=""
LIVE_FILE=""
PORTS_FILE=""
URLS_GAU=""
URLS_KATANA=""
URLS_HAKRAWLER=""
ALL_URLS=""
PARAMS_FILE=""
INTERESTING_FILE=""
JS_FILE=""
NUCLEI_FILE=""
SUMMARY_FILE=""
LOG_FILE=""
TEMP_SUBFINDER_OUT=""
TEMP_ASSETFINDER_OUT=""
TIMEOUT_BIN=""

# NOTE: exec > >(tee ...) is intentionally NOT set here.
# It is set in main() after setup_output() so LOG_FILE has a valid path.

escape_ere() {
  printf '%s\n' "$1" | sed -e 's/[][(){}.^$*+?|\\-]/\\&/g'
}

resolve_timeout_bin() {
  if command -v timeout &>/dev/null; then
    TIMEOUT_BIN="$(command -v timeout)"
  elif command -v gtimeout &>/dev/null; then
    TIMEOUT_BIN="$(command -v gtimeout)"
  else
    TIMEOUT_BIN=""
  fi
}

run_with_timeout() {
  local seconds="$1"
  shift

  if [[ -n "$TIMEOUT_BIN" ]]; then
    "$TIMEOUT_BIN" "$seconds" "$@"
  else
    "$@"
  fi
}

cleanup_temp_files() {
  rm -f "$TEMP_SUBFINDER_OUT" "$TEMP_ASSETFINDER_OUT"
}

# =============================================================================
# SECTION 8: ADJUST SETTINGS BASED ON FLAGS
# =============================================================================
apply_mode_settings() {
  if [[ "$FAST_MODE" == true ]]; then
    log_info "Fast mode enabled — reducing threads and depth."
    HTTPX_THREADS=25
    HTTPX_RATE=50
    KATANA_DEPTH=2
    KATANA_CONCURRENCY=5
    HAKRAWLER_DEPTH=2
    GAU_THREADS=3
    NMAP_TIMING=3
  fi

  if [[ "$DEEP_MODE" == true ]]; then
    log_info "Deep mode enabled — increasing depth and coverage."
    HTTPX_THREADS=100
    HTTPX_RATE=300
    KATANA_DEPTH=5
    KATANA_CONCURRENCY=20
    HAKRAWLER_DEPTH=5
    GAU_THREADS=10
    NMAP_TIMING=4
  fi
}

# =============================================================================
# SECTION 9: SUBDOMAIN ENUMERATION
# Uses subfinder and assetfinder — passive, no brute force
# =============================================================================
phase_subdomains() {
  log_phase "Phase 1 — Subdomain Enumeration"
  touch "$SUBS_RAW"
  local target_regex
  target_regex="$(escape_ere "$TARGET")"

  # --- subfinder ---
  log_info "Running subfinder..."
  if subfinder -d "$TARGET" -silent -o "$TEMP_SUBFINDER_OUT" 2>/dev/null; then
    cat "$TEMP_SUBFINDER_OUT" >> "$SUBS_RAW"
    log_success "subfinder: $(wc -l < "$TEMP_SUBFINDER_OUT" | tr -d ' ') subdomains found"
  else
    log_warn "subfinder encountered an error or returned no results. Continuing..."
  fi

  # --- assetfinder ---
  log_info "Running assetfinder..."
  if assetfinder --subs-only "$TARGET" 2>/dev/null > "$TEMP_ASSETFINDER_OUT"; then
    cat "$TEMP_ASSETFINDER_OUT" >> "$SUBS_RAW"
    log_success "assetfinder: $(wc -l < "$TEMP_ASSETFINDER_OUT" | tr -d ' ') subdomains found"
  else
    log_warn "assetfinder encountered an error or returned no results. Continuing..."
  fi

  # --- Deduplicate ---
  log_info "Deduplicating subdomains..."
  sort -u "$SUBS_RAW" | grep -E "(^|\\.)${target_regex}$" > "$SUBS_FILE" || true
  # Also include the root domain itself
  echo "$TARGET" >> "$SUBS_FILE"
  sort -u "$SUBS_FILE" -o "$SUBS_FILE"

  local count
  count=$(wc -l < "$SUBS_FILE" | tr -d ' ')
  log_success "Total unique subdomains after dedup: ${BOLD}$count${RESET}"
}

# =============================================================================
# SECTION 10: LIVE HOST PROBING
# httpx checks which subdomains respond over HTTP/HTTPS
# =============================================================================
phase_live_hosts() {
  log_phase "Phase 2 — Probing Live Hosts"

  if [[ ! -s "$SUBS_FILE" ]]; then
    log_warn "No subdomains found, skipping live host probe."
    return
  fi

  log_info "Running httpx (threads: $HTTPX_THREADS, rate: $HTTPX_RATE)..."
  if httpx \
    -l "$SUBS_FILE" \
    -silent \
    -threads "$HTTPX_THREADS" \
    -rate-limit "$HTTPX_RATE" \
    -follow-redirects \
    -status-code \
    -title \
    -tech-detect \
    -o "$LIVE_FILE" 2>/dev/null; then
    local count
    count=$(wc -l < "$LIVE_FILE" | tr -d ' ')
    log_success "Live hosts found: ${BOLD}$count${RESET}"
  else
    log_warn "httpx encountered an issue. Continuing with any partial results."
  fi
}

# =============================================================================
# SECTION 11: PORT SCANNING
# nmap with conservative timing — no aggressive/intrusive scans
# =============================================================================
phase_port_scan() {
  log_phase "Phase 3 — Port Scanning (nmap)"

  if [[ ! -s "$LIVE_FILE" ]]; then
    log_warn "No live hosts, skipping port scan."
    return
  fi

  # Extract hostnames only (strip protocol and status info from httpx output)
  local hosts_file="$OUTPUT_DIR/live_hosts_clean.txt"
  grep -oE 'https?://[^ ]+' "$LIVE_FILE" | sed -E 's|https?://||' | sed 's|/.*||' | sort -u > "$hosts_file" || true

  local host_count
  host_count=$(wc -l < "$hosts_file" | tr -d ' ')
  log_info "Scanning $host_count hosts with nmap (timing: T${NMAP_TIMING})..."

  # Common web-relevant ports only — not a full port sweep
  # -Pn: skip host discovery (already confirmed live via httpx)
  # --open: show only open ports
  # No -sV or script scans to keep it light
  if nmap \
    -T"$NMAP_TIMING" \
    -Pn \
    --open \
    -p 80,81,443,800,8000,8008,8080,8081,8443,8888,9000,9090,3000,4000,5000,6379,27017 \
    -iL "$hosts_file" \
    -oN "$PORTS_FILE" 2>/dev/null; then
    log_success "Port scan complete. Results saved to ports.txt"
  else
    log_warn "nmap encountered an error. Continuing..."
  fi
}

# =============================================================================
# SECTION 12: URL COLLECTION WITH GAU
# Fetches historical/known URLs from Wayback, OTX, Common Crawl etc.
# Entirely passive — no active crawling
# =============================================================================
phase_gau() {
  log_phase "Phase 4 — URL Collection (gau)"

  log_info "Fetching URLs from gau (threads: $GAU_THREADS, timeout: ${TOOL_TIMEOUT_SECONDS}s)..."
  if run_with_timeout "$TOOL_TIMEOUT_SECONDS" gau \
    --threads "$GAU_THREADS" \
    --subs \
    --providers wayback,commoncrawl,otx \
    "$TARGET" \
    > "$URLS_GAU" 2>/dev/null; then
    local count
    count=$(wc -l < "$URLS_GAU" | tr -d ' ')
    log_success "gau URLs collected: ${BOLD}$count${RESET}"
  else
    log_warn "gau encountered an error or returned no results. Continuing..."
    touch "$URLS_GAU"
  fi
}

# =============================================================================
# SECTION 13: CRAWLING WITH KATANA
# Active crawl of live hosts — rate-limited and non-destructive
# =============================================================================
phase_katana() {
  log_phase "Phase 5 — Crawling (katana)"

  if [[ ! -s "$LIVE_FILE" ]]; then
    log_warn "No live hosts, skipping katana crawl."
    touch "$URLS_KATANA"
    return
  fi

  # Extract URLs from live.txt for katana input
  local live_urls="$OUTPUT_DIR/live_urls_only.txt"
  grep -oE 'https?://[^ ]+' "$LIVE_FILE" | awk '{print $1}' | sort -u > "$live_urls" || true

  log_info "Running katana (depth: $KATANA_DEPTH, concurrency: $KATANA_CONCURRENCY, timeout: ${TOOL_TIMEOUT_SECONDS}s)..."
  if run_with_timeout "$TOOL_TIMEOUT_SECONDS" katana \
    -list "$live_urls" \
    -depth "$KATANA_DEPTH" \
    -concurrency "$KATANA_CONCURRENCY" \
    -rate-limit 50 \
    -silent \
    -no-color \
    -o "$URLS_KATANA" 2>/dev/null; then
    local count
    count=$(wc -l < "$URLS_KATANA" | tr -d ' ')
    log_success "katana URLs crawled: ${BOLD}$count${RESET}"
  else
    log_warn "katana encountered an error. Continuing..."
    touch "$URLS_KATANA"
  fi
}

# =============================================================================
# SECTION 14: CRAWLING WITH HAKRAWLER
# Secondary crawler for additional coverage
# =============================================================================
phase_hakrawler() {
  log_phase "Phase 6 — Crawling (hakrawler)"

  if [[ ! -s "$LIVE_FILE" ]]; then
    log_warn "No live hosts, skipping hakrawler crawl."
    touch "$URLS_HAKRAWLER"
    return
  fi

  local live_urls="$OUTPUT_DIR/live_urls_only.txt"

  log_info "Running hakrawler (depth: $HAKRAWLER_DEPTH, timeout: ${TOOL_TIMEOUT_SECONDS}s)..."
  # hakrawler reads from stdin; feed the live URLs list directly
  if run_with_timeout "$TOOL_TIMEOUT_SECONDS" hakrawler \
    -d "$HAKRAWLER_DEPTH" \
    -subs \
    < "$live_urls" \
    > "$URLS_HAKRAWLER" 2>/dev/null; then
    local count
    count=$(wc -l < "$URLS_HAKRAWLER" | tr -d ' ')
    log_success "hakrawler URLs crawled: ${BOLD}$count${RESET}"
  else
    log_warn "hakrawler encountered an error. Continuing..."
    touch "$URLS_HAKRAWLER"
  fi
}

# =============================================================================
# SECTION 15: URL DEDUPLICATION & ANALYSIS
# Combines all URL sources, deduplicates, then extracts interesting subsets
# =============================================================================
phase_url_analysis() {
  log_phase "Phase 7 — URL Deduplication & Analysis"

  # Combine all URL sources
  log_info "Combining URLs from gau, katana, hakrawler..."
  cat "$URLS_GAU" "$URLS_KATANA" "$URLS_HAKRAWLER" 2>/dev/null | sort -u > "$ALL_URLS"
  local total
  total=$(wc -l < "$ALL_URLS" | tr -d ' ')
  log_success "Total unique URLs: ${BOLD}$total${RESET}"

  # --- Extract URLs with query parameters ---
  log_info "Extracting parameterized URLs..."
  grep '?' "$ALL_URLS" | sort -u > "$PARAMS_FILE" || true
  local params_count
  params_count=$(wc -l < "$PARAMS_FILE" | tr -d ' ')
  log_success "URLs with parameters: ${BOLD}$params_count${RESET}"

  # --- Extract interesting endpoints ---
  log_info "Extracting interesting endpoints (api, admin, login, auth, debug, ...)..."
  grep -iE "$INTERESTING_KEYWORDS" "$ALL_URLS" | sort -u > "$INTERESTING_FILE" || true
  local interesting_count
  interesting_count=$(wc -l < "$INTERESTING_FILE" | tr -d ' ')
  log_success "Interesting endpoints: ${BOLD}$interesting_count${RESET}"

  # --- Extract JavaScript files ---
  log_info "Extracting JavaScript file URLs..."
  grep -iE '\.js(\?|$)' "$ALL_URLS" | sort -u > "$JS_FILE" || true
  local js_count
  js_count=$(wc -l < "$JS_FILE" | tr -d ' ')
  log_success "JavaScript files found: ${BOLD}$js_count${RESET}"
}

# =============================================================================
# SECTION 16: NUCLEI SCAN (OPTIONAL)
# Uses only safe/default templates — no exploit or DOS templates
# =============================================================================
phase_nuclei() {
  log_phase "Phase 8 — Nuclei Scan (optional)"

  if [[ "$RUN_NUCLEI" == false ]]; then
    log_skip "Nuclei scan disabled via --no-nuclei flag."
    touch "$NUCLEI_FILE"
    return
  fi

  if [[ ! -s "$LIVE_FILE" ]]; then
    log_warn "No live hosts available for nuclei scan."
    touch "$NUCLEI_FILE"
    return
  fi

  local live_urls="$OUTPUT_DIR/live_urls_only.txt"

  log_info "Running nuclei with safe/default templates only (timeout: ${TOOL_TIMEOUT_SECONDS}s)..."
  log_warn "Only using tags: exposure,config,info,tech — NO exploit templates."

  # Deliberately conservative template selection:
  # - exposure: exposed files/configs
  # - config: misconfiguration detection
  # - info: technology fingerprinting
  # - tech: technology detection
  # Rate-limited to 50 req/s; -bulk-size and -concurrency kept low
  if run_with_timeout "$TOOL_TIMEOUT_SECONDS" nuclei \
    -l "$live_urls" \
    -tags "exposure,config,info,tech" \
    -severity "info,low,medium" \
    -rate-limit 50 \
    -bulk-size 10 \
    -concurrency 5 \
    -silent \
    -no-color \
    -o "$NUCLEI_FILE" 2>/dev/null; then
    local count
    count=$(wc -l < "$NUCLEI_FILE" | tr -d ' ')
    log_success "Nuclei findings: ${BOLD}$count${RESET}"
  else
    log_warn "Nuclei encountered an error or found nothing. Continuing..."
    touch "$NUCLEI_FILE"
  fi
}

# =============================================================================
# SECTION 17: SUMMARY REPORT
# Prints and saves a final summary of findings
# =============================================================================
phase_summary() {
  log_phase "Recon Complete — Summary"

  local subs_count live_count total_urls params_count js_count nuclei_count

  subs_count=$(wc -l < "$SUBS_FILE"       2>/dev/null | tr -d ' ' || echo 0)
  live_count=$(wc -l < "$LIVE_FILE"       2>/dev/null | tr -d ' ' || echo 0)
  total_urls=$(wc -l < "$ALL_URLS"        2>/dev/null | tr -d ' ' || echo 0)
  params_count=$(wc -l < "$PARAMS_FILE"   2>/dev/null | tr -d ' ' || echo 0)
  js_count=$(wc -l < "$JS_FILE"           2>/dev/null | tr -d ' ' || echo 0)
  nuclei_count=$(wc -l < "$NUCLEI_FILE"   2>/dev/null | tr -d ' ' || echo 0)

  # Write to summary file
  {
    echo "======================================================"
    echo " RECON SUMMARY — $TARGET"
    echo " Generated: $(date)"
    echo "======================================================"
    echo ""
    echo "  Target              : $TARGET"
    echo "  Output Directory    : $OUTPUT_DIR"
    echo ""
    echo "  Subdomains found    : $subs_count"
    echo "  Live hosts          : $live_count"
    echo "  Total URLs          : $total_urls"
    echo "  Parameterized URLs  : $params_count"
    echo "  JavaScript files    : $js_count"
    echo "  Nuclei findings     : $nuclei_count"
    echo ""
    echo "  Output Files:"
    echo "  ├── subs.txt          Unique subdomains"
    echo "  ├── live.txt          Live HTTP hosts (httpx)"
    echo "  ├── ports.txt         nmap port scan results"
    echo "  ├── urls_gau.txt      Historical URLs (gau)"
    echo "  ├── urls_katana.txt   Crawled URLs (katana)"
    echo "  ├── urls_hakrawler.txt Crawled URLs (hakrawler)"
    echo "  ├── all_urls.txt      All unique combined URLs"
    echo "  ├── params.txt        URLs with query parameters"
    echo "  ├── interesting.txt   Interesting endpoints"
    echo "  ├── js.txt            JavaScript file URLs"
    echo "  ├── nuclei.txt        Nuclei scan findings"
    echo "  ├── summary.txt       This summary"
    echo "  └── recon.log         Full log of this run"
    echo "======================================================"
  } > "$SUMMARY_FILE"

  # Also print to terminal with colors
  echo ""
  echo -e "${MAGENTA}${BOLD}  ╔══════════════════════════════════════════════════╗${RESET}"
  echo -e "${MAGENTA}${BOLD}  ║           RECON SUMMARY — $TARGET${RESET}"
  echo -e "${MAGENTA}${BOLD}  ╚══════════════════════════════════════════════════╝${RESET}"
  echo ""
  echo -e "  ${CYAN}Subdomains found   :${RESET} ${BOLD}$subs_count${RESET}"
  echo -e "  ${CYAN}Live hosts         :${RESET} ${BOLD}$live_count${RESET}"
  echo -e "  ${CYAN}Total URLs         :${RESET} ${BOLD}$total_urls${RESET}"
  echo -e "  ${CYAN}Parameterized URLs :${RESET} ${BOLD}$params_count${RESET}"
  echo -e "  ${CYAN}JavaScript files   :${RESET} ${BOLD}$js_count${RESET}"
  echo -e "  ${CYAN}Nuclei findings    :${RESET} ${BOLD}$nuclei_count${RESET}"
  echo ""
  echo -e "  ${GREEN}${BOLD}Output folder: $OUTPUT_DIR${RESET}"
  echo ""
  log_success "Full log saved to: $LOG_FILE"
  log_success "Summary saved to:  $SUMMARY_FILE"
  echo ""
}

# =============================================================================
# SECTION 18: MAIN EXECUTION FLOW
# =============================================================================
main() {
  banner
  parse_args "$@"
  validate_domain

  # Conditionally require nuclei — only when --no-nuclei was NOT passed
  if [[ "$RUN_NUCLEI" == true ]]; then
    REQUIRED_TOOLS+=(nuclei)
  fi

  check_tools
  setup_output
  resolve_timeout_bin
  TEMP_SUBFINDER_OUT="$(mktemp "/tmp/recon-subfinder-${TARGET//./-}.XXXXXX")"
  TEMP_ASSETFINDER_OUT="$(mktemp "/tmp/recon-assetfinder-${TARGET//./-}.XXXXXX")"
  trap cleanup_temp_files EXIT

  # Re-define output file paths after OUTPUT_DIR is known
  SUBS_RAW="$OUTPUT_DIR/subs_raw.txt"
  SUBS_FILE="$OUTPUT_DIR/subs.txt"
  LIVE_FILE="$OUTPUT_DIR/live.txt"
  PORTS_FILE="$OUTPUT_DIR/ports.txt"
  URLS_GAU="$OUTPUT_DIR/urls_gau.txt"
  URLS_KATANA="$OUTPUT_DIR/urls_katana.txt"
  URLS_HAKRAWLER="$OUTPUT_DIR/urls_hakrawler.txt"
  ALL_URLS="$OUTPUT_DIR/all_urls.txt"
  PARAMS_FILE="$OUTPUT_DIR/params.txt"
  INTERESTING_FILE="$OUTPUT_DIR/interesting.txt"
  JS_FILE="$OUTPUT_DIR/js.txt"
  NUCLEI_FILE="$OUTPUT_DIR/nuclei.txt"
  SUMMARY_FILE="$OUTPUT_DIR/summary.txt"
  LOG_FILE="$OUTPUT_DIR/recon.log"

  # NOW it's safe to tee — LOG_FILE points inside the created output directory
  exec > >(tee -a "$LOG_FILE") 2>&1

  apply_mode_settings

  if [[ -n "$TIMEOUT_BIN" ]]; then
    log_info "Timeout protection enabled via $(basename "$TIMEOUT_BIN") (${TOOL_TIMEOUT_SECONDS}s per guarded tool)."
  else
    log_warn "No timeout binary found. Install coreutils for gtimeout on macOS to enable hang protection."
  fi

  echo ""
  echo -e "${YELLOW}${BOLD}  ⚠  REMINDER: Only run against domains you are authorized to test.${RESET}"
  echo ""

  # Run all phases — each phase handles its own errors and continues gracefully
  phase_subdomains
  phase_live_hosts
  phase_port_scan
  phase_gau
  phase_katana
  phase_hakrawler
  phase_url_analysis
  phase_nuclei
  phase_summary
}

main "$@"
