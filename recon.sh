#!/usr/bin/env bash
# =============================================================================
# recon.sh — Bug Bounty Recon Automation Script
# Author   : Generated for authorized security testing only
# Platform : macOS Apple Silicon (arm64)
# Purpose  : Passive/light-active recon — NO exploits, NO brute force
# Usage    : ./recon.sh [OPTIONS] <target.com>
# =============================================================================

set -euo pipefail
SCRIPT_VERSION="1.3.0"
trap 'log_error "Script failed at line $LINENO"; exit 1' ERR

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
VERBOSE=false
SEQUENTIAL_MODE=false
DRY_RUN=false
JSON_OUTPUT=false
CONFIG_FILE=""
TARGET=""

# Rate limit defaults (requests per second / thread counts)
HTTPX_THREADS=50
HTTPX_RATE=150
KATANA_DEPTH=3
KATANA_CONCURRENCY=10
HAKRAWLER_DEPTH=3
HAKRAWLER_XARGS_PARALLEL=5
GAU_THREADS=5
NMAP_TIMING=3   # T3 = normal, not aggressive
NMAP_PORTS="80,81,443,800,8000,8008,8080,8081,8443,8888,9000,9090,3000,4000,5000,6379,27017"
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
  echo "  --verbose     Show tool stderr for debugging"
  echo "  --sequential  Run gau/katana/hakrawler sequentially (lower request burst)"
  echo "  --config FILE Load settings from a JSON config file"
  echo "  --dry-run     Validate args/tools and print plan without network phases"
  echo "  --json        Write machine-readable summary.json for CI integration"
  echo "  --version     Show script version"
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
      --version|-v)   echo "recon.sh version ${SCRIPT_VERSION}"; exit 0 ;;
      --no-nuclei)    RUN_NUCLEI=false; shift ;;
      --fast)         FAST_MODE=true; shift ;;
      --deep)         DEEP_MODE=true; shift ;;
      --verbose|-V)   VERBOSE=true; shift ;;
      --sequential)   SEQUENTIAL_MODE=true; shift ;;
      --dry-run)      DRY_RUN=true; shift ;;
      --json)         JSON_OUTPUT=true; shift ;;
      --config)
        if [[ $# -lt 2 ]]; then
          log_error "--config requires a file path argument."
          usage
        fi
        CONFIG_FILE="$2"
        shift 2
        ;;
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
JS_LIVE_FILE=""
JS_DOWNLOAD_DIR=""
JS_ENDPOINTS_FILE=""
JS_KEYWORDS_FILE=""
FOCUSED_DIR=""
FOCUSED_AUTH=""
FOCUSED_API=""
FOCUSED_IDOR=""
FOCUSED_REDIRECTS=""
FOCUSED_UPLOADS=""
FOCUSED_TOKENS=""
FOCUSED_ADMIN_DEBUG=""
FOCUSED_GRAPHQL=""
FOCUSED_JS_HIGH_SIGNAL=""
PRIORITY_FILE=""
MANUAL_CHECKLIST_FILE=""
NUCLEI_FILE=""
SUMMARY_FILE=""
SUMMARY_JSON_FILE=""
LOG_FILE=""
TEMP_SUBFINDER_OUT=""
TEMP_ASSETFINDER_OUT=""
TIMEOUT_BIN=""
EARLY_LOG_FILE=""

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

stderr_silence() {
  # Bash-specific note: this helper is used via process substitution (2> >(stderr_silence)).
  # Bash runs that substitution in a subshell and keeps this function available there.
  if [[ "$VERBOSE" == true ]]; then
    cat
  else
    cat >/dev/null
  fi
}

cleanup_temp_files() {
  rm -f "$TEMP_SUBFINDER_OUT" "$TEMP_ASSETFINDER_OUT" "$EARLY_LOG_FILE"
}

prepare_live_urls() {
  local live_urls="$OUTPUT_DIR/live_urls_only.txt"

  if [[ ! -s "$LIVE_FILE" ]]; then
    touch "$live_urls"
    return
  fi

  grep -oE 'https?://[^ ]+' "$LIVE_FILE" | awk '{print $1}' | sort -u > "$live_urls" || true
}

show_progress() {
  local current="$1"
  local total="$2"
  local label="$3"
  local width=$(( (${COLUMNS:-80} * 35) / 100 ))
  [[ "$width" -lt 20 ]] && width=20
  [[ "$width" -gt 50 ]] && width=50
  local filled=$((current * width / total))
  local empty=$((width - filled))
  local bar
  bar="$(printf '%*s' "$filled" '' | tr ' ' '#')$(printf '%*s' "$empty" '' | tr ' ' '-')"
  log_info "Progress [$bar] (${current}/${total}) ${label}"
}

load_config_file() {
  if [[ -z "$CONFIG_FILE" ]]; then
    return
  fi

  if [[ ! -f "$CONFIG_FILE" ]]; then
    log_error "Config file not found: $CONFIG_FILE"
    exit 1
  fi

  if ! command -v jq &>/dev/null; then
    log_error "--config requires jq. Install jq and try again."
    exit 1
  fi

  log_info "Loading config from: $CONFIG_FILE"

  local val
  local int_regex='^[0-9]+$'

  val="$(jq -r '.httpx_threads // empty' "$CONFIG_FILE")"
  if [[ -n "$val" ]]; then
    if [[ "$val" =~ $int_regex ]] && [[ "$val" -gt 0 ]]; then HTTPX_THREADS="$val"; else log_warn "Config: httpx_threads must be a positive integer, ignoring: '$val'"; fi
  fi
  val="$(jq -r '.httpx_rate // empty' "$CONFIG_FILE")"
  if [[ -n "$val" ]]; then
    if [[ "$val" =~ $int_regex ]] && [[ "$val" -gt 0 ]]; then HTTPX_RATE="$val"; else log_warn "Config: httpx_rate must be a positive integer, ignoring: '$val'"; fi
  fi
  val="$(jq -r '.katana_depth // empty' "$CONFIG_FILE")"
  if [[ -n "$val" ]]; then
    if [[ "$val" =~ $int_regex ]] && [[ "$val" -gt 0 ]]; then KATANA_DEPTH="$val"; else log_warn "Config: katana_depth must be a positive integer, ignoring: '$val'"; fi
  fi
  val="$(jq -r '.katana_concurrency // empty' "$CONFIG_FILE")"
  if [[ -n "$val" ]]; then
    if [[ "$val" =~ $int_regex ]] && [[ "$val" -gt 0 ]]; then KATANA_CONCURRENCY="$val"; else log_warn "Config: katana_concurrency must be a positive integer, ignoring: '$val'"; fi
  fi
  val="$(jq -r '.hakrawler_depth // empty' "$CONFIG_FILE")"
  if [[ -n "$val" ]]; then
    if [[ "$val" =~ $int_regex ]] && [[ "$val" -gt 0 ]]; then HAKRAWLER_DEPTH="$val"; else log_warn "Config: hakrawler_depth must be a positive integer, ignoring: '$val'"; fi
  fi
  val="$(jq -r '.hakrawler_xargs_parallel // empty' "$CONFIG_FILE")"
  if [[ -n "$val" ]]; then
    if [[ "$val" =~ $int_regex ]] && [[ "$val" -gt 0 ]]; then HAKRAWLER_XARGS_PARALLEL="$val"; else log_warn "Config: hakrawler_xargs_parallel must be a positive integer, ignoring: '$val'"; fi
  fi
  val="$(jq -r '.gau_threads // empty' "$CONFIG_FILE")"
  if [[ -n "$val" ]]; then
    if [[ "$val" =~ $int_regex ]] && [[ "$val" -gt 0 ]]; then GAU_THREADS="$val"; else log_warn "Config: gau_threads must be a positive integer, ignoring: '$val'"; fi
  fi
  val="$(jq -r '.nmap_timing // empty' "$CONFIG_FILE")"
  if [[ -n "$val" ]]; then
    if [[ "$val" =~ $int_regex ]] && [[ "$val" -gt 0 ]]; then NMAP_TIMING="$val"; else log_warn "Config: nmap_timing must be a positive integer, ignoring: '$val'"; fi
  fi
  val="$(jq -r '.tool_timeout_seconds // empty' "$CONFIG_FILE")"
  if [[ -n "$val" ]]; then
    if [[ "$val" =~ $int_regex ]] && [[ "$val" -gt 0 ]]; then TOOL_TIMEOUT_SECONDS="$val"; else log_warn "Config: tool_timeout_seconds must be a positive integer, ignoring: '$val'"; fi
  fi
  val="$(jq -r '.nmap_ports // empty' "$CONFIG_FILE")"; [[ -n "$val" ]] && NMAP_PORTS="$val"
  val="$(jq -r '.interesting_keywords // empty' "$CONFIG_FILE")"; [[ -n "$val" ]] && INTERESTING_KEYWORDS="$val"
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
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
    HAKRAWLER_XARGS_PARALLEL=3
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
    HAKRAWLER_XARGS_PARALLEL=8
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
  if subfinder -d "$TARGET" -silent -o "$TEMP_SUBFINDER_OUT" 2> >(stderr_silence); then
    cat "$TEMP_SUBFINDER_OUT" >> "$SUBS_RAW"
    log_success "subfinder: $(wc -l < "$TEMP_SUBFINDER_OUT" | tr -d ' ') subdomains found"
  else
    log_warn "subfinder encountered an error or returned no results. Continuing..."
  fi

  # --- assetfinder ---
  log_info "Running assetfinder..."
  if assetfinder --subs-only "$TARGET" > "$TEMP_ASSETFINDER_OUT" 2> >(stderr_silence); then
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
    -o "$LIVE_FILE" 2> >(stderr_silence); then
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

  if [[ "$host_count" -eq 0 ]]; then
    log_warn "No hosts extracted for nmap, skipping."
    touch "$PORTS_FILE"
    return
  fi

  # Common web-relevant ports only — not a full port sweep
  # -Pn: skip host discovery (already confirmed live via httpx)
  # --open: show only open ports
  # No -sV or script scans to keep it light
  if nmap \
    -T"$NMAP_TIMING" \
    -Pn \
    --open \
    -p "$NMAP_PORTS" \
    -iL "$hosts_file" \
    -oN "$PORTS_FILE" 2> >(stderr_silence); then
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
    > "$URLS_GAU" 2> >(stderr_silence); then
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

  local live_urls="$OUTPUT_DIR/live_urls_only.txt"

  log_info "Running katana (depth: $KATANA_DEPTH, concurrency: $KATANA_CONCURRENCY, timeout: ${TOOL_TIMEOUT_SECONDS}s)..."
  if run_with_timeout "$TOOL_TIMEOUT_SECONDS" katana \
    -list "$live_urls" \
    -depth "$KATANA_DEPTH" \
    -concurrency "$KATANA_CONCURRENCY" \
    -rate-limit 50 \
    -silent \
    -no-color \
    -o "$URLS_KATANA" 2> >(stderr_silence); then
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
  local hakrawler_targets="$OUTPUT_DIR/hakrawler_targets.txt"
  grep -oE 'https?://[^/]+' "$live_urls" | sed -E 's|https?://||' | sort -u > "$hakrawler_targets" || true

  if [[ ! -s "$hakrawler_targets" ]]; then
    log_warn "No hakrawler targets extracted, skipping hakrawler crawl."
    touch "$URLS_HAKRAWLER"
    return
  fi

  log_info "Running hakrawler (depth: $HAKRAWLER_DEPTH, timeout: ${TOOL_TIMEOUT_SECONDS}s)..."
  # Feed hostnames to hakrawler to avoid URL-format ambiguity across versions.
  if run_with_timeout "$TOOL_TIMEOUT_SECONDS" xargs -P "$HAKRAWLER_XARGS_PARALLEL" -I{} hakrawler \
    -d "$HAKRAWLER_DEPTH" \
    -subs \
    "{}" \
    < "$hakrawler_targets" \
    > "$URLS_HAKRAWLER" 2> >(stderr_silence); then
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
  # Note: For very large target datasets, consider:
  # sort -u -m "$URLS_GAU" "$URLS_KATANA" "$URLS_HAKRAWLER" > "$ALL_URLS"
  # when each input file is guaranteed to be pre-sorted.
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

  # --- Extract live JavaScript URLs ---
  if [[ -s "$JS_FILE" ]]; then
    log_info "Filtering live JavaScript URLs with httpx..."
    if httpx -l "$JS_FILE" -silent > "$JS_LIVE_FILE" 2> >(stderr_silence); then
      local js_live_count
      js_live_count=$(wc -l < "$JS_LIVE_FILE" | tr -d ' ')
      log_success "Live JavaScript URLs: ${BOLD}$js_live_count${RESET}"
    else
      log_warn "httpx JS live filtering encountered an issue. Continuing..."
      touch "$JS_LIVE_FILE"
    fi
  else
    touch "$JS_LIVE_FILE"
  fi
}

# =============================================================================
# SECTION 16: JAVASCRIPT DOWNLOAD & ANALYSIS
# Downloads live JavaScript files and extracts lightweight recon signals.
# =============================================================================
phase_js_analysis() {
  log_phase "Phase 8 — JavaScript Download & Analysis"

  mkdir -p "$JS_DOWNLOAD_DIR"
  : > "$JS_ENDPOINTS_FILE"
  : > "$JS_KEYWORDS_FILE"

  if [[ ! -s "$JS_LIVE_FILE" ]]; then
    log_warn "No live JavaScript URLs found, skipping JS download and analysis."
    return
  fi

  log_info "Downloading live JavaScript files into js_downloads/..."
  local url idx=0 success_count=0
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    idx=$((idx + 1))

    # Sanitize URL into a safe filename and add cksum to avoid collisions.
    local safe_base checksum out_file
    safe_base="$(printf '%s' "$url" | sed -E 's|^https?://||; s|[^a-zA-Z0-9._-]|_|g')"
    checksum="$(printf '%s' "$url" | cksum | awk '{print $1}')"
    out_file="$JS_DOWNLOAD_DIR/${idx}_${checksum}_${safe_base}.js"

    if run_with_timeout "$TOOL_TIMEOUT_SECONDS" curl -sL "$url" -o "$out_file" 2> >(stderr_silence); then
      success_count=$((success_count + 1))
    else
      log_warn "JS download failed: $url"
      rm -f "$out_file"
    fi
  done < "$JS_LIVE_FILE"
  log_success "JavaScript files downloaded: ${BOLD}$success_count${RESET}"

  # Extract endpoint-like paths from downloaded JS safely.
  log_info "Extracting endpoint-like paths from downloaded JavaScript..."
  grep -RhoE "[\"'][/][^\"' ]{3,}[\"']" "$JS_DOWNLOAD_DIR" 2>/dev/null \
    | tr -d "\"'" \
    | sort -u > "$JS_ENDPOINTS_FILE" || true
  local endpoints_count
  endpoints_count=$(wc -l < "$JS_ENDPOINTS_FILE" | tr -d ' ')
  log_success "JS endpoints extracted: ${BOLD}$endpoints_count${RESET}"

  # Extract security-relevant keyword matches from downloaded JS.
  log_info "Extracting security-relevant keyword matches from JavaScript..."
  local js_keyword_regex
  js_keyword_regex="api|token|organization|org|team|user|role|permission|control_plane|control-plane|gateway|service|route|consumer|vault|secret|billing|entitlement|graphql|auth|saml|oidc|redirect|csrf|jwt|jwks|apikey|api_key|client_id|client_secret"
  grep -RniE "$js_keyword_regex" "$JS_DOWNLOAD_DIR" \
    > "$JS_KEYWORDS_FILE" 2>/dev/null || true
  local keywords_count
  keywords_count=$(wc -l < "$JS_KEYWORDS_FILE" | tr -d ' ')
  log_success "JS keyword matches: ${BOLD}$keywords_count${RESET}"
}

# =============================================================================
# SECTION 17: FOCUSED HUNTING OUTPUTS
# Curates high-signal files for faster manual review workflows.
# =============================================================================
phase_focused_outputs() {
  log_phase "Phase 9 — Focused Hunting Outputs"

  mkdir -p "$FOCUSED_DIR"

  local combined="$OUTPUT_DIR/_combined_hunt_input.tmp"
  cat "$ALL_URLS" "$PARAMS_FILE" "$INTERESTING_FILE" "$JS_ENDPOINTS_FILE" "$JS_KEYWORDS_FILE" 2>/dev/null \
    | sort -u > "$combined"

  grep -iE "login|logout|signin|signup|register|auth|authenticate|authorize|oauth|oidc|saml|sso|session|csrf|callback" "$combined" \
    > "$FOCUSED_AUTH" || true

  grep -iE "/api/|api/v|graphql|rest|gateway|servicehub|konnect|kong-ui|v1|v2|v3" "$combined" \
    > "$FOCUSED_API" || true

  grep -iE "org|organization|team|user|member|role|permission|account|tenant|workspace|project|control_plane|control-plane|runtime_group|service_id|route_id|consumer_id|plugin_id|entity_id" "$combined" \
    > "$FOCUSED_IDOR" || true

  grep -iE "redirect|redirect_uri|return|return_to|next=|url=|continue|callback|logout" "$combined" \
    > "$FOCUSED_REDIRECTS" || true

  grep -iE "upload|file|import|export|download|attachment|avatar|logo|csv|yaml|yml|json|pdf" "$combined" \
    > "$FOCUSED_UPLOADS" || true

  grep -iE "token|secret|apikey|api_key|client_secret|client_id|jwt|jwks|bearer|credential|pat|service.account|service_account" "$combined" \
    > "$FOCUSED_TOKENS" || true

  grep -iE "admin|debug|dev|staging|sandbox|preview|internal|config|configuration|undefined|error|trace" "$combined" \
    > "$FOCUSED_ADMIN_DEBUG" || true

  grep -iE "graphql|graphiql|apollo|query|mutation|subscription" "$combined" \
    > "$FOCUSED_GRAPHQL" || true

  grep -iE "token|secret|organization|org|team|role|permission|control_plane|gateway|service|route|consumer|vault|billing|entitlement|auth|saml|oidc|redirect|csrf|jwt|jwks|client_id|client_secret" "$JS_KEYWORDS_FILE" \
    > "$FOCUSED_JS_HIGH_SIGNAL" || true

  {
    echo "PRIORITY HUNTING FILE — $TARGET"
    echo "Generated: $(date)"
    echo ""
    echo "Read these first:"
    echo "1. focused/idor.txt"
    echo "2. focused/tokens-secrets.txt"
    echo "3. focused/auth.txt"
    echo "4. focused/api.txt"
    echo "5. focused/admin-debug.txt"
    echo "6. focused/redirects.txt"
    echo "7. focused/js-high-signal.txt"
    echo ""
    echo "Top manual testing themes:"
    echo "- IDOR / cross-tenant access"
    echo "- role and permission bypass"
    echo "- token/service-account exposure"
    echo "- OAuth/OIDC redirect/state issues"
    echo "- stored XSS in names/descriptions/config fields"
    echo "- SSRF via webhook/upstream/proxy URL fields"
    echo "- undefined/null route behavior"
    echo ""
    echo "Suggested first commands:"
    echo "head -80 focused/idor.txt"
    echo "head -80 focused/tokens-secrets.txt"
    echo "head -80 focused/auth.txt"
    echo "head -80 focused/api.txt"
    echo "head -80 focused/js-high-signal.txt"
  } > "$PRIORITY_FILE"

  {
    echo "MANUAL HUNT CHECKLIST — $TARGET"
    echo ""
    echo "[ ] Create two test accounts/orgs if allowed"
    echo "[ ] Capture authenticated requests in Burp"
    echo "[ ] Identify org_id/team_id/user_id/control_plane_id/service_id/route_id"
    echo "[ ] Test read-only user vs admin user actions"
    echo "[ ] Test Account A object IDs in Account B session"
    echo "[ ] Check token pages/API responses for overexposure"
    echo "[ ] Review OAuth redirect_uri/state/nonce handling"
    echo "[ ] Review logout redirects"
    echo "[ ] Review upload/import/export surfaces"
    echo "[ ] Review JS endpoints and keyword context"
    echo "[ ] Stop immediately if you reach data not owned by your test accounts"
  } > "$MANUAL_CHECKLIST_FILE"

  rm -f "$combined"

  log_success "Focused hunting outputs written to: $FOCUSED_DIR"
  log_success "Priority file written to: $PRIORITY_FILE"
}

# =============================================================================
# SECTION 18: NUCLEI SCAN (OPTIONAL)
# Uses only safe/default templates — no exploit or DOS templates
# =============================================================================
phase_nuclei() {
  log_phase "Phase 10 — Nuclei Scan (optional)"

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
    -o "$NUCLEI_FILE" 2> >(stderr_silence); then
    local count
    count=$(wc -l < "$NUCLEI_FILE" | tr -d ' ')
    log_success "Nuclei findings: ${BOLD}$count${RESET}"
  else
    log_warn "Nuclei encountered an error or found nothing. Continuing..."
    touch "$NUCLEI_FILE"
  fi
}

# =============================================================================
# SECTION 19: SUMMARY REPORT
# Prints and saves a final summary of findings
# =============================================================================
phase_summary() {
  log_phase "Recon Complete — Summary"

  local subs_count live_count total_urls params_count js_count js_live_count js_endpoints_count js_keywords_count focused_auth_count focused_api_count focused_idor_count focused_tokens_count focused_js_signal_count nuclei_count

  subs_count=$(wc -l < "$SUBS_FILE"       2>/dev/null | tr -d ' ' || echo 0)
  live_count=$(wc -l < "$LIVE_FILE"       2>/dev/null | tr -d ' ' || echo 0)
  total_urls=$(wc -l < "$ALL_URLS"        2>/dev/null | tr -d ' ' || echo 0)
  params_count=$(wc -l < "$PARAMS_FILE"   2>/dev/null | tr -d ' ' || echo 0)
  js_count=$(wc -l < "$JS_FILE"           2>/dev/null | tr -d ' ' || echo 0)
  js_live_count=$(wc -l < "$JS_LIVE_FILE" 2>/dev/null | tr -d ' ' || echo 0)
  js_endpoints_count=$(wc -l < "$JS_ENDPOINTS_FILE" 2>/dev/null | tr -d ' ' || echo 0)
  js_keywords_count=$(wc -l < "$JS_KEYWORDS_FILE" 2>/dev/null | tr -d ' ' || echo 0)
  focused_auth_count=$(wc -l < "$FOCUSED_AUTH" 2>/dev/null | tr -d ' ' || echo 0)
  focused_api_count=$(wc -l < "$FOCUSED_API" 2>/dev/null | tr -d ' ' || echo 0)
  focused_idor_count=$(wc -l < "$FOCUSED_IDOR" 2>/dev/null | tr -d ' ' || echo 0)
  focused_tokens_count=$(wc -l < "$FOCUSED_TOKENS" 2>/dev/null | tr -d ' ' || echo 0)
  focused_js_signal_count=$(wc -l < "$FOCUSED_JS_HIGH_SIGNAL" 2>/dev/null | tr -d ' ' || echo 0)
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
    echo "  Live JavaScript URLs: $js_live_count"
    echo "  JS endpoints        : $js_endpoints_count"
    echo "  JS keyword matches  : $js_keywords_count"
    echo "  Focused auth lines  : $focused_auth_count"
    echo "  Focused api lines   : $focused_api_count"
    echo "  Focused idor lines  : $focused_idor_count"
    echo "  Focused token lines : $focused_tokens_count"
    echo "  Focused JS signal   : $focused_js_signal_count"
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
    echo "  ├── js_live.txt       Live JavaScript file URLs"
    echo "  ├── js_downloads/     Downloaded JavaScript files"
    echo "  ├── js_endpoints.txt  Endpoint-like paths from JavaScript"
    echo "  ├── js_keywords.txt   Security-relevant JavaScript keywords"
    echo "  ├── findings-priority.txt Priority hunting guide"
    echo "  ├── manual-hunt-checklist.txt Manual testing checklist"
    echo "  ├── focused/auth.txt  Auth-related lines"
    echo "  ├── focused/api.txt   API-related lines"
    echo "  ├── focused/idor.txt  IDOR-related lines"
    echo "  ├── focused/redirects.txt Redirect-related lines"
    echo "  ├── focused/uploads.txt Upload/download-related lines"
    echo "  ├── focused/tokens-secrets.txt Token/secret-related lines"
    echo "  ├── focused/admin-debug.txt Admin/debug-related lines"
    echo "  ├── focused/graphql.txt GraphQL-related lines"
    echo "  ├── focused/js-high-signal.txt High-signal JS keyword lines"
    echo "  ├── nuclei.txt        Nuclei scan findings"
    echo "  ├── summary.txt       This summary"
    echo "  ├── summary.json      Machine-readable summary (when --json is used)"
    echo "  └── recon.log         Full log of this run"
    echo "======================================================"
  } > "$SUMMARY_FILE"

  if [[ "$JSON_OUTPUT" == true ]]; then
    local json_target json_output_dir
    json_target="$(json_escape "$TARGET")"
    json_output_dir="$(json_escape "$OUTPUT_DIR")"
    {
      echo "{"
      echo "  \"target\": \"${json_target}\","
      echo "  \"generated_at\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
      echo "  \"output_directory\": \"${json_output_dir}\","
      echo "  \"counts\": {"
      echo "    \"subdomains\": ${subs_count},"
      echo "    \"live_hosts\": ${live_count},"
      echo "    \"total_urls\": ${total_urls},"
      echo "    \"parameterized_urls\": ${params_count},"
      echo "    \"javascript_files\": ${js_count},"
      echo "    \"live_javascript_urls\": ${js_live_count},"
      echo "    \"js_endpoints\": ${js_endpoints_count},"
      echo "    \"js_keyword_matches\": ${js_keywords_count},"
      echo "    \"focused_auth_lines\": ${focused_auth_count},"
      echo "    \"focused_api_lines\": ${focused_api_count},"
      echo "    \"focused_idor_lines\": ${focused_idor_count},"
      echo "    \"focused_token_lines\": ${focused_tokens_count},"
      echo "    \"focused_js_signal_lines\": ${focused_js_signal_count},"
      echo "    \"nuclei_findings\": ${nuclei_count}"
      echo "  }"
      echo "}"
    } > "$SUMMARY_JSON_FILE"
  fi

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
  echo -e "  ${CYAN}Live JS URLs       :${RESET} ${BOLD}$js_live_count${RESET}"
  echo -e "  ${CYAN}JS endpoints       :${RESET} ${BOLD}$js_endpoints_count${RESET}"
  echo -e "  ${CYAN}JS keyword matches :${RESET} ${BOLD}$js_keywords_count${RESET}"
  echo -e "  ${CYAN}Focused auth lines :${RESET} ${BOLD}$focused_auth_count${RESET}"
  echo -e "  ${CYAN}Focused api lines  :${RESET} ${BOLD}$focused_api_count${RESET}"
  echo -e "  ${CYAN}Focused idor lines :${RESET} ${BOLD}$focused_idor_count${RESET}"
  echo -e "  ${CYAN}Focused token lines:${RESET} ${BOLD}$focused_tokens_count${RESET}"
  echo -e "  ${CYAN}Focused JS signal  :${RESET} ${BOLD}$focused_js_signal_count${RESET}"
  echo -e "  ${CYAN}Nuclei findings    :${RESET} ${BOLD}$nuclei_count${RESET}"
  echo ""
  echo -e "  ${GREEN}${BOLD}Output folder: $OUTPUT_DIR${RESET}"
  echo ""
  log_success "Full log saved to: $LOG_FILE"
  log_success "Summary saved to:  $SUMMARY_FILE"
  if [[ "$JSON_OUTPUT" == true ]]; then
    log_success "JSON summary saved to: $SUMMARY_JSON_FILE"
  fi
  echo ""
}

# =============================================================================
# SECTION 20: MAIN EXECUTION FLOW
# =============================================================================
main() {
  parse_args "$@"
  load_config_file
  EARLY_LOG_FILE="$(mktemp "/tmp/recon-early-${TARGET//./-}.XXXXXX")"
  trap cleanup_temp_files EXIT
  exec > >(tee -a "$EARLY_LOG_FILE") 2>&1
  banner
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
  JS_LIVE_FILE="$OUTPUT_DIR/js_live.txt"
  JS_DOWNLOAD_DIR="$OUTPUT_DIR/js_downloads"
  JS_ENDPOINTS_FILE="$OUTPUT_DIR/js_endpoints.txt"
  JS_KEYWORDS_FILE="$OUTPUT_DIR/js_keywords.txt"
  FOCUSED_DIR="$OUTPUT_DIR/focused"
  FOCUSED_AUTH="$FOCUSED_DIR/auth.txt"
  FOCUSED_API="$FOCUSED_DIR/api.txt"
  FOCUSED_IDOR="$FOCUSED_DIR/idor.txt"
  FOCUSED_REDIRECTS="$FOCUSED_DIR/redirects.txt"
  FOCUSED_UPLOADS="$FOCUSED_DIR/uploads.txt"
  FOCUSED_TOKENS="$FOCUSED_DIR/tokens-secrets.txt"
  FOCUSED_ADMIN_DEBUG="$FOCUSED_DIR/admin-debug.txt"
  FOCUSED_GRAPHQL="$FOCUSED_DIR/graphql.txt"
  FOCUSED_JS_HIGH_SIGNAL="$FOCUSED_DIR/js-high-signal.txt"
  PRIORITY_FILE="$OUTPUT_DIR/findings-priority.txt"
  MANUAL_CHECKLIST_FILE="$OUTPUT_DIR/manual-hunt-checklist.txt"
  NUCLEI_FILE="$OUTPUT_DIR/nuclei.txt"
  SUMMARY_FILE="$OUTPUT_DIR/summary.txt"
  SUMMARY_JSON_FILE="$OUTPUT_DIR/summary.json"
  LOG_FILE="$OUTPUT_DIR/recon.log"

  # Preserve early output (banner/tool checks) so recon.log includes full run context.
  cat "$EARLY_LOG_FILE" > "$LOG_FILE"
  rm -f "$EARLY_LOG_FILE"
  EARLY_LOG_FILE=""

  # NOW it's safe to tee — LOG_FILE points inside the created output directory.
  exec > >(tee -a "$LOG_FILE") 2>&1

  apply_mode_settings

  if [[ -n "$TIMEOUT_BIN" ]]; then
    log_info "Timeout protection enabled via $(basename "$TIMEOUT_BIN") (${TOOL_TIMEOUT_SECONDS}s per guarded tool)."
  else
    log_error "No timeout binary found. Hang protection is disabled."
    log_error "Install GNU coreutils for gtimeout on macOS: brew install coreutils"
    log_warn "Continuing without timeout enforcement."
  fi

  echo ""
  echo -e "${YELLOW}${BOLD}  ⚠  REMINDER: Only run against domains you are authorized to test.${RESET}"
  echo ""

  if [[ "$DRY_RUN" == true ]]; then
    log_phase "Dry Run Complete — Validation & Planned Execution"
    log_success "Arguments validated and required tools are available."
    log_info "No recon network phases were executed because --dry-run is enabled."
    log_info "Target: $TARGET"
    log_info "Config file: ${CONFIG_FILE:-<none>}"
    log_info "JSON summary: $JSON_OUTPUT"
    log_info "Planned phase order: subdomains -> live_hosts -> port_scan -> gau/katana/hakrawler -> url_analysis -> js_analysis -> focused_outputs -> nuclei -> summary"
    return
  fi

  # Run all phases — each phase handles its own errors and continues gracefully
  show_progress 1 9 "Subdomain Enumeration"
  phase_subdomains
  show_progress 2 9 "Live Host Probing"
  phase_live_hosts
  prepare_live_urls
  show_progress 3 9 "Port Scanning"
  phase_port_scan

  if [[ "$SEQUENTIAL_MODE" == true ]]; then
    show_progress 4 9 "Sequential URL Collection & Crawling"
    log_phase "Phase 4-6 — Sequential URL Collection & Crawling"
    phase_gau
    phase_katana
    phase_hakrawler
  else
    show_progress 4 9 "Parallel URL Collection & Crawling"
    log_phase "Phase 4-6 — Parallel URL Collection & Crawling"
    # Background phase failures are handled in each phase (warn + fallback file).
    # The ERR trap is intended for unexpected parent-shell failures.
    phase_gau &
    local gau_pid=$!
    phase_katana &
    local katana_pid=$!
    phase_hakrawler &
    local hakrawler_pid=$!
    local parallel_failed=false
    for pid in "$gau_pid" "$katana_pid" "$hakrawler_pid"; do
      if ! wait "$pid"; then
        parallel_failed=true
      fi
    done
    if [[ "$parallel_failed" == true ]]; then
      log_warn "One or more parallel phases exited non-zero. Continuing with available results."
    fi
  fi
  show_progress 5 9 "URL Analysis"
  phase_url_analysis
  show_progress 6 9 "JavaScript Analysis"
  phase_js_analysis
  show_progress 7 9 "Focused Hunting Outputs"
  phase_focused_outputs
  show_progress 8 9 "Nuclei Scan"
  phase_nuclei
  show_progress 9 9 "Summary"
  phase_summary
}

main "$@"
