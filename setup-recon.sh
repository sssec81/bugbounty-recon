#!/usr/bin/env bash
# =============================================================================
# setup-recon.sh — One-time environment setup for recon.sh
# Platform: macOS (Homebrew) and Linux (limited best-effort)
# =============================================================================

set -euo pipefail

BOLD="\033[1m"
RESET="\033[0m"
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"

log_info()    { echo -e "${CYAN}[*]${RESET} $1"; }
log_success() { echo -e "${GREEN}[+]${RESET} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
log_error()   { echo -e "${RED}[x]${RESET} $1"; }

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" &>/dev/null; then
    log_error "Missing required command: $cmd"
    exit 1
  fi
}

detect_os() {
  case "$(uname -s)" in
    Darwin) echo "macos" ;;
    Linux)  echo "linux" ;;
    *)      echo "unknown" ;;
  esac
}

brew_install_if_missing() {
  local pkg="$1"
  if brew list "$pkg" &>/dev/null; then
    log_success "brew package already installed: $pkg"
  else
    log_info "Installing brew package: $pkg"
    brew install "$pkg"
  fi
}

go_install_if_missing() {
  local bin="$1"
  local module="$2"

  if command -v "$bin" &>/dev/null; then
    log_success "Go tool already installed: $bin"
  else
    log_info "Installing Go tool: $bin"
    go install "$module"
  fi
}

normalize_go_version() {
  local ver="$1"
  if [[ "$ver" == @* ]]; then
    echo "$ver"
  else
    echo "@$ver"
  fi
}

linux_package_hint() {
  if command -v apt &>/dev/null; then
    log_info "Debian/Ubuntu hint: sudo apt update && sudo apt install -y nmap coreutils"
  elif command -v dnf &>/dev/null; then
    log_info "Fedora/RHEL hint: sudo dnf install -y nmap coreutils"
  elif command -v yum &>/dev/null; then
    log_info "RHEL/CentOS hint: sudo yum install -y nmap coreutils"
  elif command -v pacman &>/dev/null; then
    log_info "Arch hint: sudo pacman -S --needed nmap coreutils"
  else
    log_info "Install nmap/coreutils using your distro package manager."
  fi
}

ensure_gobin_path() {
  local gobin_line='export PATH="$PATH:$HOME/go/bin"'
  local shell_name
  shell_name="${SHELL##*/}"

  local rc_files=()
  case "$shell_name" in
    zsh)  rc_files+=("$HOME/.zshrc") ;;
    bash) rc_files+=("$HOME/.bashrc" "$HOME/.bash_profile") ;;
    *)    rc_files+=("$HOME/.profile") ;;
  esac

  for rc in "${rc_files[@]}"; do
    touch "$rc"
    if grep -F "$gobin_line" "$rc" &>/dev/null; then
      log_success "PATH already configured in $rc"
    else
      printf '\n# Added by setup-recon.sh\n%s\n' "$gobin_line" >> "$rc"
      log_success "Added ~/go/bin PATH to $rc"
    fi
  done
}

main() {
  echo -e "${BOLD}Recon Environment Setup${RESET}"
  echo "This script performs one-time setup for recon.sh."
  echo ""

  local os
  os="$(detect_os)"

  if [[ "$os" == "unknown" ]]; then
    log_error "Unsupported OS: $(uname -s)"
    exit 1
  fi

  if [[ "$os" == "macos" ]]; then
    require_cmd brew
    log_info "Updating Homebrew metadata..."
    brew update

    brew_install_if_missing go
    brew_install_if_missing nmap
    brew_install_if_missing coreutils
  else
    log_warn "Linux detected: automatic package installation is limited."
    log_warn "Please ensure 'go', 'nmap', and 'timeout' are installed via your distro package manager."
    linux_package_hint
    require_cmd go
  fi

  require_cmd go
  ensure_gobin_path

  # Ensure current shell can locate newly installed Go binaries in this run.
  export PATH="$PATH:$HOME/go/bin"
  log_info "Go binaries are available in this current shell session."

  # Optional version pinning (defaults to @latest)
  local subfinder_ver
  local assetfinder_ver
  local httpx_ver
  local nuclei_ver
  local gau_ver
  local hakrawler_ver
  local katana_ver
  subfinder_ver="$(normalize_go_version "${SUBFINDER_VERSION:-@latest}")"
  assetfinder_ver="$(normalize_go_version "${ASSETFINDER_VERSION:-@latest}")"
  httpx_ver="$(normalize_go_version "${HTTPX_VERSION:-@latest}")"
  nuclei_ver="$(normalize_go_version "${NUCLEI_VERSION:-@latest}")"
  gau_ver="$(normalize_go_version "${GAU_VERSION:-@latest}")"
  hakrawler_ver="$(normalize_go_version "${HAKRAWLER_VERSION:-@latest}")"
  katana_ver="$(normalize_go_version "${KATANA_VERSION:-@latest}")"

  # Note: Module paths reflect upstream Go project structure; do not modify.
  go_install_if_missing subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder${subfinder_ver}"
  go_install_if_missing assetfinder "github.com/tomnomnom/assetfinder${assetfinder_ver}"
  go_install_if_missing httpx "github.com/projectdiscovery/httpx/cmd/httpx${httpx_ver}"
  go_install_if_missing nuclei "github.com/projectdiscovery/nuclei/v3/cmd/nuclei${nuclei_ver}"
  go_install_if_missing gau "github.com/lc/gau/v2/cmd/gau${gau_ver}"
  go_install_if_missing hakrawler "github.com/hakluke/hakrawler${hakrawler_ver}"
  go_install_if_missing katana "github.com/projectdiscovery/katana/cmd/katana${katana_ver}"

  echo ""
  log_success "Setup complete."
  log_info "Open a new terminal, then verify with:"
  echo "  subfinder -h >/dev/null && echo subfinder ok"
  echo "  httpx -h >/dev/null && echo httpx ok"
  echo "  nuclei -h >/dev/null && echo nuclei ok"
  echo ""
  log_info "You can now run:"
  echo "  ./recon.sh --fast example.com"
}

main "$@"
