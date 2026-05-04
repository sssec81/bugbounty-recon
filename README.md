# Bug Bounty Recon Automation (`recon.sh`)

Automated passive/light-active recon workflow for authorized bug bounty targets.

This script is designed to:
- enumerate subdomains
- probe live HTTP hosts
- run conservative port scans
- collect and crawl URLs
- extract useful URL subsets
- optionally run a safe nuclei pass

It does **not** perform brute force, exploitation, or destructive actions.

## Quick Start

```bash
./setup-recon.sh
# open a new terminal (or source your rc file)
./recon.sh --help
./recon.sh --fast example.com
```

## Setup Options

```bash
# Default (latest tool versions)
./setup-recon.sh

# Pin specific versions (with or without '@')
NUCLEI_VERSION=v3.2.0 HTTPX_VERSION=@v1.3.5 ./setup-recon.sh

# CI-style reproducible setup
env SUBFINDER_VERSION=@v2.6.0 NUCLEI_VERSION=@v3.2.0 ./setup-recon.sh
```

## Usage

```bash
./recon.sh [OPTIONS] <target.com>
```

### Options

- `--no-nuclei` Skip nuclei scanning
- `--fast` Lower depth/threading for quicker runs
- `--deep` Increase depth/threading for broader coverage
- `--verbose` Show stderr from tools (debug mode)
- `--sequential` Run URL collection/crawling phases sequentially (lower request burst)
- `--config FILE` Load shared JSON config (rate limits, depths, keyword regex, ports)
- `--dry-run` Validate arguments and tools, then print planned execution without recon network phases
- `--json` Write machine-readable `summary.json` for CI parsing
- `--version` Print script version
- `--help` Show help

### Examples

```bash
./recon.sh example.com
./recon.sh --no-nuclei example.com
./recon.sh --fast example.com
./recon.sh --deep example.com
./recon.sh --config team-config.json --json example.com
./recon.sh --dry-run --config team-config.json example.com
```

### Config File Example

```json
{
  "httpx_threads": 40,
  "httpx_rate": 120,
  "katana_depth": 3,
  "katana_concurrency": 8,
  "hakrawler_depth": 3,
  "hakrawler_xargs_parallel": 4,
  "gau_threads": 5,
  "nmap_timing": 3,
  "tool_timeout_seconds": 300,
  "nmap_ports": "80,443,8080,8443",
  "interesting_keywords": "api|admin|login|auth|debug|token|config"
}
```

Config notes:
- Integer fields in config (threads/rates/depth/concurrency/timing/timeout) must be positive integers; invalid values are ignored with a warning.
- `--fast` / `--deep` are applied after config load, so those mode flags override overlapping config values.

## Requirements

Required tools:
- `subfinder`
- `assetfinder`
- `httpx`
- `gau`
- `hakrawler`
- `katana`
- `nmap`
- `nuclei` (only required when `--no-nuclei` is not used)

macOS install hints:

```bash
brew install nmap
brew install coreutils   # provides gtimeout on macOS

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

Add Go binaries to `PATH` if needed:

```bash
export PATH="$PATH:$HOME/go/bin"
```

## What It Does

`recon.sh` runs phases in this order:

1. Subdomain enumeration (`subfinder`, `assetfinder`)
2. Live host probing (`httpx`)
3. Port scan (`nmap`, conservative common web ports)
4. URL collection/crawling:
   - parallel by default: `gau`, `katana`, `hakrawler`
   - sequential if `--sequential` is passed
5. URL analysis (all URLs, params, interesting endpoints, JS URLs)
6. JavaScript download and analysis (`js_downloads`, `js_endpoints.txt`, `js_keywords.txt`)
7. Focused hunting output generation (`focused/*.txt`, priority/checklist files)
8. Optional nuclei scan (safe/default tags only)
9. Summary report generation

## Output

Each run creates:

```text
recon-<target>-<YYYYMMDD-HHMM>/
```

With files:
- `subs_raw.txt` Raw combined subdomain output
- `subs.txt` Deduplicated subdomains for target scope
- `live.txt` Live HTTP(S) hosts
- `ports.txt` nmap results
- `urls_gau.txt` Historical URLs
- `urls_katana.txt` Katana crawl URLs
- `urls_hakrawler.txt` Hakrawler crawl URLs
- `all_urls.txt` Combined deduplicated URLs
- `params.txt` URLs containing query strings
- `interesting.txt` URLs matching keywords (`api`, `admin`, `login`, etc.)
- `js.txt` JavaScript URL candidates (`.js`)
- `js_live.txt` Live JavaScript URLs (filtered via `httpx`)
- `js_downloads/` Downloaded live JavaScript files
- `js_endpoints.txt` Endpoint-like paths extracted from JavaScript
- `js_keywords.txt` Security-relevant JS keyword matches with file/line context
- `focused/auth.txt` Auth-related high-signal lines
- `focused/api.txt` API-related high-signal lines
- `focused/idor.txt` IDOR/multi-tenant identifier high-signal lines
- `focused/redirects.txt` Redirect/callback high-signal lines
- `focused/uploads.txt` Upload/download/import/export high-signal lines
- `focused/tokens-secrets.txt` Token/secret-related high-signal lines
- `focused/admin-debug.txt` Admin/debug/internal high-signal lines
- `focused/graphql.txt` GraphQL-related high-signal lines
- `focused/js-high-signal.txt` High-signal JS keyword lines
- `findings-priority.txt` Suggested priority hunting order and themes
- `manual-hunt-checklist.txt` Manual bug-hunting checklist
- `nuclei.txt` Nuclei findings (if enabled)
- `summary.txt` Final run summary
- `summary.json` Machine-readable summary (written when `--json` is passed)
- `recon.log` Full run log

## Safety and Scope Notes

- Only run against assets you are explicitly authorized to test.
- Script validates target domain format before running.
- Subdomain filtering is scope-aware and includes root + subdomains.
- Temporary subfinder/assetfinder files are created with `mktemp` and cleaned on exit.

## Timeout Protection

- Long-running tools are wrapped with a timeout guard (default `300` seconds per tool).
- Timeout coverage: `gau`, `katana`, `hakrawler`, `nuclei`.
- On Linux, `timeout` is used if available.
- On macOS, `gtimeout` (from `coreutils`) is used if available.
- If neither exists, the script still runs but without timeout enforcement.

## Parallel and Verbose Notes

- Default mode runs `gau`, `katana`, and `hakrawler` in parallel for speed.
- Use `--sequential` if a target is sensitive to request bursts/rate limits.
- `--verbose` reveals tool stderr; default mode suppresses noisy stderr while keeping phase-level warnings.
- Progress output auto-adjusts bar width to terminal size (with safe min/max bounds) for cleaner display in split panes and CI logs.

## Authorization Reminder

This project is for legal and authorized security testing workflows only.
