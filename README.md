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

## Usage

```bash
./recon.sh [OPTIONS] <target.com>
```

### Options

- `--no-nuclei` Skip nuclei scanning
- `--fast` Lower depth/threading for quicker runs
- `--deep` Increase depth/threading for broader coverage
- `--help` Show help

### Examples

```bash
./recon.sh example.com
./recon.sh --no-nuclei example.com
./recon.sh --fast example.com
./recon.sh --deep example.com
```

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
4. Historical URL collection (`gau`)
5. Crawling (`katana`)
6. Crawling (`hakrawler`)
7. URL analysis (all URLs, params, interesting endpoints, JS URLs)
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
- `nuclei.txt` Nuclei findings (if enabled)
- `summary.txt` Final run summary
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

## Authorization Reminder

This project is for legal and authorized security testing workflows only.
