# Changelog

## v1.3.0

- Added `--config FILE` support to centralize team-tunable settings from JSON:
  - thread/rate/depth/concurrency values
  - timeout seconds
  - nmap timing/ports
  - `INTERESTING_KEYWORDS`
- Added `--dry-run` mode to validate args/tools and show planned execution without running recon network phases.
- Added `--json` output mode to generate `summary.json` for CI and automation parsing.
- Added lightweight progress indicators across long-running phase flow for better interactive UX.
- Added config value hardening: positive-integer validation for numeric JSON config fields with warning-and-ignore behavior on invalid values.
- Improved progress bar UX by adapting width to terminal size with min/max bounds.

## v1.2.0

- Added early-run logging capture so `recon.log` includes banner and pre-output-dir phases.
- Added tunable hakrawler parallel fanout via `HAKRAWLER_XARGS_PARALLEL`.
- Added JavaScript analysis phase:
  - live JS download into `js_downloads/`
  - endpoint extraction into `js_endpoints.txt`
  - keyword extraction with file/line context into `js_keywords.txt`
- Added focused hunting phase with curated output files in `focused/`.
- Added `findings-priority.txt` and `manual-hunt-checklist.txt`.
- Expanded summary metrics and output inventory to include JS/focused artifacts.
- Added clearer timeout-missing guidance with explicit macOS `coreutils` installation hint.

## v1.1.0+

- Added `--verbose` mode to expose tool stderr when debugging.
- Added `--sequential` mode to disable parallel `gau`/`katana`/`hakrawler` execution.
- Added `prepare_live_urls` to avoid parallel dependency races on `live_urls_only.txt`.
- Added live JavaScript filtering output: `js_live.txt`.
- Added `--version` flag and centralized `SCRIPT_VERSION`.
- Added timeout wrapper (`timeout`/`gtimeout`) and temp-file cleanup trap.
- Added defensive nmap empty-host guard.
- Improved summary output to include live JS counts.
