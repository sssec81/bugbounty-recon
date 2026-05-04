# Changelog

## v1.1.0+

- Added `--verbose` mode to expose tool stderr when debugging.
- Added `--sequential` mode to disable parallel `gau`/`katana`/`hakrawler` execution.
- Added `prepare_live_urls` to avoid parallel dependency races on `live_urls_only.txt`.
- Added live JavaScript filtering output: `js_live.txt`.
- Added `--version` flag and centralized `SCRIPT_VERSION`.
- Added timeout wrapper (`timeout`/`gtimeout`) and temp-file cleanup trap.
- Added defensive nmap empty-host guard.
- Improved summary output to include live JS counts.
