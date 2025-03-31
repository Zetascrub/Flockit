# Changelog

All notable changes to the **Flockit** will be documented in this file.

---

### Planned / To-Do
- Passive Recon: WHOIS and DNS record lookups with parser integration.
- Severity tagging and markdown colourisation in AI output.
- Potential project name change
- Move checks to the start of the script (Ollama, Nmap, etc)
---

## [0.6.2]

### Improved
- Replaced standard logging output in the terminal with `print_status()` for cleaner, user-friendly output.
  - Status levels use emojis and colors (e.g., ✅ success, ⚠️ warning, ❌ error).
  - Automatically logs to file while showing clean output in terminal.
- Added `print_banner()` to mark major script phases with styled headings.
- Suppressed duplicate console output by removing the `StreamHandler` from the logger setup.
- Streamlined messaging logic across internal modules (`PreFlightCheck`, `util.py`).
- Migrated settings to `settings.xml` for dynamic configuration (ports, timeout, SMB info, valid IP ranges).
- Modularised the codebase into themed components:
  - `PreFlight` (scope parsing, setup, SMB upload)
  - `RavenRecon` (active scanning with plugins)
  - `Owl` (markdown reporting & AI analysis)
- Plugins are now standalone files and can inherit from a base `ScanPlugin`.
- Plugin scanning now uses consistent output format and integrates with `raven.results`.

### Fixed
- Resolved terminal output duplication caused by combined logger and print calls.
- Fixed indentation and `cprint` argument bugs within the enhanced `print_status()` function.
- Corrected `getpass` usage to avoid `TypeError: 'module' object is not callable`.
- Plugins now load independently using safe dynamic import handling.
- Fixed `KeyError` on `nmap` scan results when hosts return no data.
- Prevented `UnboundLocalError` when skipping active recon or AI analysis.

### Added
- Full rewrite of `README.md` to reflect new modular structure.
- Added `demo.gif` terminal preview support.
- Introduced `Why Flockit?` section to explain the naming and vision behind the tool.

---

## [0.6.1]

### Added
- ASCII Network Visualisation with `--ascii` flag:
  - Groups hosts by /24 subnet
  - Displays open services next to each host
  - Terminal-friendly map layout

---

## [0.6.0]

### Added
- Refactored core functionality into modular classes: `PreFlightCheck`, `RavenRecon`, and `ReportGenerator`.
- Auto-generated executive summaries with scan stats and exposure highlights.
- Auto Mode support using `--auto` flag and unified yes/no prompt handler.
- AI vulnerability analysis decoupled from active scanning for post-processing flexibility.
- Enhanced reporting phase with markdown generation and summary injection.

---

## [0.5.1] - 2025-03-25

### Fixed
- Resolved terminal input visibility issue using `termios` and `atexit`.
- Adjusted prompt order to avoid hidden input during AI analysis.

### Improved
- Unified logging via the `logging` module across console and file outputs.
- Secure SMB password input using `getpass.getpass()`.

---

## [0.5.0]

### Added
- AI-powered vulnerability analysis via Ollama and LLaMA 3.
- Plugin architecture for extensible scan logic (`ScanPlugin` base class).
- Banner grabbing and basic CVE lookup via cve.circl.lu API.
- `RavenRecon` engine for modular active recon, scanning, and report generation.

---

## [0.4.0]

### Added
- Project folder compression to `.zip` archive.
- SMB upload updated to send compressed archive instead of raw folder content.

---

## [0.3.0]

### Added
- Auto-creation of `Screenshots/` and `Scan-Data/` folders in project directory.
- Remote upload path generation based on the project folder name.

---

## [0.2.0]

### Added
- `scope.txt` parser with output split into internal, external, and web scope files.
- SMB share upload support via Impacket `SMBConnection`.
- Terminal summary display and `summary.txt` generation.

---

## [0.1.0]

### Initial Release
- Basic port scanner using `socket` and optional `nmap`.
- Supports custom XML config for timeout, ports, and external IP URL.
- Classifies IPs by internal/external range.
- Outputs scan results to XML file format.
