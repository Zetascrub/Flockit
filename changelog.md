# Changelog

All notable changes to the **Pre-Flight Check Tool** will be documented in this file.

---

### Planned / To-Do
- Passive Recon: WHOIS and DNS record lookups with parser integration.
- Severity tagging and markdown colorization in AI output.
- Improve logging output, give a cleaner output of relavent data
- 

---

## [0.6.1] - In progress

### Added
- ASCII Network Visualisation with `--ascii` flag:
  - Groups hosts by /24 subnet
  - Displays open services next to each host
  - Terminal-friendly map layout

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
