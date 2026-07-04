# Changelog

All notable changes to **Sift** (formerly **Flock-It**, renamed 2026-07-03) will be documented in this file. Entries before the rename refer to the tool by its former name.

---

### Planned / To-Do
- Passive Recon: WHOIS and DNS record lookups with parser integration.
- Wire `--auto-plugin` into the active scan loop so uncovered ports trigger candidate generation automatically (generation entry point exists, quarantined by default, but isn't yet auto-triggered mid-scan).
- Active web/HTTP probing phase for `web_scope.txt` targets.

---

## [0.7.0] - 2026-07-03 (Unreleased)

### Renamed
- Project renamed from **Flock-It** to **Sift** — `flockit.py` is now `sift.py`, `flockit.png` is now `sift.png`.
- Internal modules renamed from bird-themed to purpose-descriptive names: `raven.py`→`scanner.py` (`Raven`→`Scanner`), `owl.py`→`reporter.py` (`Owl`→`Reporter`), `magpie.py`→`plugin_manager.py` (`Magpie`→`PluginManager`), `kea.py`→`ai_prompts.py`, `kestrel.py`→`cve_lookup.py`, `harrier.py`→`correlation.py`. `preflight.py`, `adaptive.py`, and `plugin_validator.py` were already descriptive and are unchanged.

### Added
- **Adaptive scanning**: `--scan-mode adaptive` (new default) quick-scans every host, then escalates specific hosts to a deeper nmap pass based on high-value ports, notable version signatures, plugin opt-in, and peer-subnet influence (`modules/adaptive.py`).
- **CVE-backed vulnerability matching**: deterministic service/version-to-CVE matching against the NVD CVE API 2.0, preferring nmap's own CPE data for precision, with a local per-project sqlite cache (`modules/cve_lookup.py`). Replaces the previously dead/unwired `cve.circl.lu` lookup code.
- **Cross-host correlation**: a new "Top Findings" report section ranks repeated CVEs, shared vulnerable versions, and service overexposure across the whole engagement (`modules/correlation.py`), fully deterministic with optional AI narration on top of the top N findings.
- **Safer AI plugin generation**: generated plugins are now written to `modules/plugins_quarantine/` and statically validated (`modules/plugin_validator.py`, AST-based) — never auto-loaded. New `sift.py plugins list|show|approve|reject` subcommands manage the review workflow. The 5 pre-existing AI-generated plugins were retroactively quarantined pending review.
- Provider-neutral `AIClient` (`utils/ai_client.py`) used consistently for per-port analysis, plugin generation, and finding narration — `default_ai_provider=openai` now actually takes effect everywhere, not just plugin generation.
- `settings.example.xml` documenting the full settings schema, including new `<CVE>`/`<AdaptiveScan>` blocks.
- `--cve-source`, `--nvd-api-key`, `--top-findings` CLI flags.

### Changed
- **Architecture**: replaced the mutable module-level globals (`AUTO`, `CUSTOM_SETTINGS`, `SCAN_RESULTS`) with explicit `Config`/`ProjectContext` objects threaded through every phase, and loosely-shaped result dicts with a typed schema (`utils/models.py`: `PortResult`, `HostResult`, `ScanRun`, `Finding`). Scan/plugin file writes now go through `ArtifactStore` (`utils/artifacts.py`) instead of manual path-joining.
- `--mode` renamed to `--scan-mode {quick,full,adaptive}` (default changed from `quick` to `adaptive`).
- The preflight TCP-connect check is now explicitly advisory — nmap's active scan is always authoritative on port state; the report calls out the two only when they disagree.
- Report structure: Top Findings now leads the report, followed by a factual scan summary, then per-host detail (including a CVE Matches table per port). The old naive `generate_executive_summary` (service-count-only, no real risk signal) was removed.

### Fixed
- `prompt_recon`/the "continue anyway" prompt no longer pass a bool where a dict key was expected (only harmless before by accident).
- Removed a dead report code path that guessed artifact filenames from port dict keys, producing broken links.
- `setup_logging` is now actually invoked, so each project folder gets a `sift.log`; fixed a file-handle leak on repeated calls.

---

## [0.6.4] - 2025-04-10

### Added

- AI vulnerability summaries are now formatted using format_ai_summary() with PDF-safe wrapping.
- PDF generation now uses hard wrapping (72 chars) with no mid-word breaks.
- Final confirmation message "Auto mode complete. All steps finished." now shown when using --auto.
- Large project folders now compress correctly using zipfile.ZipFile(..., allowZip64=True).
- CUSTOM_SETTINGS["auto_mode"] is now set when --auto is passed.

### Improved

- Raw plugin_outputs["ai_recommendation"] blocks are no longer duplicated in the report.
- Markdown backticks, headings, and shell hints are removed or normalized in AI sections.
- SMB upload banner is now suppressed when in auto mode.

### Fixed

- Prevented silent hangs on --auto caused by waiting for SMB input.
- Cleaned up overspill and mid-word wrapping in PDF output.
- Ensured PDF-safe rendering of long command-line strings and recommendation headers.

## [0.6.3]

### Added
- **Plugin Auto-Generation**:
  - Magpie now uses Ollama to generate new plugins for uncovered services automatically.
  - Generated plugins inherit from `ScanPlugin` and include `should_run()` and `run()` methods.
  - Plugins are validated before being saved and reloaded dynamically.

- **Mode-Aware AUTO Flags**:
  - Refined `AUTO` config handling with more granular usage for automation (e.g., report viewing, plugin generation).

- **Improved AI Analysis**:
  - AI summaries are now inserted per host with better markdown formatting.
  - Fallback messages are included when analysis fails.

### Improved
- `Raven` now uses **multi-threaded scanning** via `ThreadPoolExecutor` for faster parallel port scanning across hosts.
- `Owl` generates richer markdown reports by including:
  - Plugin output blocks
  - Executive summaries
  - SSL scan and AI results per host

- Cross-platform compatibility improved when opening generated reports.

### Fixed
- Plugins generated by Magpie now reload immediately after generation, avoiding missed detections.
- `AUTO` dictionary use standardized to ensure correct behavior in all user prompts.
- Report generation now gracefully handles malformed scan results or missing data.

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
