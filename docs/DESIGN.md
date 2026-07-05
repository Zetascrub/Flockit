# Sift Design Document (formerly Flock-It)

Last reviewed: 2026-07-03
Reviewed from: post-rebuild — the "Suggested Target Architecture" and P0-P2 items from the 2026-07-02 review below have been implemented (Stages 0-6 of the rebuild). This document is kept for historical context; the "Current Implementation" section below describes the code as it exists now.

## Purpose

Sift (formerly Flock-It) is a command-line penetration testing workflow tool. It turns a root `scope.txt` file into scoped project artifacts, performs preflight reachability checks, runs active nmap-based host and service discovery (uniformly or adaptively), executes service plugins, matches services against real CVE data, correlates findings across the whole engagement, optionally asks an AI provider for per-port and cross-host narrative context, generates a markdown/PDF report, and can package/upload the project folder to SMB.

The current implementation is organized around bird-themed modules:

- `sift.py`: CLI entrypoint and pipeline orchestration, plus the `plugins` review subcommand group.
- `modules/preflight.py`: project setup, scope splitting, advisory preflight checks, XML/summary output, SMB packaging/upload.
- `modules/scanner.py`: active discovery/scanning (quick/full/adaptive two-phase), banner collection, plugin execution, AI analysis dispatch.
- `modules/adaptive.py`: `AdaptiveScanPlanner` — pure escalation-decision logic (no I/O).
- `modules/cve_lookup.py`: NVD CVE API 2.0 lookup client with a local sqlite cache (`CVELookupClient`, `CVECache`).
- `modules/correlation.py`: deterministic cross-host correlation (`correlate()`) and optional AI narration of the top findings (`narrate()`).
- `modules/plugin_manager.py`: plugin discovery/loading (trusted directory only), AI-generated plugin quarantine writer, and quarantine lifecycle helpers (list/approve/reject).
- `modules/plugin_validator.py`: AST-based static validation gate for AI-generated plugin code.
- `modules/reporter.py`: report generation.
- `modules/ai_prompts.py`: AI plugin-generation prompt building and AI summary markdown/PDF formatting.
- `utils/config.py`: `Config` and nested dataclasses (`AIProviderConfig`, `SMBConfig`, `CVEConfig`, `AdaptiveScanConfig`, `AutomationFlags`), loaded from XML + CLI overrides.
- `utils/context.py`: `ProjectContext` — the per-run object threaded through every phase instead of globals.
- `utils/artifacts.py`: `ArtifactStore`/`Artifact` — all scan/plugin file writes under a project root.
- `utils/models.py`: typed result schema (`PortResult`, `HostResult`, `ScanRun`, `CVEMatch`, `PreflightHint`, `Finding`).
- `utils/ai_client.py`: `AIClient` — the single provider-neutral (Ollama/OpenAI) AI entry point used everywhere AI is called.
- `utils/common.py`: settings XML parsing, prompts, logging/status output, dependency checks, PDF conversion, ASCII map helper.
- `modules/plugins/__init__.py`: base `ScanPlugin` contract (extended with optional escalation-vote return keys).

## Current Execution Flow

1. CLI parsing starts in `sift.py`.
   - `--settings`, `--project`, `--scan-mode`, `--output`, `--pdf`, `--ascii`, `--cve-source`, `--nvd-api-key`, `--top-findings`, verbosity, and automation flags are parsed (plus the `plugins` subcommand group, handled separately before any of the below).
   - `Config.load()` parses settings XML and layers CLI overrides into one `Config` object — no global settings dict.

2. Environment validation runs (`validate_environment()` — a lightweight banner/status print; full external IP validation is deferred to step 3, and only runs when external scope is present).

3. `ProjectContext.create()` builds the project folder, `ArtifactStore`, and per-project log file, then `PreFlight` runs:
   - Root `scope.txt` is copied into the project folder and split into `int_scope.txt`, `ext_scope.txt`, `web_scope.txt`.
   - External IP is fetched and validated against `valid_external_ranges` only if external scope is present; the result is cached on `ProjectContext.external_ip`.

4. Preflight reachability checks run (advisory only — see `PreflightHint` below).
   - For each scope file, entries are tagged as IP, URL, or unknown.
   - IP entries get a simple TCP connect check against configured common ports.
   - Results are written to `scan_results.xml` and `Pre-Flight-Summary.txt`, and stored as `PreflightHint`s for later merge onto scan results.

5. Active recon runs through `Scanner.scan_network()`:
   - `nmap -sn` discovery identifies live hosts.
   - Phase A: every live host gets a quick `-F` scan (or the configured quick/full args in non-adaptive mode).
   - Phase B (adaptive mode only): `AdaptiveScanPlanner.plan()` scores each host and escalates a subset to a deeper `-sV --version-all -sC [-O]` rescan, merging richer results back in.
   - Banner grabbing and plugin execution happen per port in both phases; all artifacts are written via `ArtifactStore`.

6. CVE matching runs (`modules/cve_lookup.py`) — deterministic, not gated on AI: each `PortResult` with a CPE (or service+version) is looked up against the NVD CVE API 2.0, with a local sqlite cache.

7. Cross-host correlation runs (`modules/correlation.py`) — `correlate()` produces ranked `Finding`s from the typed scan results (repeated CVEs, shared vulnerable versions, service overexposure, credential weakness signals from plugins). Fully deterministic.

8. Optional AI vulnerability analysis runs, gated on `--no-ai`/prompt/automation:
   - Each scanned port is sent to `AIClient.chat()` (Ollama or OpenAI per `config.ai.provider`); the response is stored as `PortResult.ai_recommendation`.
   - `correlation.narrate()` adds an AI-written explanation to the top N findings (`--top-findings`), never inventing new ones.

9. Reporting runs through `Reporter.generate_report()`:
   - A markdown report is generated: Top Findings, factual scan summary, then per-host tables (port/service/version/banner, CVE matches, AI recommendation, plugin output, artifacts).
   - CSV appendices are written beside the report for findings (`findings.csv`) and open services (`open_services.csv`).
   - If requested, markdown is converted to PDF with WeasyPrint.
   - The report is printed only if the view-report prompt/automation flag says yes; otherwise nothing further happens.

10. Packaging/upload runs — the project folder is zipped and uploaded to a configured or prompted SMB share unless `--no-upload` or automation says otherwise.

## Data Model

### Settings

`Config` (`utils/config.py`) is built by `Config.load(xml_path, cli_args)`, which parses the settings XML via `load_settings_xml` (kept in `utils/common.py` as the low-level XML→dict parser) and layers CLI overrides on top. Nested dataclasses:

- `AIProviderConfig`: `provider`, `ollama_host`, `ollama_model` (fast/default analysis model), `ollama_report_model` (final finding/report narration model), `openai_api_key`, `openai_model`, `openai_report_model`.
- `SMBConfig`: `server`, `share`, `username`.
- `CVEConfig`: `source` (`nvd`|`off`), `nvd_api_key`, `cache_ttl_days`, `request_timeout`.
- `AdaptiveScanConfig`: `escalation_threshold`, `peer_escalation_threshold`, `max_escalated_hosts`, `high_value_ports`, `notable_version_patterns`, `service_overexposure_thresholds`.
- `AutomationFlags`: `general`, `upload`, `ai_analysis`, `view_report`, `plugin`.

`Config` also carries `ports`, `timeout`, `external_ip_url`, `output_format`, `valid_external_ranges`, and `scan_mode` (`quick`|`full`|`adaptive`).

### Project Context

`ProjectContext` (`utils/context.py`) is constructed once per run: `project_id`, `project_folder` (absolute), `scope_source_path`, `config`, `artifacts` (`ArtifactStore`), `external_ip` (cached), `log_path`. It's passed into `PreFlight`, `Scanner`, `Reporter`, and the CVE/correlation steps — no module-level globals.

### Preflight Results

`PreFlight` keeps `preflight_hints: dict[str, PreflightHint]` (and `scan_results` for XML/summary output) as **instance** state, not a module global. `PreflightHint` (`utils/models.py`) is `{responded: bool, open_ports: list[int]}` — advisory only; nmap's active scan is always authoritative on final port state.

### Active Scan Results

`Scanner.scan_network()` returns a `ScanRun` (`utils/models.py`):

```python
ScanRun(
    hosts={"192.168.1.10": HostResult(
        host="192.168.1.10",
        ports=[PortResult(
            port=22, service="ssh", version="OpenSSH 9.x", banner="SSH-2.0-OpenSSH_9.x",
            cpe="cpe:2.3:a:openbsd:openssh:9.x:*:*:*:*:*:*:*",
            cve_matches=[CVEMatch(cve_id="CVE-...", severity="high", cvss=7.5, source="nvd")],
            plugin_results={"ssh_22": {"status": "ok"}},
            ai_recommendation="markdown summary",
            artifacts=[Artifact(label="Banner 22", path="Scan-Data/192.168.1.10/banner_22.txt")],
            escalated=False,
        )],
        preflight_hint=PreflightHint(responded=True, open_ports=[22]),
    )},
    targets=["192.168.1.10"], mode="adaptive",
)
```

Cross-host `Finding`s (from `correlation.correlate()`) are a separate list passed into `Reporter`, not attached to individual hosts.

### Plugin Contract

Plugins inherit from `ScanPlugin` and implement:

- `name`: unique plugin output key.
- `should_run(self, host, port, port_data)`: returns true when applicable. `port_data` is a plain dict view (`port`, `state`, `service`, `version`, `banner`) built from the `PortResult` for backward compatibility with existing plugins — plugins never receive the dataclass directly.
- `run(self, host, port, port_data)`: performs service-specific checks and returns a dict, optionally including `escalate`/`escalate_weight`/`escalate_reason` to vote on adaptive scan escalation.

Plugin results are collected into `PortResult.plugin_results[plugin.name]`, not mixed into the port's own fields.

## External Dependencies

Runtime dependencies from `requirements.txt`:

- `requests`
- `termcolor`
- `impacket`
- `python-nmap`
- `ollama`
- `openai`
- `markdown2`
- `weasyprint`

No new dependencies were added for CVE matching (stdlib `sqlite3` + `requests`) or plugin validation (stdlib `ast`).

Additional practical dependencies:

- Python 3.8+.
- `nmap` CLI installed and available in `PATH`.
- Ollama running locally (or an OpenAI API key configured) only if AI analysis/plugin generation/finding narration is actually used — no longer required at Scanner startup.
- Network access to `services.nvd.nist.gov` for CVE matching (disable with `--cve-source off`).
- SMB connectivity and credentials if upload is used.
- WeasyPrint system dependencies if PDF export is used.

## Operational Assumptions

- The operator has authorization for all entries in `scope.txt`.
- Root `scope.txt` lives in the process working directory, not inside the project folder.
- Project output folders are relative to the working directory.
- Internal/external IP classification uses RFC1918 ranges.
- Web scope is split and preflight-tagged, but active web testing is not currently part of the main active scanning target list.
- AI output is advisory and should not be treated as authoritative vulnerability validation — CVE matches (`modules/cve_lookup.py`) and cross-host findings (`modules/correlation.py`) are the deterministic, evidence-backed layer; AI only narrates on top of them.
- The preflight TCP-connect check and the active nmap scan can legitimately disagree (e.g. a port outside preflight's fixed port list). The active scan is always authoritative; `Reporter` surfaces a discrepancy note only when they differ.

## Key Design Constraints (resolved)

The constraints below were true as of the 2026-07-02 review and drove the rebuild. They are resolved in the current implementation, kept here for historical context:

- ~~The tool currently relies heavily on mutable module-level globals for settings, automation, and preflight results.~~ Resolved: `Config`/`ProjectContext` are threaded explicitly through every phase. `AUTO`/`CUSTOM_SETTINGS`/module-level `SCAN_RESULTS` have been removed from `utils/common.py`; `PreFlight` keeps its own `preflight_hints`/`scan_results` as instance state.
- ~~Scanning side effects are coupled to reporting paths through `save_scan_output(base_dir=self.output)`.~~ Resolved: `ArtifactStore` (`utils/artifacts.py`) owns all file writes and returns `Artifact` objects (label+path+kind) instead of raw path strings.
- ~~Plugins are loaded dynamically from local Python files with no sandboxing or manifest.~~ Partially resolved: `modules/plugin_validator.py` adds an AST-based static gate, and AI-generated plugins are quarantined (never auto-loaded) until explicitly approved. This is still not a sandbox — hand-authored plugins in `modules/plugins/` are still trusted at import time by design.
- ~~AI-generated plugins write executable Python into `modules/plugins`.~~ Resolved: they write to `modules/plugins_quarantine/` only; `sift.py plugins approve` (which re-validates) is the only path into the trusted, auto-loaded directory.
- ~~Report generation consumes the mutable scan result dictionaries directly.~~ Resolved: `Reporter` consumes typed `HostResult`/`PortResult`/`Finding` dataclasses (`utils/models.py`); the ad-hoc "final filter on malformed results" dict-shape guards in `sift.py` were removed since the shape is now guaranteed.

## Current Architecture (previously "Suggested Target Architecture")

Implemented boundaries:

- `Config` (`utils/config.py`): parsed settings, automation flags, output paths, provider choices, CVE and adaptive-scan tuning.
- `ProjectContext` (`utils/context.py`): project folder, scope source, `Config`, `ArtifactStore`, cached external IP, log path.
- `PreFlight` (`modules/preflight.py`): scope splitting, external IP validation, advisory TCP reachability hints.
- `Scanner` (`modules/scanner.py`) + `AdaptiveScanPlanner` (`modules/adaptive.py`): host discovery, quick/full/adaptive port/service enumeration, banner grabbing, escalation decisions.
- `PluginManager` (`modules/plugin_manager.py`) + `plugin_validator` (`modules/plugin_validator.py`): plugin loading (trusted dir only), quarantine writing, quarantine lifecycle (list/approve/reject).
- `CVELookupClient`/`CVECache` (`modules/cve_lookup.py`): provider-neutral, deterministic CVE matching against NVD, cached locally per project.
- `correlation` (`modules/correlation.py`): deterministic cross-host correlation into `Finding`s, plus optional AI narration on top.
- `AIClient` (`utils/ai_client.py`): provider-neutral wrapper for Ollama/OpenAI, used by per-port analysis, plugin generation, and finding narration alike.
- `Reporter` (`modules/reporter.py`): markdown/PDF report generation and CSV exports from the stable `ScanRun`/`Finding` schema.
- `ArtifactStore` (`utils/artifacts.py`): all file writes under a project root.

Actual data flow:

```text
CLI args
  -> Config.load()
  -> ProjectContext.create()
  -> PreFlight (scope split, preflight hints)
  -> Scanner.scan_network() (quick pass, then adaptive escalation via AdaptiveScanPlanner)
  -> CVELookupClient.lookup() per port (deterministic)
  -> correlation.correlate() (deterministic) -> correlation.narrate() (optional, AI)
  -> Scanner.analyse_vulnerabilities() per host (optional, AI, via AIClient)
  -> Reporter.generate_report() / convert_markdown_to_pdf()
  -> PreFlight.compress_and_upload() (SMB)
```

## Security Notes

- AI-generated plugin candidates are written to `modules/plugins_quarantine/` and are never imported/executed until `sift.py plugins approve` moves them into `modules/plugins/` (re-validating at approval time). Treat quarantine as "generated, not yet trusted."
- `modules/plugin_validator.py` is a static AST gate (denies risky imports/calls, requires the `ScanPlugin` contract) — it materially raises the bar over the previous regex-based checks, but it is not a sandbox. A sufficiently obfuscated payload could still pass; manual review before approval remains the real safety boundary.
- Plugin loading executes all import-time code in `modules/plugins/*.py` (trusted directory only).
- Scan artifacts may contain sensitive hostnames, banners, versions, and internal IPs.
- SMB upload should avoid prompting for credentials in automation unless credentials are provided securely.
- Reports clearly separate deterministic facts (port tables, CVE matches, cross-host findings) from AI-generated narrative (per-port recommendations, finding narration).
- CVE matching calls out to `services.nvd.nist.gov` over the network; disable with `--cve-source off` if the engagement requires fully offline operation.
