# 🧰 Sift: Adaptive Pentest Framework Version: 0.7.0

<img src="sift.png" alt="Logo" width="200">

Sift is an all-in-one pentest automation framework designed to streamline the recon, scanning, and reporting process for internal, external, and web application testing. It supports plugin-based extensibility and AI integration for enhanced remediation and vulnerability context.

---

## 🤔 Why Sift?

- Purpose-Named Modules: Preflight, Scanner, Plugin Manager, CVE Lookup, Correlation, and Reporter—each named for exactly what it does.
- From Boot to Report: Designed for real-world pentesters to get from scope file to upload in minutes.
- Smart, Not Noisy: Sift doesn't just scan—it organises, interprets, and documents.
- Built for Teams: Project folder structure and plugin architecture make it easy to hand off or scale.
- Modular by Design: Swap in custom plugins, use XML/Markdown outputs, or integrate into your own workflow.
---

## 🚀 Features

- 🧪 Internal, external, and web recon support
- 🔌 Plugin-based architecture
- 🧠 Adaptive scanning: hosts that look interesting (high-value ports, notable versions, plugin signals) get escalated to a deeper nmap pass automatically
- 🎯 Deterministic CVE matching against the NVD CVE API, using nmap's own CPE data for precision — not just AI opinion
- 🕸️ Cross-host correlation: repeated CVEs, shared vulnerable versions, and service overexposure are rolled up into a ranked "Top Findings" list
- 🪄 AI-assisted plugin generation with a mandatory quarantine + review step (`sift.py plugins list/show/approve/reject`) before generated code is ever trusted
- 🤖 Provider-neutral AI layer (Ollama or OpenAI) for per-port analysis, plugin generation, and finding narration
- 📦 Auto SMB uploads to shared drives
- 🗂️ Structured scan and report directories per project
- 🖼️ ASCII network visualization
- 🔍 Scope-based scanning via `scope.txt`

---

## 🗂️ Example Project Output Structure

```
PR00099/
├── int_scope.txt
├── ext_scope.txt
├── web_scope.txt
├── summary.txt
├── scan_results.xml
├── report.md
├── Screenshots/
└── Scan-Data/
    └── 192.168.8.1/
        ├── banner_22.txt
        ├── http_80_output.json
        ├── ssh_22_output.json
        ├── nmap.csv
        └── ...
```

---

## 🧩 Module Breakdown

### 🛫 Preflight (pre-checks)
- Validates the project directory and structure
- Extracts and formats `scope.txt` into internal/external/web files
- Performs quick port reachability checks as an **advisory hint only** — nmap's real scan is always the source of truth for port state, and the report calls out when the two disagree

### 🔍 Scanner (`modules/scanner.py`, active scanning)
- Orchestrates live scans using `nmap`
- In adaptive mode (default), quick-scans every host first, then uses `AdaptiveScanPlanner` (`modules/adaptive.py`) to decide which specific hosts warrant a deeper rescan
- Automatically grabs banners
- Invokes loaded plugins per port
- Stores all plugin output under `Scan-Data/<host>/` via the `ArtifactStore`

### 🧩 Plugin Manager (`modules/plugin_manager.py`)
- Manages registration and loading of static and approved AI-generated plugins from `modules/plugins`
- AI-generated candidates are written to `modules/plugins_quarantine/` only — never auto-loaded or auto-trusted
- Registers plugins using `.should_run()` matching logic
### 📦 Built-in Plugins
- `http_scan` - grabs HTTP banner
- `ftp_scan` - captures FTP welcome message
- `ssh_scan` - collects SSH server banner
- `smb_scan` - lists SMB shares anonymously


### 🎯 CVE Lookup (`modules/cve_lookup.py`)
- Matches each scanned service against the NVD CVE API 2.0, preferring nmap's own CPE string for precise matching
- Deterministic and cached locally per project (`.cve_cache.sqlite3`) — works with AI analysis off

### 🕸️ Correlation (`modules/correlation.py`, cross-host findings)
- Rolls per-host CVE matches and plugin findings up into engagement-wide findings: repeated CVEs, shared vulnerable versions, and service overexposure
- Fully deterministic; AI (if enabled) only adds a short narrative on top of the top N findings, never invents new ones

### 📝 Reporter (`modules/reporter.py`)
- Creates a rich markdown report (`report.md`) led by a ranked **Top Findings** section
- Embeds host summaries, open ports, CVE matches, plugin results, and AI recommendations
- Collapsible vulnerability insights using markdown `<details>`
- Optionally opens the report automatically post-run

---

## 🪄 AI Plugin Generation & Review

Sift can generate candidate service-specific scan plugins via Ollama or OpenAI (whichever `DefaultAIProvider` is configured). Generated candidates are **never trusted automatically**:

1. A candidate is written to `modules/plugins_quarantine/<file>.py` plus a `<file>.py.meta.json` sidecar (generation time, port/service, provider, static-validation result).
2. Review it: `python3 sift.py plugins list` / `plugins show <file>`.
3. Approve it to move it into the trusted, auto-loaded `modules/plugins/` directory (re-validated at approval time): `python3 sift.py plugins approve <file>`.
4. Or discard it: `python3 sift.py plugins reject <file>` (moved to `modules/plugins_quarantine/rejected/`).

Static validation (`modules/plugin_validator.py`) is an AST-based gate — it blocks disallowed imports (`os`, `subprocess`, `sys`, etc.), `eval`/`exec`, and structural issues (missing `should_run`/`run`, a stray `__init__`). It is not a sandbox; treat it as a defense-in-depth check on top of manual review, not a substitute for it.

Plugins follow the same structure as before — see `Plugin_Dev/plugin_template.py` for the hand-authored pattern:
```python
from modules.plugins import ScanPlugin
from utils.common import print_status

class Http_80Scan(ScanPlugin):
    name = "http_80"

    def should_run(self, host, port, port_data):
        return port == 80

    def run(self, host, port, port_data):
        print_status("Running HTTP scan...", "info")
        return {"banner": port_data.get("banner", "N/A")}
```

A plugin's `run()` may optionally return `"escalate": bool`, `"escalate_weight": int`, and `"escalate_reason": str` to vote on adaptive scan escalation for that host — this is additive and every existing plugin works unchanged without it.

---

## 🔧 Usage

```bash
python3 sift.py --project PR00100 --scope scope.txt --scan-mode adaptive
```

Available flags:
- `--project <name>`: Project folder name
- `--scope <file>`: Source scope file path (default: `scope.txt`)
- `--settings <file>`: Path to a custom settings XML file
- `--ascii`: Show ASCII network map
- `--output <file>`: Output report file (default: `report.md`)
- `--scan-mode <quick|full|adaptive>`: quick/full scan every host uniformly; adaptive (default) escalates specific hosts based on findings
- `--cve-source <nvd|off>`: CVE matching source (default: `nvd`)
- `--nvd-api-key <key>`: NVD API key (raises the rate limit from 5/30s to 50/30s)
- `--top-findings <n>`: Number of top cross-host findings to AI-narrate (default: 10)
- `--pdf`: Export a PDF copy of the markdown report
- `--no-ai`: Skip AI vulnerability analysis
- `--no-upload`: Skip SMB upload
- `--check-dependencies`: Check scan/AI/upload/PDF dependencies and exit

### 🧠 Automation Flags
- `--auto`: Auto-accept all prompts (overrides others)
- `--auto-upload`: Automatically upload the zipped project folder to SMB
- `--auto-ai`: Automatically run AI vulnerability analysis after scan
- `--auto-view-report`: Automatically print the final markdown report
- `--auto-plugin`: Reserved for future auto-generation of candidate plugins into quarantine (never auto-trusted)

### 🔌 Plugin Review Subcommands
```bash
python3 sift.py plugins list
python3 sift.py plugins show <filename>
python3 sift.py plugins approve <filename> [--yes]
python3 sift.py plugins reject <filename>
```

---

## Demo

![Demo](Demo.gif)

## 📦 SMB Upload Support

Sift can automatically zip the entire project directory and upload to an SMB share at the end of the run.

Target path is:
```
smb://<IP>/Media/Projects/<project_name>/<project_name>.zip
```
You’ll be prompted to enter credentials.

## 🌐 Result Collector Server

A basic Flask server (`results_server.py`) is included to receive zipped scan results. Run it on a system with network access:

```bash
python3 results_server.py
```

Configure Flock-It with `--server-url http://<server>:8000/upload` to send results after each loop.

---

## 📋 Requirements

- Python 3.8+
- nmap (CLI)
- `python-nmap` for active scanning
- [Ollama](https://ollama.com/) or OpenAI settings for optional AI analysis
- Impacket for optional SMB uploads
- WeasyPrint and markdown for optional PDF export
- Internet access to `services.nvd.nist.gov` for CVE matching (set `--cve-source off` to disable; no extra Python dependency required — uses `requests` and stdlib `sqlite3`)

Install dependencies:
```bash
pip install -r requirements.txt
```

Copy `settings.example.xml` to `settings.xml` (or `settings_dev.xml`) and fill in your own values. Both `settings.xml` and `settings_dev.xml` are gitignored — never commit a settings file containing real API keys, SMB credentials, or other secrets.

---

## 🤝 Contributions

Pull requests welcome. All AI plugin templates are being refined — contributions to prompt engineering or service detection logic especially helpful.

---

## 🧪 In Progress
- Web scope is split and preflight-tagged, but active web testing/HTTP probing plugins are not yet part of the main scan phase
- `--auto-plugin` is wired for future automatic candidate generation during a scan; today plugin generation is available programmatically but not yet triggered automatically mid-scan
- Passive recon (`Scanner.run_passive_recon`) exists but isn't wired into the main pipeline yet
- Plugin classification by scan type / tag-based enable-disable

---

Happy flocking 🐦
