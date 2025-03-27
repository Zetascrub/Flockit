# 🦅 Flockit - Modular Pentest Pre-Flight & Recon Tool

**Flockit** is a modular penetration testing assistant that automates the pre-engagement setup, basic recon, vulnerability enumeration, and report generation. Initially built for validating scope and reachability, it has grown into a full multi-phase toolset with support for plugins, AI-driven analysis, and team-friendly outputs.

---

# 🤔 Why Flockit?

- Bird-Themed Modules: PreFlight checks, RavenRecon, and Owl reporting—each inspired by speed, intelligence, and vision.
- From Boot to Report: Designed for real-world pentesters to get from scope file to upload in minutes.
- Smart, Not Noisy: Flockit doesn't just scan—it organises, interprets, and documents.
- Built for Teams: Project folder structure and plugin architecture make it easy to hand off or scale.
- Modular as Flock: Swap in custom plugins, use XML/Markdown outputs, or integrate into your own workflow.


## 🚀 Key Features

### 🧽 Pre-Flight Checks
- Parses `scope.txt` and auto-generates:
  - `int_scope.txt` (Internal IPs)
  - `ext_scope.txt` (External IPs)
  - `web_scope.txt` (Web targets)
- Expands IP ranges (e.g., `192.168.8.1-10`)
- Classifies domains and CIDR blocks intelligently

### 🔍 Raven (Active Scanning)
- Pings internal and external hosts to determine availability
- Performs port scanning with options for quick (`-F`) or full (`-p-`) modes
- Supports threaded scanning with banner grabbing
- Plugin system for service-specific checks (e.g. HTTP, SSH, SMB)

### 🤖 Owl (Reporting & AI Analysis)
- Auto-generates Markdown reports with:
  - Host summaries
  - Service details
  - Plugin findings
  - AI-based vulnerability analysis via Ollama
- Optional ASCII visualisation for quick subnet views

### ⚙️ Plugin Support
- Drop-in plugin files into the `modules/plugins/` folder
- Each plugin inherits from `ScanPlugin` located in `modules/plugins/__init__.py`
- Custom output can be included per-service/port

### 🛠️ Custom Settings
- Load scanning config from `settings.xml`:

  ```xml
  <settings>
    <Ports>22,80,443,445,3389</Ports>
    <Timeout>0.5</Timeout>
    <ExternalIPURL>https://api.ipify.org</ExternalIPURL>
    <OutputFormat>XML</OutputFormat>
    <ValidRanges>
      <Range>82.147.10.192/28</Range>
      <Range>82.147.10.208/28</Range>
    </ValidRanges>
    <SMB>
      <Server>fileshare.local</Server>
      <Share>Projects</Share>
      <Username>tester</Username>
    </SMB>
  </settings>



## Writing Custom Plugins

You can extend the scanner by writing plugins that inherit from `ScanPlugin`.

Each plugin must define:
- `name`: A unique string identifier.
- `should_run(host, port, port_data)`: Return `True` to run on a given port.
- `run(host, port, port_data)`: Perform the custom scan and return a string.

### Example Plugin File: `plugins/my_custom_plugin.py`

```python
class MyCustomPlugin(ScanPlugin):
    name = "my_custom_plugin"

    def should_run(self, host, port, port_data):
        return port == 8080

    def run(self, host, port, port_data):
        return "Hello from plugin"
```

## Demo

![Demo](demo.gif)

# 🧪 Usage

## ⟲ Basic Usage

```bash
python3 flockit.py
```

## ⚡ Auto Mode (No Prompts)

```bash
python3 flockit.py --auto --project PR00099 --mode full
```

# 📄 Example Scope

```bash
192.168.8.1
192.168.8.10-15
example.com
192.168.9.0/24
```


## Script Process

1. Creates a project folder (e.g. PR00000) with subfolders for Screenshots and Scan-Data.

2. Splits `scope.txt` into `int_scope.txt`, `ext_scope.txt`, and `web_scope.txt` (only if entries exist).

3. Runs pre-flight checks (port scanning for IPs, external IP retrieval, etc.) based on the scope.

4. Generates an XML output file (`scan_results.xml`) with all scan details.

5. Logs all events in `preflight_log.txt`.

6. Uploads results to SMB share (password is prompted securely).

🗂 Output Overview

After running the script, the project folder (e.g. PR00000) will be created with the following structure:

```
PR00099/
├── int_scope.txt
├── ext_scope.txt
├── web_scope.txt
├── scan_results.xml
├── raven_report.md
├── preflight_log.txt
├── Screenshots/
└── Scan-Data/

```

## Requirements

- Python 3.x
- [requests](https://pypi.org/project/requests/)
- [termcolor](https://pypi.org/project/termcolor/)
- [impacket](https://pypi.org/project/impacket/)
- [python-nmap](https://pypi.org/project/python-nmap/)
- [ollama](https://pypi.org/project/ollama/)

Install the dependencies using pip:

```bash
pip install -r requirements.txt
```

## Installation

1. Clone or download the repository and place the main script in your working directory.

2. Prepare Your Scope File
    Place your `scope.txt` file in the same directory as the script. If one is not found, a sample will be created.

3. Run the Script
    
    Execute the script:

    ```bash
    python pre-flight-check_0.6.py --auto --ascii
    ```

The script will prompt you for a project number (press Enter to default to PR00000).

