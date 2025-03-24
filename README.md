# PenTest Pre-Flight Check Tool

This project provides an pre-flight check tool for penetration testing, written in Python. It reads a single `scope.txt` file, automatically splits it into internal, external, and web scope files, and then runs various pre-flight checks (e.g. port scanning, external IP retrieval). It also supports custom settings via an XML file and outputs the scan results in XML format.

## Features

- **Scope Splitting**
  - Reads a `scope.txt` file and splits its contents into:
  - `int_scope.txt` for internal IP addresses/CIDR ranges.
  - `ext_scope.txt` for external IP addresses/CIDR ranges.
  - `web_scope.txt` for website URLs.
- **IP Range Expansion**
  - Supports expanding IP ranges expressed as `192.168.8.10-100` (last octet ranges).
- **Bare Domain Handling**
  - Recognises bare domains (e.g. `Example.com`) and prepends `http://` so they’re treated as URLs.
- **Pre-Flight Checks**
  - Performs port scans on IP targets using customisable ports and timeout settings.
  - Retrieves the external IP address using a configurable URL.
  - Tags each scope entry as `[IP]` or `[URL]` and logs the results.
- **XML Output**
  - Accumulates scan results and generates a pretty-printed XML file (`scan_results.xml`) for further processing.
- **Custom Settings**
  - Optionally override default settings (ports, timeout, external IP URL, output format) via an XML file using the `-s` flag.
- **Project Folder Structure**
  - Prompts for a project number (default: `PR00000`) and creates a folder with subfolders for Screenshots and Scan-Data.
- **Logging**
  - Generates a log file (`preflight_log.txt`) with timestamped events inside the project folder.

## Requirements

- Python 3.x
- [requests](https://pypi.org/project/requests/)
- [termcolor](https://pypi.org/project/termcolor/)

Install the dependencies using pip:

```bash
pip install requests termcolor
```


## Installation

1. Clone or download the repository and place the main script (e.g. preflight_checks.py) in your working directory.
Usage

2. Prepare Your Scope File
    Place your scope.txt file in the same directory as the script. If one is not found, a sample will be created.

3. Run the Script
    
    Execute the script:

    ```bash
    python preflight_checks.py
    ```

The script will prompt you for a project number (press Enter to default to PR00000).

Optional Custom Settings

Provide a custom settings XML file using the -s flag:

```bash
python preflight_checks.py -s path/to/settings.xml
```

## Script Process

1. Creates a project folder (e.g. PR00000) with subfolders for Screenshots and Scan-Data.

2. Splits scope.txt into int_scope.txt, ext_scope.txt, and web_scope.txt (only if entries exist).

3. Runs pre-flight checks (port scanning for IPs, external IP retrieval, etc.) based on the scope.

4. Generates an XML output file (scan_results.xml) with all scan details.

5. Logs all events in preflight_log.txt.

## Custom Settings XML

To override default settings, create an XML file with the following structure:

```bash
<settings>
  <ports>
    <port>22</port>
    <port>80</port>
    <port>443</port>
    <port>445</port>
    <port>3389</port>
  </ports>
  <timeout>0.5</timeout>
  <external_ip_url>https://api.ipify.org</external_ip_url>
  <output_format>XML</output_format>
</settings>
```

- ports: List of ports to scan.

- timeout: Connection timeout in seconds.

- external_ip_url: URL to use for external IP retrieval.

- output_format: Desired output format (currently supports XML).

### Example scope.txt

```
192.168.8.1
192.168.8.10-100
Example.com
192.168.9.0/24
```

## Project Folder Structure

After running the script, the project folder (e.g. PR00000) will be created with the following structure:

```
PR00000/
├── int_scope.txt      # Internal scope entries (if any)
├── ext_scope.txt      # External scope entries (if any)
├── web_scope.txt      # Website URLs (if any)
├── preflight_log.txt  # Log file with timestamped events
├── scan_results.xml   # XML file containing scan results
├── Screenshots/       # Folder for screenshots
└── Scan-Data/         # Folder for scan data
```
