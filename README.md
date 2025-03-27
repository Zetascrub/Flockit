# PenTest Pre-Flight Check Tool

This project provides a pre-flight check tool for penetration testing, written in Python. It reads a single `scope.txt` file, automatically splits it into internal, external, and web scope files, and then runs various pre-flight checks (e.g. port scanning, external IP retrieval). It also supports custom settings via an XML file (`settings.xml`) and outputs the scan results in XML format.


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
- **Auto Mode**
  - Use `--auto` to run the entire script non-interactively.
- **ASCII Visualisation**
  - Use `--ascii` to generate a subnet-based network map of discovered hosts and services.
- **XML Output**
  - Accumulates scan results and generates a pretty-printed XML file (`scan_results.xml`) for further processing.
- **User-Friendly Output**
  - Uses `print_status()` to display emojis and color-coded symbols in the terminal, while still logging to a file.
- **Custom Settings via XML**
  - Optionally override default settings (ports, timeout, external IP URL, output format, SMB details) using a `settings.xml` file.
- **Project Folder Structure**
  - Prompts for a project number (default: `PR00000`) and creates a folder with subfolders for Screenshots and Scan-Data.
- **Logging**
  - Generates a log file (`preflight_log.txt`) with timestamped events inside the project folder.
- **SMB Upload**
  - Exports the files to an SMB share using credentials provided via `settings.xml` and prompts for the password.

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

1. Clone or download the repository and place the main script (e.g. `pre-flight-check_0.6.py`) in your working directory.

2. Prepare Your Scope File
    Place your `scope.txt` file in the same directory as the script. If one is not found, a sample will be created.

3. Run the Script
    
    Execute the script:

    ```bash
    python pre-flight-check_0.6.py --auto --ascii
    ```

The script will prompt you for a project number (press Enter to default to PR00000).

## Script Process

1. Creates a project folder (e.g. PR00000) with subfolders for Screenshots and Scan-Data.

2. Splits `scope.txt` into `int_scope.txt`, `ext_scope.txt`, and `web_scope.txt` (only if entries exist).

3. Runs pre-flight checks (port scanning for IPs, external IP retrieval, etc.) based on the scope.

4. Generates an XML output file (`scan_results.xml`) with all scan details.

5. Logs all events in `preflight_log.txt`.

6. Uploads results to SMB share (password is prompted securely).

## Custom Settings XML

The script will automatically look for a `settings.xml` file in the same directory.

```xml
<Settings>
    <Ports>22,80,443,445,3389</Ports>
    <Timeout>0.5</Timeout>
    <ExternalIPURL>https://api.ipify.org</ExternalIPURL>
    <OutputFormat>XML</OutputFormat>

    <SMB>
        <Server>192.168.8.239</Server>
        <Share>Media</Share>
        <Username>pentest</Username>
    </SMB>
</Settings>
```

- `Ports`: List of ports to scan (comma-separated).
- `Timeout`: Connection timeout in seconds.
- `ExternalIPURL`: URL to use for external IP retrieval.
- `OutputFormat`: Currently supports `XML`.
- `SMB`: SMB server, share, and username (password is securely prompted).

### Example `scope.txt`

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