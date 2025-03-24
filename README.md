# PenTest Pre-Flight Check Tool

This project provides an pre-flight check tool for penetration testing, written in Python. It reads a single `scope.txt` file, automatically splits it into internal, external, and web scope files, and then runs various pre-flight checks (e.g. port scanning, external IP retrieval). It also supports custom settings via an XML file and outputs the scan results in XML format.


## Demo

```bash
python3 pre-flight-check_0.2.py 
Enter Project Number (or press Enter to use default PR00000): 
Created project folder: PR00000
Created folder: PR00000/Screenshots
Created folder: PR00000/Scan-Data
Created int_scope.txt with 11 entries (Internal IPs).
No external IPs found; ext_scope.txt not created.
No website URLs found; web_scope.txt not created.
[*] Running pre-flight checks for: INT
[~] 192.168.8.1 [IP]
[2025-03-24 11:43:37] Tagged scope entry: 192.168.8.1 [IP]
[*] Scanning common ports on 192.168.8.1...
[+] Open ports on 192.168.8.1: [22, 80, 443]
[2025-03-24 11:43:37] Open ports on 192.168.8.1: [22, 80, 443]
[~] 192.168.8.2 [IP]
[2025-03-24 11:43:37] Tagged scope entry: 192.168.8.2 [IP]
[*] Scanning common ports on 192.168.8.2...
[-] No common ports open on 192.168.8.2
[2025-03-24 11:43:39] No common ports open on 192.168.8.2
[~] 192.168.8.3 [IP]
[2025-03-24 11:43:39] Tagged scope entry: 192.168.8.3 [IP]
[*] Scanning common ports on 192.168.8.3...
[-] No common ports open on 192.168.8.3
[2025-03-24 11:43:42] No common ports open on 192.168.8.3
[~] 192.168.8.4 [IP]
[2025-03-24 11:43:42] Tagged scope entry: 192.168.8.4 [IP]
[*] Scanning common ports on 192.168.8.4...
[-] No common ports open on 192.168.8.4
[2025-03-24 11:43:44] No common ports open on 192.168.8.4
[~] 192.168.8.5 [IP]
[2025-03-24 11:43:44] Tagged scope entry: 192.168.8.5 [IP]
[*] Scanning common ports on 192.168.8.5...
[-] No common ports open on 192.168.8.5
[2025-03-24 11:43:47] No common ports open on 192.168.8.5
[~] 192.168.8.6 [IP]
[2025-03-24 11:43:47] Tagged scope entry: 192.168.8.6 [IP]
[*] Scanning common ports on 192.168.8.6...
[-] No common ports open on 192.168.8.6
[2025-03-24 11:43:49] No common ports open on 192.168.8.6
[~] 192.168.8.7 [IP]
[2025-03-24 11:43:49] Tagged scope entry: 192.168.8.7 [IP]
[*] Scanning common ports on 192.168.8.7...
[-] No common ports open on 192.168.8.7
[2025-03-24 11:43:52] No common ports open on 192.168.8.7
[~] 192.168.8.8 [IP]
[2025-03-24 11:43:52] Tagged scope entry: 192.168.8.8 [IP]
[*] Scanning common ports on 192.168.8.8...
[-] No common ports open on 192.168.8.8
[2025-03-24 11:43:54] No common ports open on 192.168.8.8
[~] 192.168.8.9 [IP]
[2025-03-24 11:43:54] Tagged scope entry: 192.168.8.9 [IP]
[*] Scanning common ports on 192.168.8.9...
[-] No common ports open on 192.168.8.9
[2025-03-24 11:43:57] No common ports open on 192.168.8.9
[~] 192.168.8.10 [IP]
[2025-03-24 11:43:57] Tagged scope entry: 192.168.8.10 [IP]
[*] Scanning common ports on 192.168.8.10...
[+] Open ports on 192.168.8.10: [445]
[2025-03-24 11:43:59] Open ports on 192.168.8.10: [445]
[~] 192.168.8.239 [IP]
[2025-03-24 11:43:59] Tagged scope entry: 192.168.8.239 [IP]
[*] Scanning common ports on 192.168.8.239...
[+] Open ports on 192.168.8.239: [80, 443, 445]
[2025-03-24 11:43:59] Open ports on 192.168.8.239: [80, 443, 445]
[+] INT pre-flight checks passed.

[2025-03-24 11:43:59] INT pre-flight checks passed.
[*] Running pre-flight checks for: EXT
[+] External IP Address: 82.147.10.194
[2025-03-24 11:43:59] External IP Address: 82.147.10.194
[-] ext_scope.txt not found.
[2025-03-24 11:43:59] ext_scope.txt not found.
[-] Skipping EXT checks due to no entries.
[*] Running pre-flight checks for: WEB
[+] External IP Address: 82.147.10.194
[2025-03-24 11:43:59] External IP Address: 82.147.10.194
[-] web_scope.txt not found.
[2025-03-24 11:43:59] web_scope.txt not found.
[-] Skipping WEB checks due to no entries.
Scan results written to PR00000/scan_results.xml

==================================================
Summary:
Host                 | Status                        
--------------------------------------------------
192.168.8.1          | Responded (ports: 22, 80, 443)
192.168.8.2          | Not Responded                 
192.168.8.3          | Not Responded                 
192.168.8.4          | Not Responded                 
192.168.8.5          | Not Responded                 
192.168.8.6          | Not Responded                 
192.168.8.7          | Not Responded                 
192.168.8.8          | Not Responded                 
192.168.8.9          | Not Responded                 
192.168.8.10         | Responded (ports: 445)        
192.168.8.239        | Responded (ports: 80, 443, 445)
==================================================
Summary written to PR00000/summary.txt
Do you want to upload the project folder to an SMB share? (y/n): y
Project compressed to PR00000/PR00000.zip
Zip file created: PR00000/PR00000.zip
Connected to 192.168.8.239 on share Media
Uploading PR00000/PR00000.zip to Projects/PR00000/PR00000.zip...
Upload completed successfully.
```

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
- **SMB Upload**
  - Exports the files to a smb share.

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
