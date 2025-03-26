#!/usr/bin/env python3
import os
import re
import sys
import ipaddress
import socket
import zipfile
from datetime import datetime
import requests
from termcolor import colored
import xml.etree.ElementTree as ET
import xml.dom.minidom as md
import argparse
from impacket.smbconnection import SMBConnection
import nmap
import subprocess
import logging
import json
import importlib.util
import inspect
import ollama

# Version 0.5


## Pre-Flight-Script

# Global variables for custom settings and scan results
CUSTOM_SETTINGS = {
    "ports": [22, 80, 443, 445, 3389],
    "timeout": 0.5,
    "external_ip_url": "https://api.ipify.org",
    "output_format": "XML"  # default output format
}

SCAN_RESULTS = {}  # Dictionary to store scan results per mode
PROJECT_FOLDER = ""  # Set in main()


def setup_logging(log_file):
    """
    Configures the root logger to output messages to both the console and a log file.
    """
    # Create a logger and set the overall log level.
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Define a formatter with timestamp, level and message.
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    
    # Create a StreamHandler for console output.
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # Create a FileHandler to write log messages to the specified log file.
    file_handler = logging.FileHandler(log_file, mode='a')
    file_handler.setFormatter(formatter)
    
    # Clear any existing handlers (useful if setup_logging is called multiple times)
    if logger.hasHandlers():
        logger.handlers.clear()
    
    # Add both handlers to the logger.
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger


def load_custom_settings(xml_path):
    """
    Load custom settings from an XML file and update the CUSTOM_SETTINGS dict.
    Expected XML format:
    <settings>
      <ports>
         <port>22</port>
         <port>80</port>
         <!-- etc -->
      </ports>
      <timeout>0.5</timeout>
      <external_ip_url>https://api.ipify.org</external_ip_url>
      <output_format>XML</output_format>
    </settings>
    """
    global CUSTOM_SETTINGS
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ports_elem = root.find("ports")
        if ports_elem is not None:
            ports = []
            for port in ports_elem.findall("port"):
                try:
                    ports.append(int(port.text.strip()))
                except (ValueError, AttributeError):
                    continue
            if ports:
                CUSTOM_SETTINGS["ports"] = ports
        timeout_elem = root.find("timeout")
        if timeout_elem is not None:
            try:
                CUSTOM_SETTINGS["timeout"] = float(timeout_elem.text.strip())
            except (ValueError, AttributeError):
                pass
        ip_url_elem = root.find("external_ip_url")
        if ip_url_elem is not None and ip_url_elem.text:
            CUSTOM_SETTINGS["external_ip_url"] = ip_url_elem.text.strip()
        output_elem = root.find("output_format")
        if output_elem is not None and output_elem.text:
            CUSTOM_SETTINGS["output_format"] = output_elem.text.strip().upper()
        logger.info(f"[*] Custom settings loaded from XML.")
    except Exception as e:
        logger.error(f"[-] Failed to load settings from {xml_path}: {e}")

def get_external_ip():
    """Retrieve and log the external IP address using custom or default URL."""
    try:
        ip = requests.get(CUSTOM_SETTINGS["external_ip_url"]).text
        logger.info(f"[+] External IP Address: {ip}")
        return ip
    except requests.RequestException:
        logger.info("[-] Unable to determine external IP address.")
        return ""

def expand_ip_range(entry):
    """
    Expand an IP range string of the form "192.168.8.10-100" into a list of IP addresses.
    Only supports range in the last octet.
    """
    match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$", entry)
    if match:
        base = match.group(1)
        start = int(match.group(2))
        end = int(match.group(3))
        if 0 <= start <= end <= 255:
            return [f"{base}{i}" for i in range(start, end + 1)]
    return [entry]

def is_domain(entry):
    """
    Check if the entry looks like a domain without a protocol.
    Returns True if it's a domain.
    """
    if re.match(r"^(?!http://|https://)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", entry):
        return True
    return False

def split_scope_file():
    """
    Reads the main scope.txt (in current directory) and splits its entries into:
      - Internal IPs (int_scope.txt)
      - External IPs (ext_scope.txt)
      - Website URLs (web_scope.txt)
    Files are created in the PROJECT_FOLDER only if entries exist.
    Handles IP ranges and bare domains.
    """
    MAIN_SCOPE_FILE = "scope.txt"
    INT_SCOPE_FILE = os.path.join(PROJECT_FOLDER, "int_scope.txt")
    EXT_SCOPE_FILE = os.path.join(PROJECT_FOLDER, "ext_scope.txt")
    WEB_SCOPE_FILE = os.path.join(PROJECT_FOLDER, "web_scope.txt")
    
    if not os.path.isfile(MAIN_SCOPE_FILE):
        sample = """\
192.168.8.1
192.168.8.10-12
Example.com
192.168.9.0/24
"""
        print("scope.txt not found. Creating a sample scope.txt...")
        with open(MAIN_SCOPE_FILE, "w") as f:
            f.write(sample)

    with open(MAIN_SCOPE_FILE, "r") as f:
        raw_entries = [line.strip() for line in f if line.strip()]

    internal_networks = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16")
    ]

    def is_internal_ip(ip_str):
        try:
            ip_obj = ipaddress.ip_network(ip_str, strict=False)
            return any(ip_obj.subnet_of(net) for net in internal_networks)
        except ValueError:
            return False

    int_entries = []
    ext_entries = []
    web_entries = []

    for entry in raw_entries:
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$", entry) or "-" in entry:
            expanded = expand_ip_range(entry)
            for ip in expanded:
                try:
                    ipaddress.ip_address(ip)
                    if is_internal_ip(ip):
                        int_entries.append(ip)
                    else:
                        ext_entries.append(ip)
                except ValueError:
                    continue
        else:
            try:
                ipaddress.ip_network(entry, strict=False)
                if is_internal_ip(entry):
                    int_entries.append(entry)
                else:
                    ext_entries.append(entry)
                continue
            except ValueError:
                pass

            if re.match(r"^https?://", entry):
                web_entries.append(entry)
            elif is_domain(entry):
                web_entries.append("http://" + entry)
            else:
                logger.info(f"[-] Unrecognized scope entry format: {entry}")
    
    if int_entries:
        with open(INT_SCOPE_FILE, "w") as f:
            for line in int_entries:
                f.write(line + "\n")
        logger.info(f"Created int_scope.txt with {len(int_entries)} entries (Internal IPs).")
    else:
        if os.path.exists(INT_SCOPE_FILE):
            os.remove(INT_SCOPE_FILE)
        logger.info("No internal IPs found; int_scope.txt not created.")

    if ext_entries:
        with open(EXT_SCOPE_FILE, "w") as f:
            for line in ext_entries:
                f.write(line + "\n")
        print(f"Created ext_scope.txt with {len(ext_entries)} entries (External IPs).")
    else:
        if os.path.exists(EXT_SCOPE_FILE):
            os.remove(EXT_SCOPE_FILE)
        print("No external IPs found; ext_scope.txt not created.")

    if web_entries:
        with open(WEB_SCOPE_FILE, "w") as f:
            for line in web_entries:
                f.write(line + "\n")
        print(f"Created web_scope.txt with {len(web_entries)} entries (Website URLs).")
    else:
        if os.path.exists(WEB_SCOPE_FILE):
            os.remove(WEB_SCOPE_FILE)
        print("No website URLs found; web_scope.txt not created.")

def check_scope_file(file_path):
    """Read and return non-empty entries from a given scope file."""
    if not os.path.isfile(file_path):
        logger.info(f"[-] {os.path.basename(file_path)} not found.")
        return []
    with open(file_path, "r") as f:
        entries = [line.strip() for line in f if line.strip()]
    if not entries:
        logger.info(f"[-] {os.path.basename(file_path)} is empty.")
    return entries


def get_recon_targets():
    """
    Read internal and external scope files (if they exist) and combine them into a single
    string of targets (space-separated) for RavenRecon to scan.
    """
    targets = []
    for scope_file in [os.path.join(PROJECT_FOLDER, "int_scope.txt"),
                       os.path.join(PROJECT_FOLDER, "ext_scope.txt")]:
        if os.path.exists(scope_file):
            with open(scope_file, "r") as f:
                for line in f:
                    target = line.strip()
                    if target:
                        targets.append(target)
    return " ".join(targets)


def auto_tag(entry):
    """Tag the entry as [IP] or [URL] based on its format."""
    if re.match(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", entry):
        return f"{entry} [IP]"
    elif re.match(r"https?://", entry):
        return f"{entry} [URL]"
    else:
        return f"{entry} [UNKNOWN]"

def port_scan(ip):
    """Scan a set of common ports on the given IP address using custom settings.
    Returns a list of open ports."""
    logger.info(f"[*] Scanning common ports on {ip}...")
    open_ports = []
    for port in CUSTOM_SETTINGS["ports"]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(CUSTOM_SETTINGS["timeout"])
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except socket.error:
            continue
    if open_ports:
        logger.info(f"[+] Open ports on {ip}: {open_ports}")
    else:
        logger.info(f"[-] No common ports open on {ip}")
    return open_ports

def run_checks(mode, file_path):
    """
    Run pre-flight checks for a given mode (int, ext, web) using the specified scope file.
    For external and web modes, fetch the external IP.
    Accumulate results in the global SCAN_RESULTS dictionary.
    """
    logger.info(f"[*] Running pre-flight checks for: {mode.upper()}")
    mode_results = []
    if mode in ["ext", "web"]:
        ext_ip = get_external_ip()
        mode_results.append({"external_ip": ext_ip})
    scope_entries = check_scope_file(file_path)
    if not scope_entries:
        logger.info(f"[-] Skipping {mode.upper()} checks due to no entries.")
        return
    for entry in scope_entries:
        result = {}
        result["target"] = entry
        result["tag"] = auto_tag(entry)
        logger.info(f"[~] {result['tag']}")
        logger.info(f"Tagged scope entry: {result['tag']}")
        if "[IP]" in result["tag"]:
            result["open_ports"] = port_scan(entry)
        mode_results.append(result)
    logger.info(f"[+] {mode.upper()} pre-flight checks passed.\n")
    SCAN_RESULTS[mode] = mode_results

def write_xml_output():
    """
    Write the accumulated SCAN_RESULTS into an XML file in the project folder.
    The XML structure includes mode sections and for each target, its details.
    """
    root = ET.Element("ScanResults")
    timestamp = ET.SubElement(root, "Timestamp")
    timestamp.text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for mode, results in SCAN_RESULTS.items():
        mode_elem = ET.SubElement(root, "Mode", name=mode)
        for entry in results:
            if "external_ip" in entry:
                ext_elem = ET.SubElement(mode_elem, "ExternalIP")
                ext_elem.text = entry["external_ip"]
                continue
            target_elem = ET.SubElement(mode_elem, "Target")
            address_elem = ET.SubElement(target_elem, "Address")
            address_elem.text = entry["target"]
            tag_elem = ET.SubElement(target_elem, "Tag")
            tag_elem.text = entry["tag"]
            if "[IP]" in entry["tag"]:
                ports_elem = ET.SubElement(target_elem, "OpenPorts")
                for port in entry.get("open_ports", []):
                    port_elem = ET.SubElement(ports_elem, "Port")
                    port_elem.text = str(port)
    xml_str = ET.tostring(root, encoding="utf-8")
    parsed_xml = md.parseString(xml_str)
    pretty_xml = parsed_xml.toprettyxml(indent="  ")
    xml_file = os.path.join(PROJECT_FOLDER, "scan_results.xml")
    with open(xml_file, "w") as f:
        f.write(pretty_xml)
    logger.info(f"Scan results written to {xml_file}")

def create_project_structure(proj_number):
    """
    Create a project folder named after the project number (or PR00000 by default)
    with subfolders for Screenshots and Scan-Data.
    """
    base_folder = proj_number if proj_number else "PR00000"
    if not os.path.isdir(base_folder):
        os.makedirs(base_folder)
        print(f"Created project folder: {base_folder}")
    else:
        print(f"Project folder '{base_folder}' already exists.")
    for sub in ["Screenshots", "Scan-Data"]:
        sub_path = os.path.join(base_folder, sub)
        if not os.path.isdir(sub_path):
            os.makedirs(sub_path)
            print(f"Created folder: {sub_path}")
        else:
            print(f"Folder '{sub_path}' already exists.")
    return base_folder

def ensure_remote_path(conn, share, remote_path):
    """
    Ensure that the full remote_path exists on the SMB share.
    Splits the path into parts and creates each directory if needed.
    """
    parts = remote_path.strip("/").split("/")
    current_path = ""
    for part in parts:
        current_path = current_path + "/" + part if current_path else part
        try:
            conn.createDirectory(share, current_path)
        except Exception:
            pass

def compress_project_folder(project_folder, zip_filename):
    """
    Compress the given project_folder into a zip file named zip_filename.
    """
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(project_folder):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, project_folder)
                zipf.write(full_path, arcname)
    print(f"Project compressed to {zip_filename}")

def upload_project_to_smb(local_file, smb_server, share_name, remote_path, username, password, domain=""):
    """
    Upload a single file (local_file) to the remote_path on the SMB share.
    Ensures the remote directory exists before uploading.
    """
    try:
        conn = SMBConnection(smb_server, smb_server)
        conn.login(username, password, domain)
        print(f"Connected to {smb_server} on share {share_name}")
        ensure_remote_path(conn, share_name, remote_path)
        remote_file = os.path.join(remote_path, os.path.basename(local_file)).replace("\\", "/")
        print(f"Uploading {local_file} to {remote_file}...")
        with open(local_file, 'rb') as fp:
            conn.putFile(share_name, remote_file, fp.read)
        conn.logoff()
        print("Upload completed successfully.")
    except Exception as e:
        print("Upload failed:", e)


def print_summary():
    """
    Print a summary table of the scan results and write it to a summary.txt file.
    For each target, display the host and its status.
    For IPs: "Responded" if any open ports were found, otherwise "Not Responded".
    For URLs: simply mark as "URL Scanned".
    """
    summary_lines = []
    summary_lines.append("=" * 50)
    summary_lines.append("Summary:")
    summary_lines.append("{:<20} | {:<30}".format("Host", "Status"))
    summary_lines.append("-" * 50)
    
    for mode, results in SCAN_RESULTS.items():
        for entry in results:
            if "target" in entry:
                host = entry["target"]
                if "[IP]" in entry["tag"]:
                    if entry.get("open_ports") and len(entry["open_ports"]) > 0:
                        status = "Responded (ports: " + ", ".join(str(p) for p in entry["open_ports"]) + ")"
                    else:
                        status = "Not Responded"
                elif "[URL]" in entry["tag"]:
                    status = "URL Scanned"
                else:
                    status = "Unknown"
                summary_lines.append("{:<20} | {:<30}".format(host, status))
    summary_lines.append("=" * 50)
    summary_str = "\n".join(summary_lines)
    
    # Print summary to the terminal
    print("\n" + summary_str)
    
    # Write summary to summary.txt in the project folder
    summary_file = os.path.join(PROJECT_FOLDER, "summary.txt")
    try:
        with open(summary_file, "w") as f:
            f.write(summary_str)
        logger.info(f"Summary written to {summary_file}")
    except Exception as e:
        logger.info(f"[-] Failed to write summary: {e}")


def check_external_ip_validity():
    """
    Check if the external IP of the host system is within the allowed ranges.
    The allowed external IP ranges are 82.147.10.208/28 and 82.147.10.192/28.
    If not, warn the user to connect to the VPN before proceeding.
    Returns the external IP string.
    """
    ext_ip = get_external_ip()
    if not ext_ip:
        return ""
    valid_networks = [
        ipaddress.ip_network("82.147.10.208/28"),
        ipaddress.ip_network("82.147.10.192/28")
    ]
    try:
        ip_obj = ipaddress.ip_address(ext_ip)
    except ValueError:
        logger.info("[-] Invalid external IP format received.")
        return ext_ip

    if any(ip_obj in net for net in valid_networks):
        logger.info(f"[+] External IP {ext_ip} is valid for testing.")
    else:
        logger.info(f"[-] Warning: External IP {ext_ip} is not within the valid testing ranges.")
        choice = input("Do you want to continue anyway? (y/n): ").strip().lower()
        if choice != 'y':
            sys.exit("Exiting. Please connect to the VPN and try again.")
    return ext_ip


### Raven

# Base Plugin Class
class ScanPlugin:
    """
    Base class for scan plugins.
    Each plugin should define a unique name, a condition (should_run) and execution logic (run).
    """
    name = "base_plugin"

    def should_run(self, host, port, port_data):
        return False

    def run(self, host, port, port_data):
        return None


# Vulnerability Lookup Function
def lookup_vulnerabilities_for_port(port_data):
    """
    Uses a vulnerability database API (example: cve.circl.lu) to lookup CVEs for a service.
    This is a simple example that searches by service name.
    """
    service = port_data.get("service")
    version = port_data.get("version")
    if not service or not version:
        return "No service/version info available for vulnerability lookup."

    url = f"https://cve.circl.lu/api/search/{service}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            # Filter results that mention the version (this logic can be refined)
            vulns = [entry for entry in data if version in json.dumps(entry)]
            if vulns:
                vuln_list = "\n".join(f"- {vuln.get('id', 'Unknown')}: {vuln.get('summary', 'No summary')}" for vuln in vulns)
                return vuln_list
            else:
                return "No vulnerabilities found for this service/version."
        else:
            return "Vulnerability lookup API returned an error."
    except Exception as e:
        return f"Error during vulnerability lookup: {e}"

# Main RavenRecon Class
class RavenRecon:
    def __init__(self, targets, output, mode):
        self.targets = targets
        self.output = output
        self.mode = mode
        self.results = {}
        self.plugins = []
        try:
            self.scanner = nmap.PortScanner()
        except nmap.PortScannerError:
            print("[-] Nmap is not installed or not in PATH. Please install it first.", flush=True)
            sys.exit(1)
        if not self.check_ollama():
            print("[-] Ollama service is not responding. Please ensure it's running.", flush=True)
            sys.exit(1)
        self.load_external_plugins()  # Load additional plugins from the 'plugins' directory

    def load_external_plugins(self, plugins_dir="plugins"):
        """
        Dynamically load external plugins from the specified directory.
        Simply drop your .py plugin files in the 'plugins' folder.
        """
        if not os.path.exists(plugins_dir):
            print(f"[-] Plugins directory '{plugins_dir}' not found. Skipping external plugins.", flush=True)
            return
        for filename in os.listdir(plugins_dir):
            if filename.endswith(".py"):
                module_name = filename[:-3]
                file_path = os.path.join(plugins_dir, filename)
                try:
                    spec = importlib.util.spec_from_file_location(module_name, file_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, ScanPlugin) and obj is not ScanPlugin:
                            plugin_instance = obj()
                            self.register_plugin(plugin_instance)
                except Exception as e:
                    print(f"[-] Failed to load plugin from {filename}: {e}", flush=True)

    def register_plugin(self, plugin):
        self.plugins.append(plugin)
        print(f"[+] Registered plugin: {plugin.name}", flush=True)

    def check_ollama(self):
        try:
            response = requests.get("http://localhost:11434/api/status", timeout=3)
            if response.status_code == 200:
                print("[+] Ollama service is running (status check)", flush=True)
                return True
        except requests.RequestException as e:
            print(f"[-] Ollama /api/status check failed: {e}", flush=True)
        try:
            response = requests.get("http://localhost:11434/api/version", timeout=3)
            if response.status_code == 200:
                print("[+] Ollama service is running (version check)", flush=True)
                return True
        except requests.RequestException as e:
            print(f"[-] Ollama /api/version check failed: {e}", flush=True)
        return False

    def discover_hosts(self):
        print(f"[+] Discovering live hosts in {self.targets}...", flush=True)
        self.scanner.scan(hosts=self.targets, arguments="-sn")
        live_hosts = [host for host in self.scanner.all_hosts() if self.scanner[host].state() == "up"]
        print(f"[+] Found {len(live_hosts)} live hosts", flush=True)
        return live_hosts

    def scan_network(self, live_hosts):
        if not live_hosts:
            print("[-] No live hosts found. Exiting.", flush=True)
            return
        print("[+] Scanning network for open ports and services...", flush=True)
        scan_arguments = "-O -sV --version-all -sC" if self.mode == "full" else "-F"
        # Using concurrent futures to scan each host concurrently
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_host = {executor.submit(self.scan_host, host, scan_arguments): host for host in live_hosts}
            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    self.results[host] = future.result()
                    print(f"[+] Scan completed for {host}", flush=True)
                except Exception as exc:
                    print(f"[-] Error scanning {host}: {exc}", flush=True)
        self.generate_report()

    def scan_host(self, host, arguments):
        print(f"[+] Starting scan on {host} with arguments: {arguments}", flush=True)
        try:
            self.scanner.scan(host, arguments=arguments)
            host_info = {
                "hostname": self.scanner[host].hostname(),
                "state": self.scanner[host].state(),
                "ports": []
            }
            for proto in self.scanner[host].all_protocols():
                for port in self.scanner[host][proto].keys():
                    print(f"[+] Scanning port {port} on {host}...", flush=True)
                    port_info = self.scanner[host][proto][port]
                    port_data = {
                        "port": port,
                        "state": port_info["state"],
                        "service": port_info.get("name", "Unknown"),
                        "version": port_info.get("version", "Unknown"),
                        "raw_output": json.dumps(port_info, indent=2)[:500]
                    }
                    self.grab_banner(host, port, port_data)
                    # Run plugins for applicable ports
                    for plugin in self.plugins:
                        if plugin.should_run(host, port, port_data):
                            result = plugin.run(host, port, port_data)
                            port_data[plugin.name] = result
                    # Optionally, add vulnerability lookup per port
                    port_data["vulnerabilities"] = lookup_vulnerabilities_for_port(port_data)
                    host_info["ports"].append(port_data)
            print(f"[+] Running AI vulnerability analysis for {host}...", flush=True)
            host_info["vulnerabilities_ai"] = self.analyse_vulnerabilities(host_info)
            print(f"[+] AI analysis completed for {host}.", flush=True)
            return host_info
        except Exception as e:
            print(f"[-] Exception scanning {host}: {str(e)}", flush=True)
            return {}

    def grab_banner(self, host, port, port_data):
        print(f"[+] Grabbing banner for {host}:{port}...", flush=True)
        try:
            with socket.create_connection((host, port), timeout=2) as s:
                s.sendall(b"\r\n")
                banner = s.recv(1024).decode("utf-8", "ignore").strip().split("\n")[0]
                if banner:
                    port_data["banner"] = banner[:200]
        except Exception:
            pass

    def analyse_vulnerabilities(self, host_info):
        # Create a payload that only includes essential info to avoid overloading the AI model
        trimmed_data = {
            "hostname": host_info.get("hostname"),
            "ports": [
                {
                    "port": port.get("port"),
                    "state": port.get("state"),
                    "service": port.get("service"),
                    "version": port.get("version"),
                    "banner": port.get("banner", "")
                }
                for port in host_info.get("ports", [])
            ]
        }
        response = ollama.chat(
            model='llama3.2',
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert. Analyse the scan results and identify potential vulnerabilities. Provide a list with a brief description and remediation advice for each vulnerability."},
                {"role": "user", "content": f"Scan Data:\n{json.dumps(trimmed_data, indent=2)}"}
            ]
        )
        return response["message"]["content"]

    def count_vulnerabilities(self, vulnerabilities_text):
        return len(re.findall(r'\*\*Vulnerability \d+:', vulnerabilities_text))

    def generate_report(self):
        print("[+] Generating report...", flush=True)
        report_md = f"# Internal Network Scan Report\n\n"
        report_md += f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report_md += f"**Targets:** {self.targets}\n\n"
        if not self.results:
            print("[-] No scan results to report.", flush=True)
            return
        total_hosts = len(self.results)
        total_ports = sum(len(data.get("ports", [])) for data in self.results.values())
        total_vulns = sum(self.count_vulnerabilities(data.get("vulnerabilities_ai", "")) for data in self.results.values())
        print(f"[+] Scan Summary:\n Hosts Scanned: {total_hosts}\n Ports Scanned: {total_ports}\n Vulnerabilities Found (AI): {total_vulns}", flush=True)
        report_md += "**Scan Summary:**\n"
        report_md += f"- Hosts Scanned: {total_hosts}\n"
        report_md += f"- Ports Scanned: {total_ports}\n"
        report_md += f"- Vulnerabilities Found (AI): {total_vulns}\n\n"
        for host, data in self.results.items():
            report_md += f"## Host: {host} ({data.get('hostname', 'Unknown')})\n"
            report_md += f"| Port  | State | Service | Version | Banner |\n"
            report_md += f"|-------|-------|---------|---------|--------|\n"
            for port in data.get("ports", []):
                report_md += f"| {port['port']}/tcp | {port['state']} | {port['service']} | {port['version']} | {port.get('banner', 'N/A')} |\n"
                if "ssl_scan" in port:
                    report_md += f"\n**SSL Scan Result:**\n```\n{port['ssl_scan']}\n```\n"
                # Include vulnerability lookup results per port
                report_md += f"\n**Vulnerability Lookup Result:**\n```\n{port.get('vulnerabilities', 'No vulnerabilities found.')}\n```\n"
            report_md += "\n## AI Vulnerability Analysis\n\n"
            report_md += data.get("vulnerabilities_ai", "No vulnerabilities identified.") + "\n\n"
        with open(self.output, "w") as f:
            f.write(report_md)
        print(f"[+] Report saved to {self.output}", flush=True)


def main():
    global PROJECT_FOLDER, logger
    smb_server = "192.168.8.239"
    smb_share = "Media"
    smb_user = ""
    smb_pass = ""
    parser = argparse.ArgumentParser(
        description="Integrated PenTest Pre-Flight Check Tool with Custom Settings, XML Output, and Summary"
    )
    parser.add_argument("-s", "--settings", help="Path to an XML file for custom settings")
    parser.add_argument("--targets",help="Target IP range (e.g., 192.168.1.0/24)")
    parser.add_argument("--output", default="raven_report.md", help="Output file for Markdown report")
    parser.add_argument("--mode", choices=["quick", "full"], default="quick", help="Scan mode: quick (top 100 ports) or full (all ports)")
    args = parser.parse_args()
    if args.settings:
        load_custom_settings(args.settings)
    

    # Setup unified logging     
    log_file = os.path.join(PROJECT_FOLDER, "preflight_log.txt")
    logger = setup_logging(log_file)
    logger.info("Unified logging is now configured.")

    # Check external IP validity before proceeding with tests.
    check_external_ip_validity()

    proj_number = input("Enter Project Number (or press Enter to use default PR00000): ").strip()
    if not proj_number:
        proj_number = "PR00000"
    PROJECT_FOLDER = create_project_structure(proj_number)



    split_scope_file()
    int_scope_path = os.path.join(PROJECT_FOLDER, "int_scope.txt")
    ext_scope_path = os.path.join(PROJECT_FOLDER, "ext_scope.txt")
    web_scope_path = os.path.join(PROJECT_FOLDER, "web_scope.txt")
    run_checks("int", int_scope_path)
    run_checks("ext", ext_scope_path)
    run_checks("web", web_scope_path)
    if CUSTOM_SETTINGS.get("output_format") == "XML":
        write_xml_output()
    print_summary()


    # Optionally prompt for SMB upload (as before)
    upload_choice = input("Do you want to upload the project folder to an SMB share? (y/n): ").strip().lower()
    if upload_choice == 'y':
        # Compress and upload
        zip_filename = os.path.join(PROJECT_FOLDER, os.path.basename(PROJECT_FOLDER) + ".zip")
        compress_project_folder(PROJECT_FOLDER, zip_filename)
        print("Zip file created:", zip_filename)
        remote_path = os.path.join("Projects", os.path.basename(PROJECT_FOLDER))
        upload_project_to_smb(zip_filename, smb_server, smb_share, remote_path, smb_user, smb_pass)

    # Now, feed the pre-flight targets to RavenRecon:
    recon_targets = get_recon_targets()
    logger.info(f"Recon targets: {recon_targets}")
    if recon_targets:
        perform_test = input("Do you want to perform automatic testing? (y/n): ").strip().lower()
        if perform_test == 'y':
            raven = RavenRecon(recon_targets, args.output, args.mode)
            live_hosts = raven.discover_hosts()
            if live_hosts:
                raven.scan_network(live_hosts)
            else:
                print("[-] No live hosts found. Exiting.", flush=True)
    else:
        print("[-] No recon targets found from scope files. Exiting.", flush=True)


if __name__ == "__main__":
    main()