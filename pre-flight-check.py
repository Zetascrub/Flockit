#!/usr/bin/env python3
import os
import re
import sys
import ipaddress
import socket
from datetime import datetime
import requests
from termcolor import colored
import xml.etree.ElementTree as ET
import xml.dom.minidom as md
import argparse

# Global variables for custom settings and scan results
CUSTOM_SETTINGS = {
    "ports": [22, 80, 443, 445, 3389],
    "timeout": 0.5,
    "external_ip_url": "https://api.ipify.org",
    "output_format": "XML"  # default output format
}

SCAN_RESULTS = {}  # Dictionary to store scan results per mode
PROJECT_FOLDER = ""  # Set in main()

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
        print(colored("[*] Custom settings loaded from XML.", "cyan"))
    except Exception as e:
        print(colored(f"[-] Failed to load settings from {xml_path}: {e}", "red"))

def log(message):
    """Append a timestamped message to the log file in the project folder and print it."""
    log_file = os.path.join(PROJECT_FOLDER, "preflight_log.txt")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"
    with open(log_file, "a") as f:
        f.write(full_message + "\n")
    print(full_message)

def get_external_ip():
    """Retrieve and log the external IP address using custom or default URL."""
    try:
        ip = requests.get(CUSTOM_SETTINGS["external_ip_url"]).text
        print(colored(f"[+] External IP Address: {ip}", "green"))
        log(f"External IP Address: {ip}")
        return ip
    except requests.RequestException:
        print(colored("[-] Unable to determine external IP address.", "red"))
        log("Unable to determine external IP address.")
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
        # Check if the entry is an IP range
        if "-" in entry and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$", entry):
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
            # Try to see if it's an IP or CIDR
            try:
                ipaddress.ip_network(entry, strict=False)
                if is_internal_ip(entry):
                    int_entries.append(entry)
                else:
                    ext_entries.append(entry)
                continue
            except ValueError:
                pass

            # Check if it's a URL (with protocol)
            if re.match(r"^https?://", entry):
                web_entries.append(entry)
            # Check if it's a bare domain; if so, prepend http://
            elif is_domain(entry):
                web_entries.append("http://" + entry)
            else:
                print(colored(f"[-] Unrecognized scope entry format: {entry}", "red"))
    
    if int_entries:
        with open(INT_SCOPE_FILE, "w") as f:
            for line in int_entries:
                f.write(line + "\n")
        print(f"Created int_scope.txt with {len(int_entries)} entries (Internal IPs).")
    else:
        if os.path.exists(INT_SCOPE_FILE):
            os.remove(INT_SCOPE_FILE)
        print("No internal IPs found; int_scope.txt not created.")

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
        print(colored(f"[-] {os.path.basename(file_path)} not found.", "red"))
        log(f"{os.path.basename(file_path)} not found.")
        return []
    with open(file_path, "r") as f:
        entries = [line.strip() for line in f if line.strip()]
    if not entries:
        print(colored(f"[-] {os.path.basename(file_path)} is empty.", "red"))
        log(f"{os.path.basename(file_path)} is empty.")
    return entries

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
    print(colored(f"[*] Scanning common ports on {ip}...", "yellow"))
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
        print(colored(f"[+] Open ports on {ip}: {open_ports}", "green"))
        log(f"Open ports on {ip}: {open_ports}")
    else:
        print(colored(f"[-] No common ports open on {ip}", "red"))
        log(f"No common ports open on {ip}")
    return open_ports

def run_checks(mode, file_path):
    """
    Run pre-flight checks for a given mode (int, ext, web) using the specified scope file.
    For external and web modes, fetch the external IP.
    Accumulate results in the global SCAN_RESULTS dictionary.
    """
    print(colored(f"[*] Running pre-flight checks for: {mode.upper()}", "blue"))
    mode_results = []
    if mode in ["ext", "web"]:
        ext_ip = get_external_ip()
        mode_results.append({"external_ip": ext_ip})
    scope_entries = check_scope_file(file_path)
    if not scope_entries:
        print(colored(f"[-] Skipping {mode.upper()} checks due to no entries.", "red"))
        return
    for entry in scope_entries:
        result = {}
        result["target"] = entry
        result["tag"] = auto_tag(entry)
        print(colored(f"[~] {result['tag']}", "magenta"))
        log(f"Tagged scope entry: {result['tag']}")
        if "[IP]" in result["tag"]:
            result["open_ports"] = port_scan(entry)
        mode_results.append(result)
    print(colored(f"[+] {mode.upper()} pre-flight checks passed.\n", "green"))
    log(f"{mode.upper()} pre-flight checks passed.")
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
    print(colored(f"Scan results written to {xml_file}", "cyan"))

def print_summary():
    """
    Print a summary table of the scan results.
    For each target, display the host and its status.
    For IPs: "Responded" if any open ports were found, otherwise "Not Responded".
    For URLs: simply mark as "URL Scanned".
    """
    print("\n" + "=" * 50)
    print("Summary:")
    print("{:<20} | {:<30}".format("Host", "Status"))
    print("-" * 50)
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
                print("{:<20} | {:<30}".format(host, status))
    print("=" * 50)

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

def main():
    global PROJECT_FOLDER
    parser = argparse.ArgumentParser(
        description="Integrated PenTest Pre-Flight Check Tool with Custom Settings, XML Output, and Summary"
    )
    parser.add_argument("-s", "--settings", help="Path to an XML file for custom settings")
    args = parser.parse_args()
    if args.settings:
        load_custom_settings(args.settings)
    
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

if __name__ == "__main__":
    main()
