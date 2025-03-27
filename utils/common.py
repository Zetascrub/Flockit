import os
import re
import json
import ipaddress
from collections import defaultdict
import xml.etree.ElementTree as ET
import logging
import termios
import requests
from termcolor import cprint

# --- Main Function ---
AUTO_MODE = False  # Global flag for auto mode

def restore_terminal_settings(fd, original_term_settings):
    termios.tcsetattr(fd, termios.TCSADRAIN, original_term_settings)

def expand_ip_range(entry):
    match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$", entry)
    if match:
        base = match.group(1)
        start = int(match.group(2))
        end = int(match.group(3))
        if 0 <= start <= end <= 255:
            return [f"{base}{i}" for i in range(start, end + 1)]
    return [entry]

def is_domain(entry):
    if re.match(r"^(?!http://|https://)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", entry):
        return True
    return False

def prompt_yes_no(prompt, auto_mode=False):
    if auto_mode:
        return 'y'
    return input(prompt).strip().lower()

def create_project_structure(proj_number):
    base_folder = proj_number if proj_number else "PR00000"
    if not os.path.isdir(base_folder):
        os.makedirs(base_folder)
        logging.getLogger().info(f"Created project folder: {base_folder}")
    else:
        logging.getLogger().info(f"Project folder '{base_folder}' already exists.")
    for sub in ["Screenshots", "Scan-Data"]:
        sub_path = os.path.join(base_folder, sub)
        if not os.path.isdir(sub_path):
            os.makedirs(sub_path)
            logging.getLogger().info(f"Created folder: {sub_path}")
        else:
            logging.getLogger().info(f"Folder '{sub_path}' already exists.")
    return base_folder

def ensure_remote_path(conn, share, remote_path):
    parts = remote_path.strip("/").split("/")
    current_path = ""
    for part in parts:
        current_path = current_path + "/" + part if current_path else part
        try:
            conn.createDirectory(share, current_path)
        except Exception:
            pass

def setup_logging(log_file):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    # Remove all previous handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    # File handler only
    file_handler = logging.FileHandler(log_file, mode='a')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger

def lookup_vulnerabilities_for_port(port_data):
    service = port_data.get("service")
    version = port_data.get("version")
    if not service or not version:
        return "No service/version info available for vulnerability lookup."
    url = f"https://cve.circl.lu/api/search/{service}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
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

def generate_ascii_visualisation(results):
    """
    Generate an ASCII visual representation of scanned hosts and their services.
    Grouped by /24 subnet.
    """
    subnet_groups = defaultdict(list)

    # Group hosts by /24 subnet
    for host, data in results.items():
        try:
            net = ipaddress.IPv4Network(host + '/24', strict=False)
            subnet_groups[str(net)].append((host, data))
        except ValueError:
            continue

    ascii_output = []
    ascii_output.append("\n======= ASCII Network Map =======\n")

    for subnet, hosts in sorted(subnet_groups.items()):
        ascii_output.append(f"Subnet: {subnet}")
        for host, data in sorted(hosts):
            line = f"[{host}]"
            services = [
                port.get("service", "unknown").upper()
                for port in data.get("ports", [])
                if port.get("state") == "open"
            ]
            if services:
                branches = [f" ──┬─ [{services[0]}]"]
                for svc in services[1:]:
                    branches.append(f"   ├─ [{svc}]")
                line += "\n" + "\n".join(branches)
            else:
                line += " ── No services detected"
            ascii_output.append(line)
        ascii_output.append("")  # Blank line between subnets

    return "\n".join(ascii_output)

def print_status(msg, level="info"):
    symbols = {
        "info":    ("[~]", "cyan"),
        "success": ("✅", "green"),
        "warning": ("⚠️", "yellow"),
        "error":   ("❌", "red"),
        "scan":    ("🔍", "blue"),
        "upload":  ("📤", "magenta"),
        "report":  ("📄", "white"),
    }
    symbol, color = symbols.get(level, ("[~]", "white"))

    # Terminal output
    cprint(f"{symbol} {msg}", color, attrs=["bold"])

    # Log file output
    logger = logging.getLogger()
    log_method = {
        "info": logger.info,
        "success": logger.info,
        "warning": logger.warning,
        "error": logger.error,
        "scan": logger.info,
        "upload": logger.info,
        "report": logger.info,
    }.get(level, logger.info)
    log_method(msg)

def print_banner(title):
    cprint("\n" + "=" * 50, "blue", attrs=["bold"])
    cprint(f"{title.center(50)}", "blue", attrs=["bold"])
    cprint("=" * 50 + "\n", "blue", attrs=["bold"])

def load_settings_xml(filepath="settings.xml"):
    print_status("Loading Custom Settings","info")
    default_settings = {
        "ports": [22, 80, 443, 445, 3389],
        "timeout": 0.5,
        "external_ip_url": "https://api.ipify.org",
        "output_format": "XML",
        "smb_server": "",
        "smb_share": "",
        "smb_username": "",
        "valid_external_ranges": []
    }

    if not os.path.exists(filepath):
        print_status("settings.xml not found. Using default settings.", "warning")
        return default_settings

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()

        ports = root.findtext("Ports")
        timeout = root.findtext("Timeout")
        external_ip_url = root.findtext("ExternalIPURL")
        output_format = root.findtext("OutputFormat")

        smb = root.find("SMB")
        smb_server = smb.findtext("Server") if smb is not None else ""
        smb_share = smb.findtext("Share") if smb is not None else ""
        smb_username = smb.findtext("Username") if smb is not None else ""

        # NEW: Parse valid external IP ranges
        valid_ranges = [r.text.strip() for r in root.findall(".//ValidExternalRanges/Range") if r.text]

        return {
            "ports": [int(p.strip()) for p in ports.split(",")] if ports else default_settings["ports"],
            "timeout": float(timeout) if timeout else default_settings["timeout"],
            "external_ip_url": external_ip_url or default_settings["external_ip_url"],
            "output_format": output_format or default_settings["output_format"],
            "smb_server": smb_server,
            "smb_share": smb_share,
            "smb_username": smb_username,
            "valid_external_ranges": valid_ranges or default_settings["valid_external_ranges"]
        }

    except Exception as e:
        print_status(f"Error loading settings.xml: {e}", "error")
        return default_settings


CUSTOM_SETTINGS = load_settings_xml()