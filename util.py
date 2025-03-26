import os
import re
import json
import logging
import termios
import requests

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
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    file_handler = logging.FileHandler(log_file, mode='a')
    file_handler.setFormatter(formatter)
    if logger.hasHandlers():
        logger.handlers.clear()
    logger.addHandler(console_handler)
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
