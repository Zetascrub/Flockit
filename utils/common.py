import os
import re
import json
import ipaddress
from collections import defaultdict
import xml.etree.ElementTree as ET
import logging
import requests
import ollama
from termcolor import cprint

VERBOSITY = ""

if os.name == "nt":
    import msvcrt
else:
    import tty
    import termios

# --- Main Function ---
AUTO = {
    "general": False,
    "upload": False,
    "ai_analysis": False,
    "view_report": False
}

CUSTOM_SETTINGS = {}


# def restore_terminal_settings(fd, original_term_settings):
#     termios.tcsetattr(fd, termios.TCSADRAIN, original_term_settings)

def expand_ip_range(entry):
    match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}-\d{1,3}$", entry)
    if match:
        base = match.group(1)
        start, end = map(int, entry[len(base):].split('-'))
        if 0 <= start <= end <= 255:
            return [f"{base}{i}" for i in range(start, end + 1)]
    return [entry]

def is_domain(entry):
    return bool(re.match(r"^(?!http://|https://)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", entry))

def prompt_yes_no(prompt, auto_key=None):
    if auto_key is None:
        auto_mode = AUTO["general"]
    else:
        auto_mode = AUTO.get(auto_key, AUTO["general"])
    return 'y' if auto_mode else input(prompt).strip().lower()

def create_project_structure(proj_number):
    base_folder = proj_number or "PR00000"
    os.makedirs(base_folder, exist_ok=True)
    logging.getLogger().info(f"Created or confirmed project folder: {base_folder}")
    for sub in ["Screenshots", "Scan-Data"]:
        sub_path = os.path.join(base_folder, sub)
        os.makedirs(sub_path, exist_ok=True)
        logging.getLogger().info(f"Created or confirmed folder: {sub_path}")
    return base_folder

def ensure_remote_path(conn, share, remote_path):
    parts = remote_path.strip("/").split("/")
    current_path = ""
    for part in parts:
        current_path = f"{current_path}/{part}" if current_path else part
        try:
            conn.createDirectory(share, current_path)
        except Exception:
            pass

def setup_logging(log_file):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    logger.handlers.clear()
    file_handler = logging.FileHandler(log_file, mode='a')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

def lookup_vulnerabilities_for_port(port_data):
    service, version = port_data.get("service"), port_data.get("version")
    if not service or not version:
        return "No service/version info available for vulnerability lookup."
    try:
        response = requests.get(f"https://cve.circl.lu/api/search/{service}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            vulns = [entry for entry in data if version in json.dumps(entry)]
            return "\n".join(f"- {v.get('id', 'Unknown')}: {v.get('summary', 'No summary')}" for v in vulns) or "No vulnerabilities found."
        return "Vulnerability lookup API returned an error."
    except Exception as e:
        return f"Error during vulnerability lookup: {e}"

def generate_ascii_visualisation(results):
    subnet_groups = defaultdict(list)
    for host, data in results.items():
        try:
            net = ipaddress.IPv4Network(f"{host}/24", strict=False)
            subnet_groups[str(net)].append((host, data))
        except ValueError:
            continue
    ascii_output = ["\n======= ASCII Network Map =======\n"]
    for subnet, hosts in sorted(subnet_groups.items()):
        ascii_output.append(f"Subnet: {subnet}")
        for host, data in sorted(hosts):
            line = f"[{host}]"
            services = [port.get("service", "unknown").upper() for port in data.get("ports", []) if port.get("state") == "open"]
            if services:
                branches = [f" ──┬─ [{services[0]}]"] + [f"   ├─ [{svc}]" for svc in services[1:]]
                line += "\n" + "\n".join(branches)
            else:
                line += " ── No services detected"
            ascii_output.append(line)
        ascii_output.append("")
    return "\n".join(ascii_output)

def print_status(msg, level="info"):
    symbols = {
        "debug": ("[DEBUG]", "magenta"),
        "info":  ("[~]", "cyan"),
        "success": ("✅", "green"),
        "warning": ("⚠️", "yellow"),
        "error": ("❌", "red")
    }
    # Quiet mode: only warnings and errors.
    if VERBOSITY == "quiet" and level not in ["warning", "error"]:
        return
    # Info mode: skip debug.
    if VERBOSITY == "info" and level == "debug":
        return

    symbol, color = symbols.get(level, ("[~]", "white"))
    cprint(f"{symbol} {msg}", color, attrs=["bold"])
    log_method = {
        "info": logging.info,
        "success": logging.info,
        "warning": logging.warning,
        "error": logging.error,
        "scan": logging.info,
        "upload": logging.info,
        "report": logging.info,
    }.get(level, logging.info)
    log_method(msg)

def print_banner(title):
    # Skip banners in quiet mode.
    if VERBOSITY == "quiet":
        return
    cprint("\n" + "=" * 50, "blue", attrs=["bold"])
    cprint(f"{title.center(50)}", "blue", attrs=["bold"])
    cprint("=" * 50 + "\n", "blue", attrs=["bold"])

def load_settings_xml(filepath="settings_dev.xml"):
    print_status("Loading Custom Settings","info")
    default_settings = {
        "ports": [22, 80, 443, 445, 3389],
        "timeout": 0.5,
        "external_ip_url": "https://api.ipify.org",
        "output_format": "XML",
        "smb_server": "",
        "smb_share": "",
        "smb_username": "",
        "valid_external_ranges": [],
        "OllamaHost": "localhost",
        "OllamaModel": "llama3.2"
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
        valid_ranges = [r.text.strip() for r in root.findall(".//ValidExternalRanges/Range") if r.text]
        settings = {
            "ports": [int(p.strip()) for p in ports.split(",")] if ports else default_settings["ports"],
            "timeout": float(timeout) if timeout else default_settings["timeout"],
            "external_ip_url": external_ip_url or default_settings["external_ip_url"],
            "output_format": output_format or default_settings["output_format"],
            "smb_server": smb_server,
            "smb_share": smb_share,
            "smb_username": smb_username,
            "valid_external_ranges": valid_ranges or default_settings["valid_external_ranges"],
            "OllamaHost": root.findtext("OllamaHost") or default_settings["OllamaHost"],
            "OllamaModel": root.findtext("OllamaModel") or default_settings["OllamaModel"]
        }
        return settings
    except Exception as e:
        print_status(f"Error loading settings.xml: {e}", "error")
        return default_settings

CUSTOM_SETTINGS = load_settings_xml()

def check_ollama():
    host = CUSTOM_SETTINGS.get("ollama_host", "localhost:11434")

    try:
        response = requests.get(f"http://{host}/api/status", timeout=3)
        if response.status_code == 200:
            print_status("[+] Ollama service is running (/api/status check)", "info")
            return True
        else:
            print_status(f"[~] /api/status returned {response.status_code}", "warning")
    except requests.RequestException as e:
        print_status(f"[!] /api/status unreachable: {e}", "warning")

    try:
        response = requests.get(f"http://{host}/api/version", timeout=3)
        if response.status_code == 200:
            print_status("[+] Ollama service is running (/api/version check)", "info")
            return True
        else:
            print_status(f"[~] /api/version returned {response.status_code}", "warning")
    except requests.RequestException as e:
        print_status(f"[!] /api/version unreachable: {e}", "warning")

    print_status("[-] Ollama does not appear to be running correctly.", "error")
    return False


def ollama_chat(system_prompt, user_prompt, model=None):
    import json

    host = CUSTOM_SETTINGS.get("ollama_host", "localhost:11434").replace("http://", "").replace("https://", "")
    model = model or CUSTOM_SETTINGS.get("ollama_model", "llama3.2")
    url = f"http://{host}/api/chat"

    payload = {
        "model": model,
        "stream": True,  # Request streamed response
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
    }

    try:
        response = requests.post(url, json=payload, stream=True, timeout=30)

        content_accumulator = []
        for line in response.iter_lines(decode_unicode=True):
            if not line.strip():
                continue
            try:
                chunk = json.loads(line)
                content_piece = chunk.get("message", {}).get("content", "")
                if content_piece:
                    content_accumulator.append(content_piece)
            except json.JSONDecodeError as e:
                print_status(f"[!] Stream chunk parse failed: {e}", "warning")

        return "".join(content_accumulator).strip()

    except requests.RequestException as e:
        print_status(f"[!] Ollama streaming request failed: {e}", "error")
        return "⚠️ Ollama Error: Failed to connect to Ollama. Please check that Ollama is downloaded, running and accessible."

def set_custom_settings(settings):
    global CUSTOM_SETTINGS
    CUSTOM_SETTINGS = settings


def save_scan_output(host, filename, content, base_dir=None):
    """
    Saves output content to <base_dir>/Scan-Data/<host>/<filename>
    """
    if base_dir is None:
        base_dir = os.getcwd()
    elif os.path.isfile(base_dir):
        base_dir = os.path.dirname(base_dir)
    elif base_dir.endswith(".md"):
        base_dir = os.path.dirname(base_dir)





    full_path = os.path.join(base_dir, "Scan-Data", host)
    os.makedirs(full_path, exist_ok=True)

    file_path = os.path.join(full_path, filename)
    try:
        with open(file_path, "w") as f:
            f.write(content)
        print_status(f"[+] Saved scan output to {file_path}", "info")
    except Exception as e:
        print_status(f"[!] Failed to write {file_path}: {e}", "error")


