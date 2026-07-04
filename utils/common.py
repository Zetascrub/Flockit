import os
import re
import json
import ipaddress
import importlib.util
import shutil
from collections import defaultdict
import xml.etree.ElementTree as ET
import logging
import requests

try:
    from termcolor import cprint
except ImportError:
    def cprint(text, color=None, attrs=None):
        print(text)

VERBOSITY = ""

if os.name == "nt":
    import msvcrt
else:
    import tty
    import termios

import logging
logging.getLogger("fontTools").setLevel(logging.ERROR)
logging.getLogger("weasyprint").setLevel(logging.ERROR)
logging.getLogger().setLevel(logging.WARNING)
logging.root.setLevel(logging.WARNING)


VERBOSITY = "info"  # Default can be 'debug', 'info', or 'quiet'


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

def prompt_yes_no(prompt, auto=False):
    if auto:
        return True
    return input(prompt).strip().lower() in ("y", "yes")

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
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()
    file_handler = logging.FileHandler(log_file, mode='a')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

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
    def normalize_ollama_host(host):
        host = (host or "localhost:11434").replace("http://", "").replace("https://", "").strip()
        if ":" not in host:
            host = f"{host}:11434"
        return host

    default_settings = {
        "ports": [22, 80, 443, 445, 3389],
        "timeout": 0.5,
        "external_ip_url": "https://api.ipify.org",
        "output_format": "XML",
        "smb_server": "",
        "smb_share": "",
        "smb_username": "",
        "valid_external_ranges": [],
        "default_ai_provider": "ollama",
        "ollama_host": "localhost:11434",
        "ollama_model": "llama3.2",
        "openai_api_key": "",
        "openai_model": "gpt-4",
        "cve_source": "nvd",
        "nvd_api_key": "",
        "cve_cache_ttl_days": 30,
        "adaptive_escalation_threshold": 2,
        "adaptive_peer_escalation_threshold": 1,
        "adaptive_max_escalated_hosts": 25,
        "adaptive_high_value_ports": None,
        "adaptive_notable_version_patterns": None,
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
        openai = root.find("OpenAI")
        valid_ranges = [r.text.strip() for r in root.findall(".//ValidExternalRanges/Range") if r.text]

        cve = root.find("CVE")
        cve_source = (cve.findtext("Source") if cve is not None else None) or default_settings["cve_source"]
        nvd_api_key = (cve.findtext("NVDApiKey") if cve is not None else None) or default_settings["nvd_api_key"]
        cve_cache_ttl_raw = cve.findtext("CacheTTLDays") if cve is not None else None
        cve_cache_ttl_days = int(cve_cache_ttl_raw) if cve_cache_ttl_raw else default_settings["cve_cache_ttl_days"]

        adaptive = root.find("AdaptiveScan")
        def _adaptive_int(tag, default):
            raw = adaptive.findtext(tag) if adaptive is not None else None
            return int(raw) if raw else default
        adaptive_escalation_threshold = _adaptive_int("EscalationThreshold", default_settings["adaptive_escalation_threshold"])
        adaptive_peer_escalation_threshold = _adaptive_int("PeerEscalationThreshold", default_settings["adaptive_peer_escalation_threshold"])
        adaptive_max_escalated_hosts = _adaptive_int("MaxEscalatedHosts", default_settings["adaptive_max_escalated_hosts"])
        high_value_ports_raw = adaptive.findtext("HighValuePorts") if adaptive is not None else None
        adaptive_high_value_ports = [int(p.strip()) for p in high_value_ports_raw.split(",")] if high_value_ports_raw else None
        pattern_nodes = adaptive.findall("./NotableVersionPatterns/Pattern") if adaptive is not None else []
        adaptive_notable_version_patterns = [p.text.strip() for p in pattern_nodes if p.text] or None

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
            "default_ai_provider": (root.findtext("DefaultAIProvider") or default_settings["default_ai_provider"]).lower(),
            "ollama_host": normalize_ollama_host(root.findtext("OllamaHost") or default_settings["ollama_host"]),
            "ollama_model": root.findtext("OllamaModel") or default_settings["ollama_model"],
            "openai_api_key": openai.findtext("APIKey") if openai is not None and openai.findtext("APIKey") else default_settings["openai_api_key"],
            "openai_model": openai.findtext("Model") if openai is not None and openai.findtext("Model") else default_settings["openai_model"],
            "cve_source": cve_source.lower(),
            "nvd_api_key": nvd_api_key,
            "cve_cache_ttl_days": cve_cache_ttl_days,
            "adaptive_escalation_threshold": adaptive_escalation_threshold,
            "adaptive_peer_escalation_threshold": adaptive_peer_escalation_threshold,
            "adaptive_max_escalated_hosts": adaptive_max_escalated_hosts,
            "adaptive_high_value_ports": adaptive_high_value_ports,
            "adaptive_notable_version_patterns": adaptive_notable_version_patterns,
        }
        return settings
    except Exception as e:
        print_status(f"Error loading settings.xml: {e}", "error")
        return default_settings

def set_verbosity(level):
    global VERBOSITY
    VERBOSITY = level


def check_dependencies(scan=False, ai=False, upload=False, pdf=False, ai_config=None):
    checks = []

    if scan:
        checks.append(("nmap CLI", shutil.which("nmap") is not None, "Install nmap and ensure it is in PATH."))
        checks.append(("python-nmap", importlib.util.find_spec("nmap") is not None, "Install Python dependencies with `pip install -r requirements.txt`."))

    if ai and ai_config is not None:
        if ai_config.provider == "openai":
            checks.append(("openai", importlib.util.find_spec("openai") is not None, "Install Python dependencies with `pip install -r requirements.txt`."))
            api_key = ai_config.openai_api_key
            checks.append(("OpenAI API key", bool(api_key and "apikey" not in api_key.lower()), "Set OpenAI/APIKey in settings.xml."))
        else:
            from utils.ai_client import AIClient  # local import: avoids a circular import with utils.common
            checks.append(("Ollama service", AIClient(ai_config).available(), "Start Ollama or disable AI analysis."))

    if upload:
        checks.append(("impacket", importlib.util.find_spec("impacket") is not None, "Install Python dependencies with `pip install -r requirements.txt`."))

    if pdf:
        checks.append(("markdown", importlib.util.find_spec("markdown") is not None, "Install Python dependencies with `pip install -r requirements.txt`."))
        checks.append(("weasyprint", importlib.util.find_spec("weasyprint") is not None, "Install Python dependencies with `pip install -r requirements.txt`."))

    missing = []
    for name, ok, fix in checks:
        if ok:
            print_status(f"Dependency OK: {name}", "debug")
        else:
            missing.append((name, fix))
            print_status(f"Missing dependency: {name}. {fix}", "warning")

    return missing


def convert_markdown_to_pdf(md_path, output_path=None):
    try:
        import markdown
        from weasyprint import HTML

        # Suppress all font and rendering logs
        for noisy_logger in [
            "fontTools",
            "fontTools.ttLib",
            "fontTools.subset",
            "weasyprint",
            "weasyprint.css",
            "weasyprint.document",
            "weasyprint.text",
            "weasyprint.fonts",
            "weasyprint.logger"
        ]:
            logging.getLogger(noisy_logger).setLevel(logging.CRITICAL)

        if output_path is None:
            output_path = md_path.replace(".md", ".pdf")

        with open(md_path, "r", encoding="utf-8") as f:
            html = markdown.markdown(f.read(), extensions=["extra", "tables", "toc"])

        HTML(string=html).write_pdf(output_path)
        print_status(f"[+] PDF report generated at {output_path}", "success")

    except ImportError:
        print_status("❌ WeasyPrint or markdown module not found. Install with `pip install weasyprint markdown`", "error")
    except Exception as e:
        print_status(f"❌ PDF export failed: {e}", "error")
