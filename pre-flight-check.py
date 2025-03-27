#!/usr/bin/env python3
import sys
import ipaddress
import socket
import zipfile
from datetime import datetime
from termcolor import colored
import xml.etree.ElementTree as ET
import xml.dom.minidom as md
import argparse
from impacket.smbconnection import SMBConnection
import nmap
import subprocess
import importlib.util
import inspect
import ollama
import atexit
import getpass
from util import *
 

version = "0.6.2"

# Global variables for custom settings and scan results
CUSTOM_SETTINGS = load_settings_xml()


SCAN_RESULTS = {}  # Dictionary to store scan results per mode
PROJECT_FOLDER = ""  # Set in main()


# --- PreFlightCheck Class ---
class PreFlightCheck:
    def __init__(self, project_folder):
        self.project_folder = project_folder

    def split_scope_file(self):
        MAIN_SCOPE_FILE = "scope.txt"
        INT_SCOPE_FILE = os.path.join(self.project_folder, "int_scope.txt")
        EXT_SCOPE_FILE = os.path.join(self.project_folder, "ext_scope.txt")
        WEB_SCOPE_FILE = os.path.join(self.project_folder, "web_scope.txt")
        logger = logging.getLogger()  # using global logger

        if not os.path.isfile(MAIN_SCOPE_FILE):
            sample = "192.168.8.1\n192.168.8.10-12\nExample.com\n192.168.9.0/24\n"
            print_status("scope.txt not found. Creating a sample scope.txt...", "warning")
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
                for ip in expand_ip_range(entry):
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
                    print_status(f"[-] Unrecognized scope entry format: {entry}", "error")

        # Save results
        if int_entries:
            with open(INT_SCOPE_FILE, "w") as f:
                for line in int_entries:
                    f.write(line + "\n")
            print_status(f"Created int_scope.txt with {len(int_entries)} entries (Internal IPs).","info")
        else:
            if os.path.exists(INT_SCOPE_FILE):
                os.remove(INT_SCOPE_FILE)
            print_status("No internal IPs found; int_scope.txt not created.","info")

        if ext_entries:
            with open(EXT_SCOPE_FILE, "w") as f:
                for line in ext_entries:
                    f.write(line + "\n")
            print_status(f"Created ext_scope.txt with {len(ext_entries)} entries (External IPs).", "info")
        else:
            if os.path.exists(EXT_SCOPE_FILE):
                os.remove(EXT_SCOPE_FILE)
            print_status("No external IPs found; ext_scope.txt not created.", "warning")

        if web_entries:
            with open(WEB_SCOPE_FILE, "w") as f:
                for line in web_entries:
                    f.write(line + "\n")
            print_status(f"Created web_scope.txt with {len(web_entries)} entries (Website URLs).", "info")
        else:
            if os.path.exists(WEB_SCOPE_FILE):
                os.remove(WEB_SCOPE_FILE)
            print_status("No website URLs found; web_scope.txt not created.","warning")

    def check_external_ip_validity(self):
        ext_ip = requests.get(CUSTOM_SETTINGS["external_ip_url"]).text
        logger = logging.getLogger()
        if not ext_ip:
            return ""
        valid_networks = [
            ipaddress.ip_network("82.147.10.208/28"),
            ipaddress.ip_network("82.147.10.192/28")
        ]
        try:
            ip_obj = ipaddress.ip_address(ext_ip)
        except ValueError:
            print_status("[-] Invalid external IP format received.", "error")
            return ext_ip
        if any(ip_obj in net for net in valid_networks):
            print_status(f"[+] External IP {ext_ip} is valid for testing.", "info")
        else:
            print_status(f"[-] Warning: External IP {ext_ip} is not within the valid testing ranges.", "warning")
            choice = prompt_yes_no("Do you want to continue anyway? (y/n): ", AUTO_MODE)
            if choice != 'y':
                print_status("User chose to exit due to invalid external IP.", "info")
                sys.exit("Exiting. Please connect to the VPN and try again.")
        return ext_ip

    def compress_project_folder(self, zip_filename):
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(self.project_folder):
                for file in files:
                    full_path = os.path.join(root, file)
                    arcname = os.path.relpath(full_path, self.project_folder)
                    zipf.write(full_path, arcname)
        logging.getLogger().info(f"Project compressed to {zip_filename}")

    def upload_to_smb(self, local_file, remote_path, domain=""):
        try:
            smb_server = CUSTOM_SETTINGS.get("smb_server") or input("SMB Server: ")
            smb_share = CUSTOM_SETTINGS.get("smb_share") or input("SMB Share: ")
            smb_user = CUSTOM_SETTINGS.get("smb_username") or input("SMB Username: ")
            smb_pass = getpass.getpass("Enter SMB password (leave blank for none): ")
            conn = SMBConnection(smb_server, smb_server)
            conn.login(smb_user, smb_pass, domain)
            logger = logging.getLogger()
            print_status(f"Connected to {smb_server} on share {smb_share}", "info")
            # ensure_remote_path is assumed to be defined elsewhere or as a method.
            ensure_remote_path(conn, smb_share, remote_path)
            remote_file = os.path.join(remote_path, os.path.basename(local_file)).replace("\\", "/")
            print_status(f"Uploading {local_file} to {remote_file}...", "upload")
            with open(local_file, 'rb') as fp:
                conn.putFile(smb_share, remote_file, fp.read)
            conn.logoff()
            print_status("Upload completed successfully.", "success")
        except Exception as e:
            print_status(f"Upload failed: {e.args}", "warning")



    def check_scope_file(self, file_path):
        """Read and return non-empty entries from a given scope file."""
        if not os.path.isfile(file_path):
            logging.getLogger().info(f"[-] {os.path.basename(file_path)} not found.")
            return []
        with open(file_path, "r") as f:
            entries = [line.strip() for line in f if line.strip()]
        if not entries:
            logging.getLogger().info(f"[-] {os.path.basename(file_path)} is empty.")
        return entries


    def auto_tag(self, entry):
        """Tag the entry as [IP] or [URL] based on its format."""
        if re.match(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", entry):
            return f"{entry} [IP]"
        elif re.match(r"https?://", entry):
            return f"{entry} [URL]"
        else:
            return f"{entry} [UNKNOWN]"

    def port_scan(self, ip):
        """Scan a set of common ports on the given IP address using custom settings.
        Returns a list of open ports."""
        print_status(f"[*] Scanning common ports on {ip}...", "info")
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
            print_status(f"[+] Open ports on {ip}: {open_ports}", "info")
        else:
            print_status(f"[-] No common ports open on {ip}", "info")
        return open_ports


    def get_external_ip(self):
        """Retrieve and log the external IP address using custom or default URL."""
        try:
            ip = requests.get(CUSTOM_SETTINGS["external_ip_url"]).text
            print_status(f"[+] External IP Address: {ip}", "info")
            return ip
        except requests.RequestException:
            print_status("[-] Unable to determine external IP address.", "warning")
            return ""


    def write_xml_output(self):
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
        print_status(f"Scan results written to {xml_file}", "success")


    def print_summary(self):
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
        print_status("\n" + summary_str, "info")
        
        # Write summary to summary.txt in the project folder
        summary_file = os.path.join(PROJECT_FOLDER, "summary.txt")
        try:
            with open(summary_file, "w") as f:
                f.write(summary_str)
            print_status(f"Summary written to {summary_file}", "success")
        except Exception as e:
            print_status(f"[-] Failed to write summary: {e.args}", "error")

    def run_checks(self, mode, file_path):
        """
        Run pre-flight checks for a given mode (int, ext, web) using the specified scope file.
        For external and web modes, fetch the external IP.
        Accumulate results in the global SCAN_RESULTS dictionary.
        """
        print_status(f"[*] Running pre-flight checks for: {mode.upper()}", "info")
        mode_results = []
        if mode in ["ext", "web"]:
            ext_ip = self.get_external_ip()
            mode_results.append({"external_ip": ext_ip})
        scope_entries = self.check_scope_file(file_path)
        if not scope_entries:
            print_status(f"[-] Skipping {mode.upper()} checks due to no entries.", "warning")
            return
        for entry in scope_entries:
            result = {}
            result["target"] = entry
            result["tag"] = self.auto_tag(entry)
            print_status(f"[~] {result['tag']}", "info")
            print_status(f"Tagged scope entry: {result['tag']}", "info")
            if "[IP]" in result["tag"]:
                result["open_ports"] = self.port_scan(entry)
            mode_results.append(result)
        print_status(f"[+] {mode.upper()} pre-flight checks passed.\n", "success")
        SCAN_RESULTS[mode] = mode_results

# --- RavenRecon Class ---
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
            print_status("[-] Nmap is not installed or not in PATH. Please install it first.", "error")
            sys.exit(1)
        if not self.check_ollama():
            print_status("[-] Ollama service is not responding. Please ensure it's running.", "error")
            sys.exit(1)
        self.load_external_plugins()


    def discover_hosts(self):
        print_status(f"[+] Discovering live hosts in {self.targets}...", "info")
        self.scanner.scan(hosts=self.targets, arguments="-sn")
        live_hosts = [host for host in self.scanner.all_hosts() if self.scanner[host].state() == "up"]
        print_status(f"[+] Found {len(live_hosts)} live hosts", "info")
        return live_hosts

    def scan_network(self, live_hosts):
        if not live_hosts:
            print_status("[-] No live hosts found. Exiting.", "warning")
            return
        print_status("[+] Scanning network for open ports and services...", "info")
        scan_arguments = "-O -sV --version-all -sC" if self.mode == "full" else "-F"
        import concurrent.futures
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_host = {executor.submit(self.scan_host, host, scan_arguments): host for host in live_hosts}
                for future in concurrent.futures.as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        self.results[host] = future.result()
                        print_status(f"[+] Scan completed for {host}", "success")
                    except Exception as exc:
                        print_status(f"[-] Error scanning {host}: {exc}", "error")
        except KeyboardInterrupt:
            print_status("[-] Scan interrupted by user. Shutting down.", "error")

    def scan_host(self, host, arguments):
        print_status(f"[+] Starting scan on {host} with arguments: {arguments}", "info")
        try:
            self.scanner.scan(host, arguments=arguments)
            host_info = {
                "hostname": self.scanner[host].hostname(),
                "state": self.scanner[host].state(),
                "ports": []
            }
            for proto in self.scanner[host].all_protocols():
                for port in self.scanner[host][proto].keys():
                    print_status(f"[+] Scanning port {port} on {host}...", "info")
                    port_info = self.scanner[host][proto][port]
                    port_data = {
                        "port": port,
                        "state": port_info["state"],
                        "service": port_info.get("name", "Unknown"),
                        "version": port_info.get("version", "Unknown"),
                        "raw_output": json.dumps(port_info, indent=2)[:500]
                    }
                    self.grab_banner(host, port, port_data)
                    for plugin in self.plugins:
                        if plugin.should_run(host, port, port_data):
                            result = plugin.run(host, port, port_data)
                            port_data[plugin.name] = result
                    port_data["vulnerabilities"] = lookup_vulnerabilities_for_port(port_data)
                    host_info["ports"].append(port_data)
            return host_info
        except Exception as e:
            print_status(f"[-] Exception scanning {host}: {e.args}", "error")
            return {}


    def grab_banner(self, host, port, port_data):
        print_status(f"[+] Grabbing banner for {host}:{port}...", "info")
        try:
            with socket.create_connection((host, port), timeout=2) as s:
                s.sendall(b"\r\n")
                banner = s.recv(1024).decode("utf-8", "ignore").strip().split("\n")[0]
                if banner:
                    port_data["banner"] = banner[:200]
        except Exception:
            pass

    def analyse_vulnerabilities(self, host_info):
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
                {"role": "system", "content": "You are a cybersecurity expert. Analyse the scan results and identify potential vulnerabilities. Provide a detailed narrative summary with remediation advice in markdown format."},
                {"role": "user", "content": f"Scan Data:\n{json.dumps(trimmed_data, indent=2)}"}
            ]
        )
        return response["message"]["content"]

    def load_external_plugins(self, plugins_dir="plugins"):
        if not os.path.exists(plugins_dir):
            print_status(f"[-] Plugins directory '{plugins_dir}' not found. Skipping external plugins.", "warning")
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
                    print_status(f"[-] Failed to load plugin from {filename}: {e.args}", "error")

    def register_plugin(self, plugin):
        self.plugins.append(plugin)
        print_status(f"[+] Registered plugin: {plugin.name}", "info")

    def check_ollama(self):
        try:
            response = requests.get("http://localhost:11434/api/status", timeout=3)
            if response.status_code == 200:
                print_status("[+] Ollama service is running (status check)", "info")
                return True
        except requests.RequestException as e:
            print_status(f"[-] Ollama /api/status check failed: {e.args}", "error")
        try:
            response = requests.get("http://localhost:11434/api/version", timeout=3)
            if response.status_code == 200:
                print_status("[+] Ollama service is running (version check)", "info")
                return True
        except requests.RequestException as e:
            print_status(f"[-] Ollama /api/version check failed: {e.args}", "error")
        return False


    def count_vulnerabilities(self, vulnerabilities_text):
        return len(re.findall(r'\*\*Vulnerability \d+:', vulnerabilities_text))


# --- ReportGenerator Class ---
class ReportGenerator:
    def __init__(self, targets, results, output_path):
        self.targets = targets
        self.results = results
        self.output_path = output_path

    def generate_report(self):
        print_status("[+] Generating report...", "info")
        report_md = f"# Internal Network Scan Report\n\n"
        report_md += f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report_md += f"**Targets:** {self.targets}\n\n"
        if not self.results:
            print_status("[-] No scan results to report.", "warning")
            return
        total_hosts = len(self.results)
        total_ports = sum(len(data.get("ports", [])) for data in self.results.values())
        total_vulns = sum(self.count_vulnerabilities(data.get("vulnerabilities_ai", "")) for data in self.results.values())
        print_status(f"[+] Scan Summary: Hosts: {total_hosts}, Ports: {total_ports}, Vulnerabilities (AI): {total_vulns}", "info")
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
                report_md += f"\n**Vulnerability Lookup Result:**\n```\n{port.get('vulnerabilities', 'No vulnerabilities found.')}\n```\n"
            report_md += "\n## AI Vulnerability Analysis\n\n"
            report_md += data.get("vulnerabilities_ai", "No vulnerabilities identified.") + "\n\n"
        # Append executive summary generated by a static method
        exec_summary = ReportGenerator.generate_executive_summary(self.results)
        report_md += "\n" + exec_summary + "\n"
        with open(self.output_path, "w") as f:
            f.write(report_md)
        print_status(f"[+] Report saved to {self.output_path}", "success")

    @staticmethod
    def generate_executive_summary(results):
        # Detailed narrative summary, potentially using Ollama integration.
        total_hosts = len(results)
        total_ports = sum(len(info.get("ports", [])) for info in results.values())
        exposures = {}
        for mode in ["int", "ext"]:
            for entry in results.get(mode, []):
                for port in entry.get("ports", []):
                    if port.get("state", "").lower() == "open":
                        service = port.get("service", "unknown")
                        exposures[service] = exposures.get(service, 0) + 1
        summary = "## Executive Summary\n\n"
        summary += f"Across the network scan, **{total_hosts} host{'s' if total_hosts != 1 else ''}** were analyzed, with **{total_ports} open ports** identified.\n\n"
        if exposures:
            summary += "### Key Observations:\n"
            for service, count in exposures.items():
                summary += f"- **{service.capitalize()}** was detected on {count} host{'s' if count != 1 else ''}.\n"
        else:
            summary += "No significant service exposures were detected.\n"
        summary += "\n### Recommendations:\n"
        summary += "- Review any hosts with critical services exposed.\n"
        summary += "- Harden remote access services and ensure proper authentication is in place.\n"
        summary += "- Consider deploying additional monitoring and intrusion detection measures.\n"
        summary += "\nA detailed review of the full scan report is recommended to prioritize remediation efforts.\n"
        return summary

    @staticmethod
    def count_vulnerabilities(vulnerabilities_text):
        return len(re.findall(r'\*\*Vulnerability \d+:', vulnerabilities_text))


def main():
    print_banner("PRE-FLIGHT-CHECK")
    global PROJECT_FOLDER, logger, AUTO_MODE
    
    parser = argparse.ArgumentParser(
        description="Integrated PenTest Pre-Flight Check Tool with Custom Settings, XML Output, and Summary"
    )
    parser.add_argument("--settings", help="Path to an XML file for custom settings")
    parser.add_argument("--project", help="Project Number")
    parser.add_argument("--ascii", action="store_true", help="Generate an ASCII map of scanned hosts and services")
    parser.add_argument("--output", default="raven_report.md", help="Output file for Markdown report")
    parser.add_argument("--mode", choices=["quick", "full"], default="quick", help="Scan mode: quick (top 100 ports) or full (all ports)")
    parser.add_argument("--auto", action="store_true", help="Enable auto mode (all prompts default to yes)")
    args = parser.parse_args()
    AUTO_MODE = args.auto

    # Save original terminal settings and register restore function.
    fd = sys.stdin.fileno()
    original_term_settings = termios.tcgetattr(fd)
    atexit.register(restore_terminal_settings, fd, original_term_settings)

    # Setup temporary logging until PROJECT_FOLDER is established.
    temp_log = "temp_preflight_log.txt"
    logger = setup_logging(temp_log)
    print_status("Unified logging is now configured (temporary).", "info")

    # Ask for project number.
    if not args.project:
        proj_number = input("Enter Project Number (or press Enter to use default PR00000): ").strip()
    if args.project:
        proj_number = args.project
    if not proj_number:
        proj_number = "PR00000"
    PROJECT_FOLDER = create_project_structure(proj_number)

    # Reinitialize logging using the project folder.
    log_file = os.path.join(PROJECT_FOLDER, "preflight_log.txt")
    logger = setup_logging(log_file)
    print_status("Unified logging is now configured (project folder).", "info")

    # --- Pre-Flight Operations ---
    preflight = PreFlightCheck(PROJECT_FOLDER)
    preflight.split_scope_file()
    preflight.check_external_ip_validity()
    
    # Run pre-flight checks (for each scope type)
    print_banner("Beginning Pre-Flight-Checks")
    int_scope_path = os.path.join(PROJECT_FOLDER, "int_scope.txt")
    ext_scope_path = os.path.join(PROJECT_FOLDER, "ext_scope.txt")
    web_scope_path = os.path.join(PROJECT_FOLDER, "web_scope.txt")
    for mode, scope_path in [("int", int_scope_path), ("ext", ext_scope_path), ("web", web_scope_path)]:
        preflight.run_checks(mode, scope_path)
    if CUSTOM_SETTINGS.get("output_format") == "XML":
        preflight.write_xml_output()
    preflight.print_summary()

    # Optionally perform SMB upload.
    print_banner("SMB Upload")
    if prompt_yes_no("Do you want to upload the project folder to an SMB share? (y/n): ", AUTO_MODE) == 'y':
        zip_filename = os.path.join(PROJECT_FOLDER, os.path.basename(PROJECT_FOLDER) + ".zip")
        preflight.compress_project_folder(zip_filename)
        print_status(f"Zip file created: {zip_filename}", "success")
        remote_path = os.path.join("Projects", os.path.basename(PROJECT_FOLDER))
        preflight.upload_to_smb(zip_filename, remote_path)

    # --- Active Scanning Phase ---
    print_banner("Active Scanning Phase")
    # Build recon targets from internal and external scope files.
    recon_targets = " ".join(
        filter(None, [line.strip() for file in [int_scope_path, ext_scope_path]
                      if os.path.exists(file) for line in open(file)])
    )
    print_status(f"Recon targets: {recon_targets}", "info")
    if recon_targets:
        if prompt_yes_no("Do you want to perform active testing? (y/n): ", AUTO_MODE) == 'y':
            # Instantiate RavenRecon with targets, output path, and scan mode.
            raven = RavenRecon(recon_targets, args.output, args.mode)
            live_hosts = raven.discover_hosts()
            if live_hosts:
                raven.scan_network(live_hosts)
            else:
                print_status("[-] No live hosts found. Exiting active scanning phase.", "info")
        else:
            print_status("Active testing skipped by user.", "warning")
    else:
        print_status("[-] No recon targets found from scope files. Exiting active scanning phase.", "warning")
        sys.exit(0)

    # --- Vulnerability Analytics Phase ---
    print_banner("Vulnerability Analytics Phase")
    # Now, optionally perform AI analysis on each host.
    for host, info in raven.results.items():
        if prompt_yes_no(f"Perform AI analysis for {host}? (y/n): ", AUTO_MODE) == 'y':
            print_status(f"[+] Performing AI analysis for {host}.", "info")
            ai_result = raven.analyse_vulnerabilities(info)
            info["vulnerabilities_ai"] = ai_result
            print_status(f"[+] AI analysis completed for {host}.", "success")

    # --- Reporting Phase ---
    print_banner("Reporting Phase")
    # Generate the final report using ReportGenerator.
    reporting = ReportGenerator(raven.targets, raven.results, os.path.join(PROJECT_FOLDER, args.output))
    reporting.generate_report()

    # --- ASCII Network Map Phase ---
    print_banner("ASCII Network Map Phase")
    if args.ascii:
        print_status(generate_ascii_visualisation(raven.results), "info")

if __name__ == "__main__":
    main()

