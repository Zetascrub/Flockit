import os
import re
import sys
import zipfile
import ipaddress
import socket
import requests
import xml.dom.minidom as md
from datetime import datetime
import xml.etree.ElementTree as ET

from utils.common import *
from utils.common import CUSTOM_SETTINGS
import getpass
from impacket.smbconnection import SMBConnection

# --- Sets up project folder & scope ---

SCAN_RESULTS = {}

class PreFlight:
    def __init__(self, project_folder):
        self.project_folder = project_folder

    def setup(self):
        if not os.path.exists(self.project_folder):
            os.makedirs(self.project_folder)
        self.split_scope_file()
        self.check_external_ip_validity()


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
        ext_ip = requests.get(CUSTOM_SETTINGS["external_ip_url"]).text.strip()
        if not ext_ip:
            return ""

        # Parse valid ranges from settings
        raw_ranges = CUSTOM_SETTINGS.get("valid_external_ranges", [])
        valid_networks = []
        for net_str in raw_ranges:
            try:
                valid_networks.append(ipaddress.ip_network(net_str))
            except ValueError:
                print_status(f"Invalid network in settings.xml: {net_str}", "warning")


        try:
            ip_obj = ipaddress.ip_address(ext_ip)
        except ValueError:
            print_status("Invalid external IP format received.", "error")
            return ext_ip

        if any(ip_obj in net for net in valid_networks):
            print_status(f"External IP {ext_ip} is valid for testing.", "success")
        else:
            print_status(f"Warning: External IP {ext_ip} is not within the valid testing ranges.", "warning")
            
            choice = prompt_yes_no("Do you want to continue anyway? (y/n): ", AUTO["mode"])
            if choice != 'y':
                print_status("User chose to exit due to invalid external IP.", "info")
                sys.exit("Exiting. Please connect to the VPN and try again.")

        return ext_ip

    def prompt_smb_upload(self):
        print_banner("SMB Upload")
        return prompt_yes_no("Do you want to upload the project folder to an SMB share? (y/n): ", "upload")

    def compress_and_upload(self):
        zip_filename = os.path.join(self.project_folder, os.path.basename(self.project_folder) + ".zip")
        self.compress_project_folder(zip_filename)
        print_status(f"Zip file created: {zip_filename}", "success")
        remote_path = os.path.join("Projects", os.path.basename(self.project_folder))
        self.upload_to_smb(zip_filename, remote_path)

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

    def get_recon_targets(self):
        recon_targets = []
        for scope_file in ["int_scope.txt", "ext_scope.txt"]:
            full_path = os.path.join(self.project_folder, scope_file)
            if os.path.exists(full_path):
                with open(full_path, "r") as f:
                    recon_targets += [line.strip() for line in f if line.strip()]
        return " ".join(recon_targets)

    def prompt_recon(self):
        print_banner("Active Scanning Phase")
        return prompt_yes_no("Do you want to perform active testing? (y/n): ", AUTO["mode"])

    def prompt_ai(self):
        print_banner("Vulnerability Analytics Phase")
        print_status("This may take some time", "info")
        return prompt_yes_no("Do you want to perform AI vulnerability analysis? (y/n): ", "ai_analysis")


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
        xml_file = os.path.join(self.project_folder, "scan_results.xml")
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
        summary_file = os.path.join(self.project_folder, "Pre-Flight-Summary.txt")
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