import getpass
import ipaddress
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import xml.dom.minidom as md
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import requests

from utils.common import (
    check_dependencies,
    ensure_remote_path,
    expand_ip_range,
    is_domain,
    print_banner,
    print_status,
    prompt_yes_no,
)
from utils.context import ProjectContext
from utils.models import PreflightHint

# --- Sets up project folder & scope, using an explicit ProjectContext ---

# Safety cap on how large a CIDR block pre-flight will sweep host-by-host.
# Above this, per-host ICMP+TCP checks would take too long for a fast
# advisory pass; the real nmap-based scan phase still discovers those hosts.
MAX_NET_SWEEP_HOSTS = 1024
NET_SWEEP_WORKERS = 32


class PreFlight:
    def __init__(self, ctx: ProjectContext):
        self.ctx = ctx
        self.project_folder = ctx.project_folder
        self.scope_file = ctx.scope_source_path
        self.preflight_hints = {}  # target -> PreflightHint (advisory only, see models.PreflightHint)
        self.scan_results = {}  # mode -> list of preflight entry dicts, for XML/summary output

    def setup(self):
        if not os.path.exists(self.project_folder):
            os.makedirs(self.project_folder)
        self.split_scope_file()
        if self.has_scope_entries("ext_scope.txt"):
            self.check_external_ip_validity()
        else:
            print_status("No external IP scope found; skipping external IP validation.", "info")

    def has_scope_entries(self, filename):
        path = os.path.join(self.project_folder, filename)
        if not os.path.isfile(path):
            return False
        with open(path, "r") as f:
            return any(line.strip() for line in f)

    def split_scope_file(self):
        MAIN_SCOPE_FILE = self.scope_file
        os.makedirs(self.project_folder, exist_ok=True)
        INT_SCOPE_FILE = os.path.join(self.project_folder, "int_scope.txt")
        EXT_SCOPE_FILE = os.path.join(self.project_folder, "ext_scope.txt")
        WEB_SCOPE_FILE = os.path.join(self.project_folder, "web_scope.txt")
        PROJECT_SCOPE_FILE = os.path.join(self.project_folder, "scope.txt")

        if not os.path.isfile(MAIN_SCOPE_FILE):
            if MAIN_SCOPE_FILE != "scope.txt":
                sys.exit(f"Scope file not found: {MAIN_SCOPE_FILE}")
            sample = "192.168.8.1\n192.168.8.10-12\nExample.com\n192.168.9.0/24\n"
            print_status("scope.txt not found. Creating a sample scope.txt...", "warning")
            with open(MAIN_SCOPE_FILE, "w") as f:
                f.write(sample)

        try:
            if os.path.abspath(MAIN_SCOPE_FILE) != os.path.abspath(PROJECT_SCOPE_FILE):
                shutil.copyfile(MAIN_SCOPE_FILE, PROJECT_SCOPE_FILE)
        except Exception as e:
            print_status(f"Could not copy source scope into project folder: {e}", "warning")

        with open(MAIN_SCOPE_FILE, "r") as f:
            raw_entries = [line.strip() for line in f if line.strip()]

        internal_networks = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]

        def is_internal_ip(ip_str):
            try:
                ip_obj = ipaddress.ip_network(ip_str, strict=False)
                if ip_obj.version == 4:
                    network_address = ip_obj.network_address
                    if network_address.is_loopback or network_address.is_link_local:
                        return True
                return any(ip_obj.subnet_of(net) for net in internal_networks)
            except ValueError:
                return False

        int_entries = []
        ext_entries = []
        web_entries = []

        for entry in raw_entries:
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$", entry):
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

        if int_entries:
            with open(INT_SCOPE_FILE, "w") as f:
                for line in int_entries:
                    f.write(line + "\n")
            print_status(f"Created int_scope.txt with {len(int_entries)} entries (Internal IPs).", "info")
        else:
            if os.path.exists(INT_SCOPE_FILE):
                os.remove(INT_SCOPE_FILE)
            print_status("No internal IPs found; int_scope.txt not created.", "info")

        if ext_entries:
            with open(EXT_SCOPE_FILE, "w") as f:
                for line in ext_entries:
                    f.write(line + "\n")
            print_status(f"Created ext_scope.txt with {len(ext_entries)} entries (External IPs).", "info")
        else:
            if os.path.exists(EXT_SCOPE_FILE):
                os.remove(EXT_SCOPE_FILE)
            print_status("No external IPs found; ext_scope.txt not created.", "info")

        if web_entries:
            with open(WEB_SCOPE_FILE, "w") as f:
                for line in web_entries:
                    f.write(line + "\n")
            print_status(f"Created web_scope.txt with {len(web_entries)} entries (Website URLs).", "info")
        else:
            if os.path.exists(WEB_SCOPE_FILE):
                os.remove(WEB_SCOPE_FILE)
            print_status("No website URLs found; web_scope.txt not created.", "info")

    def check_external_ip_validity(self):
        config = self.ctx.config
        ext_ip = self.ctx.external_ip
        if not ext_ip:
            try:
                ext_ip = requests.get(config.external_ip_url, timeout=5).text.strip()
                self.ctx.external_ip = ext_ip
            except requests.RequestException:
                print_status("Unable to determine external IP address.", "warning")
                return ""
        if not ext_ip:
            return ""

        valid_networks = []
        for net_str in config.valid_external_ranges:
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

            if not prompt_yes_no("Do you want to continue anyway? (y/n): ", self.ctx.config.automation.general):
                print_status("User chose to exit due to invalid external IP.", "info")
                sys.exit("Exiting. Please connect to the VPN and try again.")

        return ext_ip

    def prompt_smb_upload(self):
        print_banner("SMB Upload")
        return prompt_yes_no("Do you want to upload the project folder to an SMB share? (y/n): ", self.ctx.config.automation.upload)

    def compress_and_upload(self):
        if not self.prompt_smb_upload():
            print_status("Skipping SMB upload.", "info")
            return

        if check_dependencies(upload=True):
            print_status("Skipping SMB upload because upload dependencies are missing.", "warning")
            return

        smb = self.ctx.config.smb
        missing_settings = [name for name, val in (("smb_server", smb.server), ("smb_share", smb.share)) if not val]
        if missing_settings and self.ctx.config.automation.upload:
            print_status(f"Skipping SMB upload because settings are missing: {', '.join(missing_settings)}", "warning")
            return

        zip_filename = os.path.join(self.project_folder, os.path.basename(self.project_folder) + ".zip")
        self.compress_project_folder(zip_filename)
        print_status(f"Zip file created: {zip_filename}", "success")
        remote_path = os.path.join("Projects", os.path.basename(self.project_folder))
        self.upload_to_smb(zip_filename, remote_path)

    def compress_project_folder(self, zip_filename):
        import zipfile

        with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(self.project_folder):
                for file in files:
                    full_path = os.path.join(root, file)
                    arcname = os.path.relpath(full_path, self.project_folder)
                    zipf.write(full_path, arcname)
        logging.getLogger().info(f"Project compressed to {zip_filename}")

    def upload_to_smb(self, local_file, remote_path, domain=""):
        try:
            from impacket.smbconnection import SMBConnection

            smb = self.ctx.config.smb
            auto_upload = self.ctx.config.automation.upload
            smb_server = smb.server if smb.server else ("" if auto_upload else input("SMB Server: "))
            smb_share = smb.share if smb.share else ("" if auto_upload else input("SMB Share: "))
            smb_user = smb.username if smb.username else ("" if auto_upload else input("SMB Username: "))
            smb_pass = "" if auto_upload else getpass.getpass("Enter SMB password (leave blank for none): ")

            conn = SMBConnection(smb_server, smb_server)
            conn.login(smb_user, smb_pass, domain)
            print_status(f"Connected to {smb_server} on share {smb_share}", "info")
            ensure_remote_path(conn, smb_share, remote_path)
            remote_file = os.path.join(remote_path, os.path.basename(local_file)).replace("\\", "/")
            print_status(f"Uploading {local_file} to {remote_file}...", "upload")
            with open(local_file, "rb") as fp:
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
        """Tag the entry as [IP] (single host), [NET] (multi-host CIDR block),
        [URL], or [UNKNOWN] based on its format."""
        try:
            ipaddress.ip_address(entry)
            return f"{entry} [IP]"
        except ValueError:
            pass
        try:
            network = ipaddress.ip_network(entry, strict=False)
            return f"{entry} [NET]" if network.num_addresses > 1 else f"{entry} [IP]"
        except ValueError:
            pass
        if re.match(r"https?://", entry):
            return f"{entry} [URL]"
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
        return prompt_yes_no("Do you want to perform active testing? (y/n): ", self.ctx.config.automation.general)

    def prompt_ai(self):
        print_banner("Vulnerability Analytics Phase")
        print_status("This may take some time", "info")
        return prompt_yes_no("Do you want to perform AI vulnerability analysis? (y/n): ", self.ctx.config.automation.ai_analysis)

    def ping_host(self, ip):
        """Best-effort ICMP reachability check via the system `ping` binary
        (no raw sockets, so it works without root). A False result only means
        ICMP didn't get a reply -- the host may still be up behind a filter --
        see PreflightHint's advisory-only docstring."""
        count_flag = "-n" if os.name == "nt" else "-c"
        args = ["ping", count_flag, "1", ip]
        try:
            completed = subprocess.run(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=max(self.ctx.config.timeout, 1.0) + 1,
            )
            return completed.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def port_scan(self, ip):
        """Scan a set of common ports on the given IP address using configured settings.
        Returns a list of open ports."""
        print_status(f"[*] Scanning common ports on {ip}...", "info")
        config = self.ctx.config
        open_ports = []

        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(config.timeout)
                    if sock.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
            except socket.error:
                pass

        max_workers = min(len(config.ports), 10)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(scan_port, config.ports)
        if open_ports:
            print_status(f"[+] Open ports on {ip}: {open_ports}", "info")
        else:
            print_status(f"[-] No common ports open on {ip}", "info")
        return open_ports

    def check_host(self, ip):
        """Run the ICMP + TCP checks for a single host. Same shape as the
        per-entry dict run_checks builds for a standalone [IP] scope entry,
        so sweep results can be printed/serialized identically."""
        icmp_up = self.ping_host(ip)
        open_ports = self.port_scan(ip)
        return {"target": ip, "tag": f"{ip} [IP]", "icmp": icmp_up, "open_ports": open_ports}

    def sweep_network(self, network_str):
        """Expand a CIDR block into individual hosts and check each with a
        bounded thread pool, returning only the hosts that responded (by
        ICMP or an open port), or None if the block is too large to sweep --
        see MAX_NET_SWEEP_HOSTS. Skipped blocks are still discovered by the
        real nmap-based scan phase; this is just a faster advisory pass."""
        network = ipaddress.ip_network(network_str, strict=False)
        hosts = list(network.hosts())
        if len(hosts) > MAX_NET_SWEEP_HOSTS:
            print_status(
                f"[~] {network_str} has {len(hosts)} hosts, over the {MAX_NET_SWEEP_HOSTS}-host pre-flight "
                f"sweep cap; skipping per-host probe (host discovery still runs during the full scan).",
                "info",
            )
            return None

        print_status(f"[*] Sweeping {len(hosts)} hosts in {network_str}...", "info")
        responded = []
        with ThreadPoolExecutor(max_workers=NET_SWEEP_WORKERS) as pool:
            for result in pool.map(self.check_host, (str(ip) for ip in hosts)):
                if result["icmp"] or result["open_ports"]:
                    responded.append(result)
                    self.preflight_hints[result["target"]] = PreflightHint(
                        responded=True, open_ports=result["open_ports"]
                    )

        print_status(f"[+] {len(responded)}/{len(hosts)} host(s) in {network_str} responded", "success")
        return responded

    def get_external_ip(self):
        """Retrieve and log the external IP address, caching it on the ProjectContext."""
        cached_ip = self.ctx.external_ip
        if cached_ip:
            print_status(f"[+] External IP Address: {cached_ip}", "info")
            return cached_ip
        try:
            ip = requests.get(self.ctx.config.external_ip_url, timeout=5).text
            self.ctx.external_ip = ip
            print_status(f"[+] External IP Address: {ip}", "info")
            return ip
        except requests.RequestException:
            print_status("[-] Unable to determine external IP address.", "warning")
            return ""

    def write_xml_output(self):
        """Write the accumulated preflight scan_results into an XML file in the project folder."""
        root = ET.Element("ScanResults")
        timestamp = ET.SubElement(root, "Timestamp")
        timestamp.text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for mode, results in self.scan_results.items():
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
                    icmp_elem = ET.SubElement(target_elem, "IcmpResponded")
                    icmp_elem.text = str(entry.get("icmp", False))
                    ports_elem = ET.SubElement(target_elem, "OpenPorts")
                    for port in entry.get("open_ports", []):
                        port_elem = ET.SubElement(ports_elem, "Port")
                        port_elem.text = str(port)
                elif "swept_total" in entry:
                    swept_elem = ET.SubElement(target_elem, "Swept")
                    swept_elem.set("responded", str(entry["swept_responded"]))
                    swept_elem.set("total", str(entry["swept_total"]))
        xml_str = ET.tostring(root, encoding="utf-8")
        parsed_xml = md.parseString(xml_str)
        pretty_xml = parsed_xml.toprettyxml(indent="  ")
        xml_file = os.path.join(self.project_folder, "scan_results.xml")
        with open(xml_file, "w") as f:
            f.write(pretty_xml)
        print_status(f"Scan results written to {xml_file}", "success")

    def print_summary(self):
        """Print a summary table of the preflight results and write it to Pre-Flight-Summary.txt."""
        summary_lines = []
        summary_lines.append("=" * 50)
        summary_lines.append("Summary:")
        summary_lines.append("{:<20} | {:<30}".format("Host", "Status"))
        summary_lines.append("-" * 50)

        for mode, results in self.scan_results.items():
            for entry in results:
                if "target" in entry:
                    host = entry["target"]
                    if "[IP]" in entry["tag"]:
                        icmp_up = entry.get("icmp", False)
                        ports = entry.get("open_ports") or []
                        if icmp_up and ports:
                            status = "Responded (ICMP; ports: " + ", ".join(str(p) for p in ports) + ")"
                        elif ports:
                            status = "Responded (ports: " + ", ".join(str(p) for p in ports) + ")"
                        elif icmp_up:
                            status = "Responded (ICMP only)"
                        else:
                            status = "Not Responded"
                    elif "[NET]" in entry["tag"]:
                        if "swept_total" in entry:
                            status = f"Swept: {entry['swept_responded']}/{entry['swept_total']} host(s) responded"
                        else:
                            status = "Network range (host discovery runs during full scan)"
                    elif "[URL]" in entry["tag"]:
                        status = "URL Scanned"
                    else:
                        status = "Unknown"
                    summary_lines.append("{:<20} | {:<30}".format(host, status))
        summary_lines.append("=" * 50)
        summary_str = "\n".join(summary_lines)

        print_status("\n" + summary_str, "info")

        summary_file = os.path.join(self.project_folder, "Pre-Flight-Summary.txt")
        try:
            with open(summary_file, "w") as f:
                f.write(summary_str)
            print_status(f"Summary written to {summary_file}", "success")
        except Exception as e:
            print_status(f"[-] Failed to write summary: {e.args}", "error")

    def run_checks(self, mode, file_path):
        """Run pre-flight checks for a given mode (int, ext, web) using the specified scope file.
        Builds an advisory PreflightHint per IP target (never authoritative on port state —
        see models.PreflightHint), and appends to self.scan_results for XML/summary output."""
        print_status(f"[*] Running pre-flight checks for: {mode.upper()}", "info")
        mode_results = []
        scope_entries = self.check_scope_file(file_path)
        if not scope_entries:
            print_status(f"[-] Skipping {mode.upper()} checks due to no entries.", "info")
            return
        if mode == "ext":
            ext_ip = self.get_external_ip()
            mode_results.append({"external_ip": ext_ip})
        for entry in scope_entries:
            result = {}
            result["target"] = entry
            result["tag"] = self.auto_tag(entry)
            print_status(f"[~] {result['tag']}", "info")
            print_status(f"Tagged scope entry: {result['tag']}", "info")
            if "[IP]" in result["tag"]:
                icmp_up = self.ping_host(entry)
                print_status(
                    f"[+] {entry} responded to ICMP ping" if icmp_up else f"[-] {entry} did not respond to ICMP ping",
                    "info",
                )
                open_ports = self.port_scan(entry)
                result["icmp"] = icmp_up
                result["open_ports"] = open_ports
                self.preflight_hints[entry] = PreflightHint(responded=icmp_up or bool(open_ports), open_ports=open_ports)
            elif "[NET]" in result["tag"]:
                responded_hosts = self.sweep_network(entry)
                if responded_hosts is None:
                    print_status(
                        f"[~] {entry} is a network range; skipping per-host TCP probe (host discovery runs during the full scan).",
                        "info",
                    )
                else:
                    result["swept_total"] = len(list(ipaddress.ip_network(entry, strict=False).hosts()))
                    result["swept_responded"] = len(responded_hosts)
                    mode_results.append(result)
                    mode_results.extend(responded_hosts)
                    continue
            mode_results.append(result)
        print_status(f"[+] {mode.upper()} pre-flight checks passed.\n", "success")
        self.scan_results[mode] = mode_results
