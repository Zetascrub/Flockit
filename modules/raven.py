import re
import sys
import json
import socket
import nmap

from utils.common import (
    print_status,
    check_ollama,
    ollama_chat,
    save_scan_output,
    logging,
)
from modules.magpie import Magpie

DEBUG_AI_PROMPT = False


# --- Handles active scanning + plugins ---
class Raven:
    def __init__(self, targets, output, mode):
        self.targets = targets
        self.output = output
        self.mode = mode
        self.results = {}
        # Initialise plugin manager which loads available plugins
        self.plugin_manager = Magpie()

        # try:
        #     self.scanner = nmap.PortScanner()
        # except nmap.PortScannerError:
        #     print_status("[-] Nmap is not installed or not in PATH. Please install it first.", "error")
        #     sys.exit(1)
        if not check_ollama():
            print_status("[-] Ollama service is not responding. Please ensure it's running.", "error")
            sys.exit(1)
        # self.load_external_plugins()


    def discover_hosts(self):
        print_status(f"[+] Discovering live hosts in {' '.join(self.targets if isinstance(self.targets, list) else [self.targets])}...", "info")
        scanner = nmap.PortScanner()
        scanner.scan(hosts=" ".join(self.targets if isinstance(self.targets, list) else [self.targets]), arguments="-sn")

        live_hosts = [host for host in scanner.all_hosts() if scanner[host].state() == "up"]

        print_status(f"[+] Found {len(live_hosts)} live hosts", "success")
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
                        result = future.result()
                        if isinstance(result, dict):
                            self.results[host] = result
                        else:
                            print_status(f"[!] Invalid scan result for {host}. Skipping.", "warning")

                        print_status(f"[+] Scan completed for {host}", "success")
                    except Exception as exc:
                        print_status(f"[-] Error scanning {host}: {exc}", "error")
        except KeyboardInterrupt:
            print_status("[-] Scan interrupted by user. Shutting down.", "error")

    def scan_host(self, host, context=None):
        print_status(f"[~] Scanning network for open ports and services...", "scan")
        host_info = {"ports": []}

        scanner = nmap.PortScanner()
        arguments = "-F"
        scanner.scan(host, arguments=arguments)

        # Save raw output
        nmap_raw_output = scanner.csv()
        save_scan_output(host, "nmap.csv", nmap_raw_output, base_dir=self.output)

        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                port_data = {
                    "port": port,
                    "state": scanner[host][proto][port]["state"],
                    "service": scanner[host][proto][port].get("name", ""),
                    "version": scanner[host][proto][port].get("version", "")
                }

                print_status(f"Scanning port {port} on {host}...", "scan")

                # Grab banner and store
                banner = self.grab_banner(host, port, port_data)
                if banner:
                    port_data["banner"] = banner
                    save_scan_output(host, f"banner_{port}.txt", banner, base_dir=self.output)

                # Run plugins for this port
                for plugin in self.plugin_manager.plugins:
                    if plugin.should_run(host, port, port_data):
                        try:
                            result = plugin.run(host, port, port_data)
                            port_data[plugin.name] = result

                            # Save full plugin result as JSON
                            if isinstance(result, dict):
                                plugin_output_json = json.dumps(result, indent=2)
                                save_scan_output(host, f"{plugin.name}_output.json", plugin_output_json, base_dir=self.output)

                                # Save just the banner too, if present
                                if "banner" in result:
                                    save_scan_output(host, f"{plugin.name}_banner.txt", result["banner"], base_dir=self.output)

                        except Exception as e:
                            print_status(f"❌ Plugin {plugin.name} failed on {host}:{port} - {e}", "error")
                            logging.exception(e)

                host_info["ports"].append(port_data)

        return host_info

    def grab_banner(self, host, port, port_data):
        print_status(f"[+] Grabbing banner for {host}:{port}...", "info")
        try:
            with socket.create_connection((host, port), timeout=2) as s:
                s.sendall(b"\r\n")
                banner = s.recv(1024).decode("utf-8", "ignore").strip().split("\n")[0]
                if banner:
                    banner = banner[:200]
                    port_data["banner"] = banner
                    save_scan_output(host, f"banner_{port}.txt", banner, base_dir=self.output)
                    return banner
        except Exception:
            pass
        return None



    def analyse_vulnerabilities(self, host_info, hostname="unknown"):
        if not host_info or not isinstance(host_info, dict):
            return "⚠️ Invalid host data — skipping AI analysis."

        ports = []
        for p in host_info.get("ports", []):
            if isinstance(p, dict) and p.get("port") and p.get("service"):
                ports.append({
                    "port": p["port"],
                    "state": p.get("state", "unknown"),
                    "service": p["service"],
                    "version": p.get("version", "unknown"),
                    "banner": p.get("banner", "N/A")
                })

        data = {
            "hostname": hostname,
            "ports": ports
        }

        # Ensure ports are populated
        if not data["ports"]:
            return "⚠️ No ports found for this host — skipping AI analysis."

        system_prompt = (
            "You are a cybersecurity expert. Analyse the scan results and identify potential "
            "vulnerabilities. Provide a markdown-formatted summary of risks and remediation suggestions."
        )

        user_prompt = f"Scan Data:\n{json.dumps(data, indent=2)}"
        if DEBUG_AI_PROMPT:
            print(f"[~] Prompt sent to Ollama for {hostname}:")
            print(json.dumps(data, indent=2))

        response = ollama_chat(system_prompt, user_prompt)

        if not response.strip() or "error" in response.lower():
            return "⚠️ AI analysis failed or returned an error."

        return response.strip()[:8000]

    def count_vulnerabilities(self, vulnerabilities_text):
        return len(re.findall(r'\*\*Vulnerability \d+:', vulnerabilities_text))

    def is_domain(self, target):
        # A simple check: if the target has letters, assume it's a domain.
        return any(c.isalpha() for c in target)

    def passive_recon(self, target):
        import whois
        import dns.resolver
        results = {}
        try:
            results["whois"] = whois.whois(target)
        except Exception as e:
            results["whois"] = f"WHOIS lookup failed: {e}"
        records = {}
        for rtype in ["A", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(target, rtype)
                records[rtype] = [ans.to_text() for ans in answers]
            except Exception as e:
                records[rtype] = f"DNS lookup failed: {e}"
        results["dns"] = records
        return results

    def run_passive_recon(self):
        passive_results = {}
        # Ensure targets is a list
        targets = self.targets if isinstance(self.targets, list) else self.targets.split()
        for target in targets:
            if self.is_domain(target):
                print_status(f"[~] Running passive recon on {target}...", "info")
                passive_results[target] = self.passive_recon(target)
        return passive_results

