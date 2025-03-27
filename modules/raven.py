import os
import re
import sys
import json
import socket
import nmap
import ollama
import importlib.util
import inspect
import requests

from utils.common import print_status, lookup_vulnerabilities_for_port
from modules.plugins import ScanPlugin


# --- Handles active scanning + plugins ---
class Raven:
    def __init__(self, targets, output, mode):
        self.targets = targets
        self.output = output
        self.mode = mode
        self.results = {}
        self.plugins = []
        # try:
        #     self.scanner = nmap.PortScanner()
        # except nmap.PortScannerError:
        #     print_status("[-] Nmap is not installed or not in PATH. Please install it first.", "error")
        #     sys.exit(1)
        if not self.check_ollama():
            print_status("[-] Ollama service is not responding. Please ensure it's running.", "error")
            sys.exit(1)
        self.load_external_plugins()


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
                        self.results[host] = future.result()
                        print_status(f"[+] Scan completed for {host}", "success")
                    except Exception as exc:
                        print_status(f"[-] Error scanning {host}: {exc}", "error")
        except KeyboardInterrupt:
            print_status("[-] Scan interrupted by user. Shutting down.", "error")

    def scan_host(self, host, arguments):
        print_status(f"[+] Starting scan on {host} with arguments: {arguments}", "info")
        try:
            scanner = nmap.PortScanner()
            scanner.scan(host, arguments=arguments)

            if host not in scanner.all_hosts():
                print_status(f"⚠️ Nmap returned no results for {host}. Skipping this host.", "warning")
                return {}

            host_info = {
                "hostname": scanner[host].hostname(),
                "state": scanner[host].state(),
                "ports": []
            }

            for proto in scanner[host].all_protocols():
                for port in scanner[host][proto].keys():
                    print_status(f"[+] Scanning port {port} on {host}...", "info")
                    port_info = scanner[host][proto][port]
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
            import traceback
            print_status(f"❌ Exception scanning {host}: {e}", "error")
            traceback.print_exc()
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

    def load_external_plugins(self, plugins_dir="modules/plugins"):
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