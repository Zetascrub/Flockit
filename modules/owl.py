import re
import os
import json
from datetime import datetime
from utils.common import print_status, prompt_yes_no
from utils.common import AUTO


# --- Generates markdown reports & summary ---
class Owl:
    def __init__(self, targets, results, output_path):
        self.targets = targets
        self.results = results
        self.output_path = output_path
        self.project_dir = os.path.dirname(self.output_path)
        self.report_path = self.output_path



    def generate_report(self):
        print_status("[+] Generating report...", "info")
        report_md = f"# Comprehensive Network Scan Report\n\n"
        report_md += f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report_md += f"**Targets:** {self.targets}\n\n"

        num_hosts = len(self.results)
        num_ports = sum(len(info.get("ports", [])) for info in self.results.values())

        def count_vulnerabilities(text):
            return text.count("### Vulnerability")

        num_vulns = sum(count_vulnerabilities(info.get("vulnerabilities_ai", "")) for info in self.results.values())

        print_status(f"[+] Scan Summary: Hosts: {num_hosts}, Ports: {num_ports}, Vulnerabilities (AI): {num_vulns}", "info")

        report_md += "**Scan Summary:**\n"
        report_md += f"- Hosts Scanned: {num_hosts}\n"
        report_md += f"- Ports Scanned: {num_ports}\n"
        report_md += f"- Vulnerabilities Found (AI): {num_vulns}\n\n"

        report_md += "## Host Scan Results\n\n"

        for host, data in self.results.items():
            if not isinstance(data, dict):
                print_status(f"[!] Skipping malformed result for host: {host}", "warning")
                continue

            hostname = data.get("hostname") or host
            report_md += f"### Host: {hostname}\n"
            report_md += f"| Port  | State | Service | Version | Banner |\n"
            report_md += f"|-------|-------|---------|---------|--------|\n"

            for port in data.get("ports", []):
                report_md += f"| {port['port']}/tcp | {port['state']} | {port['service']} | {port['version']} | {port.get('banner', 'N/A')} |\n"

                if "ssl_scan" in port:
                    report_md += f"\n**SSL Scan Result:**\n```{port['ssl_scan']}\n```\n"

                report_md += f"\n**Vulnerability Lookup Result:**\n```{port.get('vulnerabilities', 'No vulnerabilities found.')}\n```\n"

                standard_keys = {"port", "state", "service", "version", "banner", "vulnerabilities", "ssl_scan", "raw_output"}
                for key, plugin_output in port.items():
                    if key not in standard_keys:
                        report_md += f"\n<details>\n<summary><strong>Plugin: {key}</strong></summary>\n\n"
                        plugin_output_str = json.dumps(plugin_output, indent=2) if isinstance(plugin_output, dict) else str(plugin_output)
                        report_md += f"```json\n{plugin_output_str}\n```\n</details>\n"

            # 🔗 Artifact links section
            report_md += f"\n### Host Artifacts\n\n"
            report_md += f"- 📁 [Raw Nmap CSV Output](Scan-Data/{host}/nmap.csv)\n"

            for port in data.get("ports", []):
                banner_file = f"banner_{port['port']}.txt"
                report_md += f"- 📄 [Banner {port['port']}]({os.path.join('Scan-Data', host, banner_file)})\n"

                for key in port.keys():
                    if key.endswith("_scan") or key.endswith("_output"):
                        filename = f"{key}_output.txt"
                        report_md += f"- 📄 [{key} Output]({os.path.join('Scan-Data', host, filename)})\n"

            ai_summary = data.get("vulnerabilities_ai", "No vulnerabilities identified.")
            report_md += "\n<details>\n<summary><strong>AI Vulnerability Analysis</strong></summary>\n\n"
            report_md += f"```markdown\n{ai_summary}\n```\n</details>\n\n"

        # Executive summary at the end
        exec_summary = self.generate_executive_summary(self.results)
        report_md += "\n" + exec_summary + "\n"

        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(report_md)

        print_status(f"[+] Report saved to {self.output_path}", "success")

        choice = prompt_yes_no("Do you want to see the report? (y/n): ", "view_report")
        if choice == 'y':
            print("\n" + "=" * 60 + "\nREPORT OUTPUT:\n" + "=" * 60)
            print(report_md)
        else:
            import subprocess
            import platform
            try:
                if platform.system() == "Windows":
                    os.startfile(self.output_path)
                elif platform.system() == "Darwin":
                    subprocess.run(["open", self.output_path])
                else:
                    subprocess.run(["xdg-open", self.output_path])
            except Exception as e:
                print_status(f"[!] Could not open file automatically: {e}", "warning")
                print_status("Please open the file manually from your file explorer.", "info")

    
    @staticmethod
    def generate_executive_summary(results):
        total_hosts = len(results)
        total_ports = sum(len(info.get("ports", [])) for info in results.values())

        exposures = {}
        for info in results.values():
            if not isinstance(info, dict):
                continue
            for port in info.get("ports", []):
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




