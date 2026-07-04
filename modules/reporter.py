import json
import os
from datetime import datetime

from modules.ai_prompts import format_ai_summary
from utils.common import print_status, prompt_yes_no
from utils.context import ProjectContext
from utils.models import HostResult, ScanRun


# --- Generates markdown/PDF reports from typed scan results ---
class Reporter:
    def __init__(self, ctx: ProjectContext, scan_run: ScanRun, output_path: str, findings=None, pdf_mode: bool = False):
        self.ctx = ctx
        self.scan_run = scan_run
        self.results = scan_run.hosts  # host -> HostResult
        self.output_path = output_path
        self.project_dir = os.path.dirname(output_path)
        self.findings = findings or []
        self.pdf_mode = pdf_mode

    def generate_report(self):
        print_status("[+] Generating report...", "info")
        report_md = "# Comprehensive Network Scan Report\n\n"
        report_md += f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report_md += f"**Targets:** {self.scan_run.targets}\n\n"

        if self.findings:
            report_md += self._render_top_findings()

        num_hosts = len(self.results)
        num_ports = sum(len(hr.ports) for hr in self.results.values())

        print_status(f"[+] Scan Summary: Hosts: {num_hosts}, Ports: {num_ports}", "info")

        report_md += "**Scan Summary:**\n"
        report_md += f"- Hosts Scanned: {num_hosts}\n"
        report_md += f"- Ports Scanned: {num_ports}\n\n"

        report_md += "## Host Scan Results\n\n"

        for host, hr in self.results.items():
            if not isinstance(hr, HostResult):
                print_status(f"[!] Skipping malformed result for host: {host}", "warning")
                continue

            hostname = hr.hostname or host
            report_md += f"### Host: {hostname}\n"
            if hr.escalated:
                reasons = {pr.escalation_reason for pr in hr.ports if pr.escalation_reason}
                report_md += f"> 🔎 **Adaptive scan escalated this host** ({'; '.join(sorted(reasons)) or 'see plugin/version signals'})\n\n"
            report_md += self._render_preflight_discrepancy(hr)

            report_md += "| Port  | State | Service | Version | Banner |\n"
            report_md += "|-------|-------|---------|---------|--------|\n"
            for pr in hr.ports:
                report_md += f"| {pr.port}/tcp | {pr.state} | {pr.service} | {pr.version} | {pr.banner or 'N/A'} |\n"

            for pr in hr.ports:
                if pr.cve_matches:
                    report_md += f"\n**CVE Matches for {pr.port}/tcp ({pr.service}):**\n\n"
                    report_md += "| CVE ID | Severity | Summary |\n|---|---|---|\n"
                    for match in pr.cve_matches:
                        summary = (match.summary or "").replace("\n", " ")[:200]
                        report_md += f"| {match.cve_id} | {match.severity} | {summary} |\n"
                    report_md += "\n"

                if pr.ai_recommendation:
                    format_type = "pdf" if self.pdf_mode else "markdown"
                    report_md += "\n" + format_ai_summary(
                        pr.ai_recommendation,
                        port_info={"port": pr.port, "service": pr.service or "unknown"},
                        format_type=format_type,
                    ) + "\n"

                for key, plugin_output in pr.plugin_results.items():
                    report_md += f"\n<details>\n<summary><strong>Plugin: {key}</strong></summary>\n\n"
                    plugin_output_str = json.dumps(plugin_output, indent=2) if isinstance(plugin_output, dict) else str(plugin_output)
                    report_md += f"```json\n{plugin_output_str}\n```\n</details>\n"

            report_md += "\n### Host Artifacts\n\n"
            if hr.artifacts:
                for artifact in hr.artifacts:
                    report_md += f"- 📁 [{artifact.label}]({artifact.path})\n"
            else:
                report_md += f"- 📁 [Raw Nmap CSV Output](Scan-Data/{host}/nmap.csv)\n"

            for pr in hr.ports:
                for artifact in pr.artifacts:
                    report_md += f"- 📄 [{artifact.label}]({artifact.path})\n"

        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(report_md)

        print_status(f"[+] Report saved to {self.output_path}", "success")

        choice = prompt_yes_no("Do you want to see the report? (y/n): ", self.ctx.config.automation.view_report)
        if choice:
            print("\n" + "=" * 60 + "\nREPORT OUTPUT:\n" + "=" * 60)
            print(report_md)

        return report_md

    def _render_preflight_discrepancy(self, hr: HostResult) -> str:
        hint = hr.preflight_hint
        if hint is None:
            return ""
        nmap_open_ports = {pr.port for pr in hr.ports if pr.state == "open"}
        hint_open_ports = set(hint.open_ports)
        disagrees = (not hint.responded and nmap_open_ports) or bool(hint_open_ports - nmap_open_ports)
        if not disagrees:
            return ""
        preflight_desc = "no response" if not hint.responded else f"open ports {sorted(hint_open_ports)}"
        return (
            f"\n> ⚠️ **Preflight vs Active Scan discrepancy:** preflight reported {preflight_desc}, "
            f"but the active nmap scan found open ports {sorted(nmap_open_ports) or 'none'}. "
            f"The active scan result is authoritative.\n\n"
        )

    def _render_top_findings(self) -> str:
        section = "## Top Findings\n\n"
        severity_badges = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        for finding in self.findings:
            badge = severity_badges.get(finding.severity, "⚪")
            section += f"### {badge} {finding.title} ({finding.severity.upper()})\n\n"
            section += f"**Affected hosts:** {', '.join(finding.affected_hosts)}\n\n"
            if finding.evidence:
                section += "**Evidence:**\n"
                for item in finding.evidence:
                    section += f"- {item}\n"
                section += "\n"
            if finding.narrative:
                section += f"{finding.narrative}\n\n"
        return section + "\n"
