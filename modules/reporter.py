import csv
import json
import os
import re
from datetime import datetime

from modules.ai_prompts import format_ai_summary
from utils.common import print_status, prompt_yes_no
from utils.context import ProjectContext
from utils.models import HostResult, ScanRun

CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean_inline(value) -> str:
    text = "" if value is None else str(value)
    return CONTROL_CHARS.sub("", text).replace("\r", "\\r").replace("\n", "\\n")


def _clean_block(value) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return CONTROL_CHARS.sub("", text)


def _sanitize_json_value(value):
    if isinstance(value, dict):
        return {_clean_inline(key): _sanitize_json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_json_value(item) for item in value]
    if isinstance(value, str):
        return _clean_block(value)
    return value


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
        port_observations = sum(len(hr.ports) for hr in self.results.values())
        hosts_with_open_ports = [
            hr for hr in self.results.values()
            if isinstance(hr, HostResult) and self._open_ports(hr)
        ]
        num_open_ports = sum(len(self._open_ports(hr)) for hr in hosts_with_open_ports)

        print_status(f"[+] Scan Summary: Hosts: {num_hosts}, Open Ports: {num_open_ports}", "info")

        report_md += "**Scan Summary:**\n"
        report_md += f"- Hosts Scanned: {num_hosts}\n"
        report_md += f"- Hosts With Open Ports: {len(hosts_with_open_ports)}\n"
        report_md += f"- Open Ports: {num_open_ports}\n"
        report_md += f"- Port Observations: {port_observations}\n\n"
        report_md += self._render_scan_completeness()

        report_md += "## Host Scan Results\n\n"

        for host, hr in self.results.items():
            if not isinstance(hr, HostResult):
                print_status(f"[!] Skipping malformed result for host: {host}", "warning")
                continue
            open_ports = self._open_ports(hr)
            if not open_ports:
                continue

            hostname = hr.hostname or host
            report_md += f"### Host: {hostname}\n"
            if hr.escalated:
                reasons = {pr.escalation_reason for pr in hr.ports if pr.escalation_reason}
                report_md += f"> 🔎 **Adaptive scan escalated this host** ({'; '.join(sorted(reasons)) or 'see plugin/version signals'})\n\n"
            report_md += self._render_preflight_discrepancy(hr)

            report_md += "| Port  | State | Service | Version | Banner |\n"
            report_md += "|-------|-------|---------|---------|--------|\n"
            for pr in open_ports:
                report_md += (
                    f"| {pr.port}/tcp | {_clean_inline(pr.state)} | {_clean_inline(pr.service)} | "
                    f"{_clean_inline(pr.version)} | {_clean_inline(pr.banner or 'N/A')} |\n"
                )

            for pr in open_ports:
                if pr.cve_matches:
                    report_md += f"\n**CVE Matches for {pr.port}/tcp ({pr.service}):**\n\n"
                    report_md += "| CVE ID | Severity | Summary |\n|---|---|---|\n"
                    for match in pr.cve_matches:
                        summary = _clean_inline(match.summary or "")[:200]
                        report_md += f"| {_clean_inline(match.cve_id)} | {_clean_inline(match.severity)} | {summary} |\n"
                    report_md += "\n"

                if pr.ai_recommendation:
                    format_type = "pdf" if self.pdf_mode else "markdown"
                    report_md += "\n" + format_ai_summary(
                        pr.ai_recommendation,
                        port_info={"port": pr.port, "service": pr.service or "unknown"},
                        format_type=format_type,
                    ) + "\n"

                for key, plugin_output in pr.plugin_results.items():
                    report_md += f"\n<details>\n<summary><strong>Plugin: {_clean_inline(key)}</strong></summary>\n\n"
                    plugin_output = _sanitize_json_value(plugin_output)
                    plugin_output_str = json.dumps(plugin_output, indent=2) if isinstance(plugin_output, dict) else str(plugin_output)
                    plugin_output_str = _clean_block(plugin_output_str)
                    report_md += f"```json\n{plugin_output_str}\n```\n</details>\n"

            host_level_artifacts = list(hr.artifacts)
            port_level_artifacts = [artifact for pr in hr.ports for artifact in pr.artifacts]
            if host_level_artifacts or port_level_artifacts:
                report_md += "\n### Host Artifacts\n\n"
                for artifact in host_level_artifacts:
                    report_md += f"- 📁 [{_clean_inline(artifact.label)}]({artifact.path})\n"
                for artifact in port_level_artifacts:
                    report_md += f"- 📄 [{_clean_inline(artifact.label)}]({artifact.path})\n"

        report_md += self._render_hosts_without_open_ports()

        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(report_md)

        print_status(f"[+] Report saved to {self.output_path}", "success")
        self.export_csv()

        choice = prompt_yes_no("Do you want to see the report? (y/n): ", self.ctx.config.automation.view_report)
        if choice:
            print("\n" + "=" * 60 + "\nREPORT OUTPUT:\n" + "=" * 60)
            print(report_md)

        return report_md

    def export_csv(self):
        """Write review-friendly CSV appendices beside the markdown report."""
        findings_path = os.path.join(self.project_dir, "findings.csv")
        services_path = os.path.join(self.project_dir, "open_services.csv")
        self._write_findings_csv(findings_path)
        self._write_services_csv(services_path)
        print_status(f"[+] CSV exports saved to {findings_path} and {services_path}", "success")

    def _write_findings_csv(self, path: str):
        fieldnames = [
            "id",
            "title",
            "severity",
            "category",
            "description",
            "impact",
            "recommendation",
            "cvss_vector",
            "affected_hosts",
            "evidence",
            "cve_ids",
        ]
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for finding in self.findings:
                writer.writerow({
                    "id": _clean_inline(finding.id),
                    "title": _clean_inline(finding.title),
                    "severity": _clean_inline(finding.severity),
                    "category": _clean_inline(finding.category),
                    "description": _clean_inline(finding.description),
                    "impact": _clean_inline(finding.impact),
                    "recommendation": _clean_inline(finding.recommendation),
                    "cvss_vector": _clean_inline(finding.cvss_vector),
                    "affected_hosts": "; ".join(_clean_inline(host) for host in finding.affected_hosts),
                    "evidence": "; ".join(_clean_inline(item) for item in finding.evidence),
                    "cve_ids": "; ".join(_clean_inline(cve_id) for cve_id in finding.cve_ids),
                })

    def _write_services_csv(self, path: str):
        fieldnames = [
            "host",
            "hostname",
            "port",
            "protocol",
            "state",
            "service",
            "product",
            "version",
            "cpe",
            "banner",
            "cve_ids",
            "plugin_keys",
            "artifact_paths",
            "escalated",
            "escalation_reason",
        ]
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for host, hr in sorted(self.results.items()):
                if not isinstance(hr, HostResult):
                    continue
                for pr in self._open_ports(hr):
                    writer.writerow({
                        "host": _clean_inline(host),
                        "hostname": _clean_inline(hr.hostname or ""),
                        "port": pr.port,
                        "protocol": _clean_inline(pr.protocol),
                        "state": _clean_inline(pr.state),
                        "service": _clean_inline(pr.service),
                        "product": _clean_inline(pr.product),
                        "version": _clean_inline(pr.version),
                        "cpe": _clean_inline(pr.cpe),
                        "banner": _clean_inline(pr.banner),
                        "cve_ids": "; ".join(_clean_inline(match.cve_id) for match in pr.cve_matches),
                        "plugin_keys": "; ".join(_clean_inline(key) for key in sorted(pr.plugin_results.keys())),
                        "artifact_paths": "; ".join(_clean_inline(artifact.path) for artifact in pr.artifacts),
                        "escalated": str(bool(pr.escalated)).lower(),
                        "escalation_reason": _clean_inline(pr.escalation_reason),
                    })

    @staticmethod
    def _open_ports(hr: HostResult):
        return [pr for pr in hr.ports if pr.state == "open"]

    def _render_hosts_without_open_ports(self) -> str:
        hosts = sorted(
            host for host, hr in self.results.items()
            if isinstance(hr, HostResult) and not self._open_ports(hr)
        )
        if not hosts:
            return ""
        sample = hosts[:20]
        remainder = len(hosts) - len(sample)
        sample_text = ", ".join(_clean_inline(host) for host in sample)
        if remainder:
            sample_text += f", +{remainder} more"
        return (
            "\n## Hosts Without Open Ports\n\n"
            f"- Count: {len(hosts)}\n"
            f"- Sample: {sample_text}\n"
        )

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
            f"but the active nmap scan found open ports {_clean_inline(sorted(nmap_open_ports) or 'none')}. "
            f"The active scan result is authoritative.\n\n"
        )

    def _render_scan_completeness(self) -> str:
        completeness = self.scan_run.completeness
        section = "## Scan Completeness\n\n"
        section += f"- Discovered Hosts: {len(completeness.discovered_hosts)}\n"
        section += f"- Successfully Scanned Hosts: {len(completeness.scanned_hosts)}\n"
        section += f"- Failed Hosts: {len(completeness.failed_hosts)}\n"
        if completeness.failed_hosts:
            section += "\n**Failed hosts:**\n"
            for host, reason in sorted(completeness.failed_hosts.items()):
                section += f"- {_clean_inline(host)}: {_clean_inline(reason)}\n"
        if completeness.scan_arguments_by_host:
            section += "\n**Scan argument groups:**\n"
            grouped = {}
            for host, arguments in completeness.scan_arguments_by_host.items():
                unique_arguments = list(dict.fromkeys(arguments))
                grouped.setdefault(tuple(unique_arguments), []).append(host)
            for arguments, hosts in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0])):
                sample = sorted(hosts)[:10]
                remainder = len(hosts) - len(sample)
                sample_text = ", ".join(_clean_inline(host) for host in sample)
                if remainder:
                    sample_text += f", +{remainder} more"
                section += f"- `{_clean_inline('; '.join(arguments))}`: {len(hosts)} host(s) ({sample_text})\n"
        if completeness.notes:
            section += "\n**Notes:**\n"
            for note in completeness.notes:
                section += f"- {_clean_inline(note)}\n"
        return section + "\n"

    def _render_top_findings(self) -> str:
        section = "## Top Findings\n\n"
        severity_badges = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        for finding in self.findings:
            badge = severity_badges.get(finding.severity, "⚪")
            section += f"### {badge} {_clean_inline(finding.title)} ({_clean_inline(finding.severity.upper())})\n\n"
            if finding.description:
                section += f"**Description:** {_clean_block(finding.description)}\n\n"
            if finding.impact:
                section += f"**Impact:** {_clean_block(finding.impact)}\n\n"
            if finding.recommendation:
                section += f"**Recommendation:** {_clean_block(finding.recommendation)}\n\n"
            if finding.cvss_vector:
                section += f"**CVSSv4 Vector:** `{_clean_inline(finding.cvss_vector)}`\n\n"
            section += f"**Affected hosts:** {_clean_inline(', '.join(finding.affected_hosts))}\n\n"
            if finding.evidence:
                section += "**Evidence:**\n"
                for item in finding.evidence:
                    section += f"- {_clean_inline(item)}\n"
                section += "\n"
            if finding.narrative:
                section += f"{_clean_block(finding.narrative)}\n\n"
        return section + "\n"
