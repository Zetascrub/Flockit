import os
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from typing import Dict, Iterable, List, Optional

from modules.cve_lookup import severity_from_cvss
from utils.models import CVEMatch, Finding, HostResult, PortResult, ScanRun

NESSUS_SEVERITIES = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
}


def parse_nessus_file(path: str) -> ScanRun:
    """Parse a NessusClientData_v2 .nessus XML file into Sift's typed model.

    Nessus reports many vulnerability plugin hits per host/port, while Sift's
    active scan model stores one PortResult per host/port. We therefore attach
    each Nessus ReportItem under PortResult.plugin_results["nessus_<pluginID>"]
    and project any CVEs into PortResult.cve_matches for normal Sift reporting
    and correlation.
    """
    tree = ET.parse(path)
    root = tree.getroot()
    report = root.find(".//Report")
    report_name = report.get("name") if report is not None else os.path.basename(path)

    scan_run = ScanRun(targets=[path], mode="nessus-import", started_at=_scan_date(root))
    hosts: Dict[str, HostResult] = {}

    for report_host in root.findall(".//ReportHost"):
        host_name = report_host.get("name") or "unknown"
        properties = _host_properties(report_host)
        host_key = properties.get("host-ip") or host_name
        hr = HostResult(
            host=host_key,
            hostname=properties.get("host-fqdn") or properties.get("netbios-name") or host_name,
            state="up",
        )
        ports_by_key: Dict[tuple, PortResult] = {}

        for item in report_host.findall("./ReportItem"):
            port = _int_attr(item, "port", 0)
            protocol = item.get("protocol") or "tcp"
            service = item.get("svc_name") or ("general" if port == 0 else "")
            port_key = (port, protocol)
            pr = ports_by_key.get(port_key)
            if pr is None:
                pr = PortResult(port=port, protocol=protocol, state="open", service=service)
                ports_by_key[port_key] = pr
            elif service and not pr.service:
                pr.service = service

            plugin_id = item.get("pluginID") or "unknown"
            plugin_key = f"nessus_{plugin_id}"
            plugin_data = _plugin_data(item, report_name)
            if port == 0:
                pr.state = "info"
            pr.plugin_results[plugin_key] = plugin_data

            for match in _cve_matches(item, plugin_data):
                if not any(existing.cve_id == match.cve_id for existing in pr.cve_matches):
                    pr.cve_matches.append(match)
            if plugin_data.get("cpe") and not pr.cpe:
                pr.cpe = plugin_data["cpe"]

        hr.ports = sorted(ports_by_key.values(), key=lambda p: (p.port, p.protocol))
        hosts[host_key] = hr

    scan_run.hosts = hosts
    scan_run.completeness.discovered_hosts = sorted(hosts)
    scan_run.completeness.scanned_hosts = sorted(hosts)
    scan_run.finished_at = datetime.now()
    return scan_run


def findings_from_nessus(scan_run: ScanRun, minimum_severity: str = "medium") -> List[Finding]:
    """Create Sift Finding objects from Nessus plugin hits.

    This preserves Nessus' per-plugin finding view so an imported report can be
    compared with Sift's own deterministic findings and CVE correlation.
    """
    threshold = _severity_rank(minimum_severity)
    grouped = defaultdict(list)

    for host, hr in scan_run.hosts.items():
        for pr in hr.ports:
            for key, result in pr.plugin_results.items():
                if not isinstance(result, dict):
                    continue
                severity = result.get("severity", "info")
                if _severity_rank(severity) > threshold:
                    continue
                grouped[key].append((host, pr.port, result))

    findings = []
    for key, hits in grouped.items():
        sample = hits[0][2]
        plugin_id = sample.get("plugin_id") or key.replace("nessus_", "")
        affected = sorted({host for host, _, _ in hits})
        cve_ids = sorted({cve for _, _, result in hits for cve in result.get("cves", [])})
        evidence = []
        for host, port, result in hits:
            label = f"{host}:{port}" if port else host
            output = result.get("plugin_output")
            if output:
                label += f" - {str(output).strip()[:180]}"
            evidence.append(label)
        findings.append(Finding(
            id=f"nessus-{plugin_id}",
            title=sample.get("plugin_name") or f"Nessus plugin {plugin_id}",
            severity=sample.get("severity", "info"),
            category="nessus-plugin",
            description=sample.get("synopsis") or sample.get("description"),
            impact=sample.get("description"),
            recommendation=sample.get("solution"),
            cvss_vector=sample.get("cvss3_vector") or sample.get("cvss_vector"),
            affected_hosts=affected,
            evidence=evidence,
            cve_ids=cve_ids,
        ))

    return sorted(findings, key=lambda f: (_severity_rank(f.severity), f.title.lower()))


def _host_properties(report_host) -> Dict[str, str]:
    properties = {}
    for tag in report_host.findall("./HostProperties/tag"):
        name = tag.get("name")
        if name:
            properties[name] = (tag.text or "").strip()
    return properties


def _plugin_data(item, report_name: str) -> dict:
    cvss = _float_text(item, "cvss3_base_score")
    if cvss is None:
        cvss = _float_text(item, "cvss_base_score")
    severity = _severity(item, cvss)
    return {
        "scanner": "nessus",
        "report": report_name,
        "plugin_id": item.get("pluginID"),
        "plugin_name": item.get("pluginName"),
        "plugin_family": item.get("pluginFamily"),
        "severity": severity,
        "risk_factor": _text(item, "risk_factor"),
        "cvss": cvss,
        "cvss_vector": _text(item, "cvss_vector"),
        "cvss3_vector": _text(item, "cvss3_vector"),
        "synopsis": _text(item, "synopsis"),
        "description": _text(item, "description"),
        "solution": _text(item, "solution"),
        "plugin_output": _text(item, "plugin_output"),
        "see_also": _texts(item, "see_also"),
        "cves": _texts(item, "cve"),
        "cpe": _first(_texts(item, "cpe")),
        "fname": _text(item, "fname"),
        "plugin_publication_date": _text(item, "plugin_publication_date"),
        "plugin_modification_date": _text(item, "plugin_modification_date"),
        "vuln_publication_date": _text(item, "vuln_publication_date"),
    }


def _cve_matches(item, plugin_data: dict) -> Iterable[CVEMatch]:
    summary = plugin_data.get("synopsis") or plugin_data.get("description") or plugin_data.get("plugin_name") or ""
    cvss = plugin_data.get("cvss")
    severity = plugin_data.get("severity") if plugin_data.get("severity") != "info" else severity_from_cvss(cvss)
    reference_url = _first(plugin_data.get("see_also") or [])
    for cve in plugin_data.get("cves") or []:
        yield CVEMatch(
            cve_id=cve,
            summary=summary,
            cvss=cvss,
            severity=severity,
            source="nessus",
            matched_cpe=plugin_data.get("cpe"),
            reference_url=reference_url,
        )


def _scan_date(root) -> Optional[datetime]:
    raw = _text(root, "Policy/policyComments") or None
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _severity(item, cvss: Optional[float]) -> str:
    raw = item.get("severity")
    if raw in NESSUS_SEVERITIES:
        return NESSUS_SEVERITIES[raw]
    risk = (_text(item, "risk_factor") or "").strip().lower()
    if risk in {"critical", "high", "medium", "low"}:
        return risk
    return severity_from_cvss(cvss) if cvss is not None else "info"


def _severity_rank(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    return order.get((severity or "unknown").lower(), 5)


def _int_attr(node, name: str, default: int) -> int:
    try:
        return int(node.get(name) or default)
    except ValueError:
        return default


def _float_text(node, tag: str) -> Optional[float]:
    value = _text(node, tag)
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _text(node, path: str) -> str:
    found = node.find(path)
    return (found.text or "").strip() if found is not None and found.text else ""


def _texts(node, tag: str) -> List[str]:
    return [(found.text or "").strip() for found in node.findall(tag) if (found.text or "").strip()]


def _first(values: List[str]) -> Optional[str]:
    return values[0] if values else None
