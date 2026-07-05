import hashlib
from collections import defaultdict
from typing import Callable, Dict, List

from utils.config import AdaptiveScanConfig
from utils.models import Finding, HostResult, ScanRun

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

ALWAYS_FLAG_SERVICES = {"telnet", "rlogin", "vnc"}

CREDENTIAL_WEAKNESS_KEYS = ("default_credentials", "weak_credentials", "anonymous_login", "no_auth")

NARRATIVE_SYSTEM_PROMPT = (
    "You are a cybersecurity analyst writing a short prioritization note for a penetration test "
    "finding that has already been computed deterministically. Do not invent new findings, hosts, "
    "or CVEs beyond what is given. Explain the risk and suggest remediation priority in 2-4 concise "
    "sentences of markdown."
)


def _worst_severity(matches) -> str:
    if not matches:
        return "unknown"
    return min((m.severity for m in matches), key=lambda s: SEVERITY_ORDER.get(s, 5))


def detect_repeated_cve(hosts: Dict[str, HostResult], cfg: AdaptiveScanConfig) -> List[Finding]:
    """Same CVE ID present on 2+ hosts — a single fix (patch/config change)
    that resolves the same exposure everywhere it appears."""
    by_cve = defaultdict(list)  # cve_id -> [(host, port, CVEMatch)]
    for host, hr in hosts.items():
        for pr in hr.ports:
            for match in pr.cve_matches:
                by_cve[match.cve_id].append((host, pr.port, match))

    findings = []
    for cve_id, occurrences in by_cve.items():
        affected = sorted({host for host, _, _ in occurrences})
        if len(affected) < 2:
            continue
        sample = occurrences[0][2]
        findings.append(Finding(
            id=f"repeated-cve-{cve_id}",
            title=f"{cve_id} present on {len(affected)} hosts",
            severity=sample.severity,
            category="repeated-cve",
            description=(
                f"{cve_id} was identified on multiple hosts during deterministic CVE correlation. "
                "Repeated exposure usually indicates a shared vulnerable package, image, or patching gap."
            ),
            impact=(
                "An attacker may be able to reuse the same exploit path across several affected assets, "
                "increasing the likelihood and scale of compromise."
            ),
            recommendation=(
                f"Review the affected service versions, validate applicability of {cve_id}, and apply the "
                "vendor-recommended patch or configuration change consistently across all affected hosts."
            ),
            affected_hosts=affected,
            evidence=[f"{host}:{port} — {(match.summary or '')[:160]}" for host, port, match in occurrences],
            cve_ids=[cve_id],
        ))
    return findings


def detect_same_vulnerable_version(hosts: Dict[str, HostResult], cfg: AdaptiveScanConfig) -> List[Finding]:
    """Same (service, product, version) with known CVEs repeated across
    2+ hosts — names the exact patch target instead of a single CVE ID."""
    by_version = defaultdict(list)  # (service, product, version) -> [(host, port, [CVEMatch])]
    for host, hr in hosts.items():
        for pr in hr.ports:
            if not pr.cve_matches:
                continue
            key = (pr.service, pr.product, pr.version)
            if not any(key):
                continue
            by_version[key].append((host, pr.port, pr.cve_matches))

    findings = []
    for (service, product, version), occurrences in by_version.items():
        affected = sorted({host for host, _, _ in occurrences})
        if len(affected) < 2:
            continue
        all_matches = [m for _, _, matches in occurrences for m in matches]
        cve_ids = sorted({m.cve_id for m in all_matches})
        label = " ".join(part for part in (product, version) if part) or service
        findings.append(Finding(
            id=f"same-version-{service}-{label}".replace(" ", "_").lower(),
            title=f"Same vulnerable {service or 'service'} version ({label}) on {len(affected)} hosts",
            severity=_worst_severity(all_matches),
            category="same-vulnerable-version",
            description=(
                f"The same vulnerable {service or 'service'} version ({label}) appears on multiple hosts "
                "with one or more associated CVEs."
            ),
            impact=(
                "A repeated vulnerable version can create a common attack path across the environment and "
                "may point to a shared build, baseline, or update process that needs correction."
            ),
            recommendation=(
                "Confirm the affected package and version on each host, then upgrade, patch, or replace the "
                "shared vulnerable service version across the affected asset group."
            ),
            affected_hosts=affected,
            evidence=[f"{host}:{port}" for host, port, _ in occurrences],
            cve_ids=cve_ids,
        ))
    return findings


def detect_service_overexposure(hosts: Dict[str, HostResult], cfg: AdaptiveScanConfig) -> List[Finding]:
    """A service exposed on more hosts than expected for its risk class —
    telnet/rlogin/vnc are flagged on any occurrence, others above a threshold."""
    occurrences = defaultdict(list)  # service -> [(host, port)]
    for host, hr in hosts.items():
        for pr in hr.ports:
            if pr.state != "open" or not pr.service:
                continue
            occurrences[pr.service.lower()].append((host, pr.port))

    thresholds = cfg.service_overexposure_thresholds
    findings = []
    for service, hits in occurrences.items():
        threshold = thresholds.get(service)
        if threshold is None:
            continue
        affected = sorted({host for host, _ in hits})
        if len(affected) <= threshold:
            continue
        severity = "high" if service in ALWAYS_FLAG_SERVICES else "medium"
        findings.append(Finding(
            id=f"overexposure-{service}",
            title=f"{service} exposed on {len(affected)} host(s) (threshold {threshold})",
            severity=severity,
            category="service-overexposure",
            description=(
                f"The {service} service is exposed on more hosts than the configured threshold allows."
            ),
            impact=(
                "Broad service exposure increases the attack surface and can make exploitation, brute force, "
                "or reconnaissance easier if the service is misconfigured or later found vulnerable."
            ),
            recommendation=(
                f"Restrict {service} exposure to hosts with a documented business need, apply network access "
                "controls, and disable the service where it is not required."
            ),
            affected_hosts=affected,
            evidence=[f"{host}:{port}" for host, port in hits],
        ))
    return findings


def _weakness_description(result: dict):
    for key in CREDENTIAL_WEAKNESS_KEYS:
        value = result.get(key)
        if value:
            return f"{key}: {value}" if isinstance(value, str) else key.replace("_", " ")
    if result.get("auth") == "none":
        return "no authentication required"
    return None


def detect_credential_weakness(hosts: Dict[str, HostResult], cfg: AdaptiveScanConfig) -> List[Finding]:
    """Groups identical credential/auth weaknesses (as reported by plugins)
    across hosts, so the same misconfiguration is one finding, not N."""
    by_description = defaultdict(list)  # description -> [(host, port)]
    for host, hr in hosts.items():
        for pr in hr.ports:
            for _, result in pr.plugin_results.items():
                if not isinstance(result, dict):
                    continue
                description = _weakness_description(result)
                if description:
                    by_description[description].append((host, pr.port))

    findings = []
    for description, hits in by_description.items():
        affected = sorted({host for host, _ in hits})
        digest = hashlib.sha1(description.encode("utf-8")).hexdigest()[:8]
        findings.append(Finding(
            id=f"credential-weakness-{digest}",
            title=f"Credential weakness: {description}",
            severity="high",
            category="credential-weakness",
            description=(
                f"Plugin output indicates a credential or authentication weakness: {description}."
            ),
            impact=(
                "Weak, default, anonymous, or missing authentication can allow unauthorized access to the "
                "affected service and may enable lateral movement or data exposure."
            ),
            recommendation=(
                "Disable anonymous or unauthenticated access where possible, remove default credentials, "
                "enforce strong unique credentials, and retest the affected service."
            ),
            affected_hosts=affected,
            evidence=[f"{host}:{port}" for host, port in hits],
        ))
    return findings


def detect_dns_recursion(hosts: Dict[str, HostResult], cfg: AdaptiveScanConfig) -> List[Finding]:
    """Promotes dns_scan recursion evidence into a finding."""
    hits = []
    for host, hr in hosts.items():
        for pr in hr.ports:
            result = pr.plugin_results.get("dns_scan")
            if not isinstance(result, dict):
                continue
            recursion_check = result.get("recursion_check")
            if isinstance(recursion_check, dict) and recursion_check.get("recursion_available"):
                hits.append((host, pr.port, recursion_check))

    if not hits:
        return []

    affected = sorted({host for host, _, _ in hits})
    return [Finding(
        id="dns-recursion-enabled",
        title=f"DNS recursion appears available on {len(affected)} host(s)",
        severity="medium",
        category="dns-recursion",
        description=(
            "The DNS service responded with recursion available during safe plugin validation. "
            "Recursive DNS should generally be restricted to trusted client networks."
        ),
        impact=(
            "If exposed beyond intended clients, recursive DNS can disclose resolver behavior and may be "
            "abused for DNS amplification or internal name-resolution reconnaissance."
        ),
        recommendation=(
            "Restrict recursive DNS to trusted source networks, disable recursion on authoritative-only "
            "interfaces, and retest from each relevant network segment."
        ),
        affected_hosts=affected,
        evidence=[
            f"{host}:{port} recursion_available={check.get('recursion_available')} rcode={check.get('rcode')}"
            for host, port, check in hits
        ],
    )]


def detect_missing_security_headers(hosts: Dict[str, HostResult], cfg: AdaptiveScanConfig) -> List[Finding]:
    """Promotes http_scan/tls_scan missing_security_headers evidence (from
    active web probing, see Scanner.scan_web_targets) into a finding when a
    response was actually observed but common security headers are absent."""
    hits = []
    for host, hr in hosts.items():
        for pr in hr.ports:
            for plugin_name in ("http_scan", "tls_scan"):
                result = pr.plugin_results.get(plugin_name)
                if not isinstance(result, dict) or result.get("error"):
                    continue
                missing = result.get("missing_security_headers")
                if missing:
                    hits.append((host, pr.port, sorted(missing)))

    if not hits:
        return []

    affected = sorted({host for host, _, _ in hits})
    return [Finding(
        id="missing-security-headers",
        title=f"Missing security response headers on {len(affected)} web host(s)",
        severity="low",
        category="missing-security-headers",
        description=(
            "One or more common security-related HTTP response headers (e.g. Content-Security-Policy, "
            "Strict-Transport-Security, X-Frame-Options) were absent during safe web plugin validation."
        ),
        impact=(
            "Missing security headers can make clickjacking, MIME-sniffing, and mixed-content/downgrade "
            "attacks easier, and remove a defense-in-depth layer even when the underlying application is sound."
        ),
        recommendation=(
            "Add the missing security headers at the web server or application layer and retest with the "
            "same plugin to confirm."
        ),
        affected_hosts=affected,
        evidence=[f"{host}:{port} missing={', '.join(missing)}" for host, port, missing in hits],
    )]


DETECTORS: List[Callable[[Dict[str, HostResult], AdaptiveScanConfig], List[Finding]]] = [
    detect_repeated_cve,
    detect_same_vulnerable_version,
    detect_service_overexposure,
    detect_credential_weakness,
    detect_dns_recursion,
    detect_missing_security_headers,
]


def correlate(scan_run: ScanRun, cfg: AdaptiveScanConfig) -> List[Finding]:
    """Deterministic, no-AI, no-network cross-host correlation over the typed
    scan result schema. AI is applied afterward (see narrate()) purely as an
    optional narrative layer on top of these already-computed findings."""
    findings: List[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector(scan_run.hosts, cfg))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 5), -len(f.affected_hosts)))
    return findings


def _build_finding_prompt(finding: Finding) -> str:
    return (
        f"Finding: {finding.title}\n"
        f"Severity: {finding.severity}\n"
        f"Category: {finding.category}\n"
        f"Description: {finding.description or 'not provided'}\n"
        f"Impact: {finding.impact or 'not provided'}\n"
        f"Recommendation: {finding.recommendation or 'not provided'}\n"
        f"Affected hosts: {', '.join(finding.affected_hosts)}\n"
        f"CVE IDs: {', '.join(finding.cve_ids) or 'none'}\n"
        "Evidence:\n" + "\n".join(f"- {e}" for e in finding.evidence)
    )


def narrate(findings: List[Finding], ai_client, top_n: int = 10) -> None:
    """Mutates finding.narrative in place for the top N findings only. Hands
    the AI the already-computed id/severity/hosts/evidence and asks only for
    an explanation/prioritization paragraph — never invents new findings."""
    for finding in findings[:top_n]:
        finding.narrative = ai_client.chat(
            NARRATIVE_SYSTEM_PROMPT,
            _build_finding_prompt(finding),
            use_report_model=True,
        )
