from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from utils.artifacts import Artifact


@dataclass
class CVEMatch:
    cve_id: str
    summary: str
    cvss: Optional[float]
    severity: str  # "critical"|"high"|"medium"|"low"|"unknown"
    source: str  # "nvd"
    matched_cpe: Optional[str] = None
    reference_url: Optional[str] = None


@dataclass
class PreflightHint:
    """Advisory result from the cheap raw-TCP preflight check. Never treated
    as authoritative — nmap's real scan is the source of truth for state."""
    responded: bool
    open_ports: List[int] = field(default_factory=list)


@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: str = ""
    banner: Optional[str] = None
    plugin_results: Dict[str, object] = field(default_factory=dict)
    cve_matches: List[CVEMatch] = field(default_factory=list)
    ai_recommendation: Optional[str] = None
    artifacts: List[Artifact] = field(default_factory=list)
    escalated: bool = False
    escalation_reason: Optional[str] = None


@dataclass
class HostResult:
    host: str
    hostname: Optional[str] = None
    state: str = "up"
    ports: List[PortResult] = field(default_factory=list)
    artifacts: List[Artifact] = field(default_factory=list)
    preflight_hint: Optional[PreflightHint] = None
    subnet: Optional[str] = None
    escalated: bool = False


@dataclass
class ScanRun:
    hosts: Dict[str, HostResult] = field(default_factory=dict)
    targets: List[str] = field(default_factory=list)
    mode: str = "quick"
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


@dataclass
class Finding:
    id: str
    title: str
    severity: str  # critical|high|medium|low|info
    category: str  # "repeated-cve" | "same-vulnerable-version" | "service-overexposure" | "credential-weakness"
    affected_hosts: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    narrative: Optional[str] = None
