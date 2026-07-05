import argparse
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from utils.common import load_settings_xml

DEFAULT_HIGH_VALUE_PORTS = [21, 23, 110, 135, 139, 445, 1433, 1521, 3306, 3389, 5900, 6379, 9200, 11211, 27017]

DEFAULT_NOTABLE_VERSION_PATTERNS = [
    r"vsftpd 2\.3\.4",
    r"OpenSSH [1-5]\.",
    r"Apache/1\.",
    r"IIS/6\.0",
    r"Samba 3\.",
]

DEFAULT_SERVICE_OVEREXPOSURE_THRESHOLDS = {
    "telnet": 0,
    "rlogin": 0,
    "vnc": 0,
    "rdp": 1,
    "ms-wbt-server": 1,  # nmap's actual service name for RDP (port 3389)
    "ftp": 3,
    "ssh": 10,
}

DEFAULT_WEBHOOK_EVENTS = [
    "run_start",
    "run_complete",
    "high_severity_finding",
    "scan_failure",
]


@dataclass
class AutomationFlags:
    general: bool = False
    upload: bool = False
    ai_analysis: bool = False
    view_report: bool = False
    plugin: bool = False  # "auto-generate into quarantine", never "auto-trust" (see Stage 5)


@dataclass
class AIProviderConfig:
    provider: str = "ollama"  # "ollama" | "openai"
    ollama_host: str = "localhost:11434"
    ollama_model: str = "qwen3:8b"
    ollama_report_model: str = "qwen3:14b"
    openai_api_key: str = ""
    openai_model: str = "gpt-4"
    openai_report_model: str = "gpt-4"


@dataclass
class SMBConfig:
    server: str = ""
    share: str = ""
    username: str = ""


@dataclass
class CVEConfig:
    source: str = "nvd"  # "nvd" | "off"
    nvd_api_key: str = ""
    cache_path: str = ""  # resolved by ProjectContext to <project>/.cve_cache.sqlite3
    cache_ttl_days: int = 30
    request_timeout: float = 10.0


@dataclass
class WebhookConfig:
    """Opt-in, local-only outbound notifications. Disabled unless a URL is
    configured; `events` restricts which event types are actually POSTed."""
    enabled: bool = False
    url: str = ""
    events: List[str] = field(default_factory=lambda: list(DEFAULT_WEBHOOK_EVENTS))
    timeout: float = 5.0


@dataclass
class AdaptiveScanConfig:
    enabled: bool = True
    escalation_threshold: int = 2
    peer_escalation_threshold: int = 1
    max_escalated_hosts: int = 25
    high_value_ports: List[int] = field(default_factory=lambda: list(DEFAULT_HIGH_VALUE_PORTS))
    notable_version_patterns: List[str] = field(default_factory=lambda: list(DEFAULT_NOTABLE_VERSION_PATTERNS))
    service_overexposure_thresholds: Dict[str, int] = field(
        default_factory=lambda: dict(DEFAULT_SERVICE_OVEREXPOSURE_THRESHOLDS)
    )


@dataclass
class Config:
    ports: List[int]
    timeout: float
    external_ip_url: str
    output_format: str
    smb: SMBConfig
    valid_external_ranges: List[str]
    ai: AIProviderConfig
    cve: CVEConfig
    adaptive: AdaptiveScanConfig
    automation: AutomationFlags
    webhooks: WebhookConfig
    scan_mode: str = "adaptive"  # "quick" | "full" | "adaptive"
    external_ip: Optional[str] = None

    @classmethod
    def load(cls, xml_path: str, cli_args: Optional[argparse.Namespace] = None) -> "Config":
        raw = load_settings_xml(xml_path)
        cli_args = cli_args if cli_args is not None else argparse.Namespace()

        smb = SMBConfig(
            server=raw.get("smb_server", ""),
            share=raw.get("smb_share", ""),
            username=raw.get("smb_username", ""),
        )
        ai = AIProviderConfig(
            provider=raw.get("default_ai_provider", "ollama"),
            ollama_host=raw.get("ollama_host", "localhost:11434"),
            ollama_model=raw.get("ollama_model", "qwen3:8b"),
            ollama_report_model=raw.get("ollama_report_model", raw.get("ollama_model", "qwen3:14b")),
            openai_api_key=raw.get("openai_api_key", ""),
            openai_model=raw.get("openai_model", "gpt-4"),
            openai_report_model=raw.get("openai_report_model", raw.get("openai_model", "gpt-4")),
        )
        cve = CVEConfig(
            source=raw.get("cve_source", "nvd"),
            nvd_api_key=raw.get("nvd_api_key", ""),
            cache_ttl_days=raw.get("cve_cache_ttl_days", 30),
        )
        webhooks = WebhookConfig(
            enabled=bool(raw.get("webhook_enabled", False)),
            url=raw.get("webhook_url", ""),
            events=raw.get("webhook_events") or list(DEFAULT_WEBHOOK_EVENTS),
            timeout=raw.get("webhook_timeout", 5.0),
        )
        adaptive = AdaptiveScanConfig(
            escalation_threshold=raw.get("adaptive_escalation_threshold", 2),
            peer_escalation_threshold=raw.get("adaptive_peer_escalation_threshold", 1),
            max_escalated_hosts=raw.get("adaptive_max_escalated_hosts", 25),
            high_value_ports=raw.get("adaptive_high_value_ports") or list(DEFAULT_HIGH_VALUE_PORTS),
            notable_version_patterns=raw.get("adaptive_notable_version_patterns") or list(DEFAULT_NOTABLE_VERSION_PATTERNS),
        )

        automation = AutomationFlags()
        automation.general = bool(getattr(cli_args, "auto", False))
        automation.upload = False if getattr(cli_args, "no_upload", False) else (
            automation.general or bool(getattr(cli_args, "auto_upload", False))
        )
        automation.ai_analysis = False if getattr(cli_args, "no_ai", False) else (
            automation.general or bool(getattr(cli_args, "auto_ai", False))
        )
        automation.view_report = automation.general or bool(getattr(cli_args, "auto_view_report", False))
        automation.plugin = automation.general or bool(getattr(cli_args, "auto_plugin", False))

        scan_mode = getattr(cli_args, "scan_mode", None) or "adaptive"

        cve_source_override = getattr(cli_args, "cve_source", None)
        if cve_source_override:
            cve.source = cve_source_override
        nvd_key_override = getattr(cli_args, "nvd_api_key", None)
        if nvd_key_override:
            cve.nvd_api_key = nvd_key_override

        return cls(
            ports=raw.get("ports", []),
            timeout=raw.get("timeout", 0.5),
            external_ip_url=raw.get("external_ip_url", "https://api.ipify.org"),
            output_format=raw.get("output_format", "XML"),
            smb=smb,
            valid_external_ranges=raw.get("valid_external_ranges", []),
            ai=ai,
            cve=cve,
            adaptive=adaptive,
            automation=automation,
            webhooks=webhooks,
            scan_mode=scan_mode,
        )
