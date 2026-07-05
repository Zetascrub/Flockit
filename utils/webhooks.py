from datetime import datetime

import requests

from utils.common import print_status
from utils.config import WebhookConfig


class WebhookNotifier:
    """Opt-in, fire-and-forget webhook delivery. Disabled by default; a
    delivery failure only logs a warning and never interrupts a run."""

    def __init__(self, config: WebhookConfig, project_id: str):
        self.config = config
        self.project_id = project_id

    def _enabled_for(self, event: str) -> bool:
        return bool(self.config.enabled and self.config.url and event in self.config.events)

    def send(self, event: str, **fields) -> bool:
        if not self._enabled_for(event):
            return False
        payload = {
            "event": event,
            "project": self.project_id,
            "timestamp": datetime.now().isoformat(),
            **fields,
        }
        try:
            requests.post(self.config.url, json=payload, timeout=self.config.timeout)
            return True
        except requests.RequestException as e:
            print_status(f"[!] Webhook delivery failed for {event}: {e}", "warning")
            return False

    def run_start(self, targets):
        self.send("run_start", targets=list(targets))

    def run_complete(self, *, hosts_scanned, findings_count, report_path):
        self.send(
            "run_complete",
            hosts_scanned=hosts_scanned,
            findings_count=findings_count,
            report_path=report_path,
        )

    def high_severity_finding(self, finding):
        self.send(
            "high_severity_finding",
            finding_id=finding.id,
            title=finding.title,
            severity=finding.severity,
            affected_hosts=list(finding.affected_hosts),
        )

    def scan_failure(self, host, reason):
        self.send("scan_failure", host=host, reason=reason)
