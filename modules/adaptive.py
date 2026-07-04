import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict

from utils.config import AdaptiveScanConfig
from utils.models import HostResult


@dataclass
class EscalationDecision:
    escalate: bool
    reason: str
    score: int


class AdaptiveScanPlanner:
    """Pure, no-I/O scan-escalation logic: decides which hosts get a deeper
    nmap pass based on findings from the initial quick scan, instead of
    applying --scan-mode uniformly to every host regardless of what's there."""

    def __init__(self, config: AdaptiveScanConfig):
        self.config = config

    def score_host(self, hr: HostResult) -> EscalationDecision:
        score = 0
        reasons = []
        for pr in hr.ports:
            if pr.state == "open" and pr.port in self.config.high_value_ports:
                score += 1
                reasons.append(f"high-value port {pr.port} open")
            for pattern in self.config.notable_version_patterns:
                if pr.version and re.search(pattern, pr.version, re.IGNORECASE):
                    score += 2
                    reasons.append(f"notable version match on port {pr.port}: {pr.version}")
            for plugin_name, result in pr.plugin_results.items():
                if isinstance(result, dict) and result.get("escalate"):
                    score += int(result.get("escalate_weight", 2))
                    reasons.append(result.get("escalate_reason", f"{plugin_name} flagged escalation"))

        threshold = self.config.escalation_threshold
        return EscalationDecision(escalate=score >= threshold, reason="; ".join(reasons), score=score)

    def plan(self, hosts: Dict[str, HostResult]) -> Dict[str, EscalationDecision]:
        decisions = {host: self.score_host(hr) for host, hr in hosts.items()}

        # Peer influence: if any host in a /24 escalated, re-score its peers at
        # the lower peer_escalation_threshold — a subnet with one interesting
        # host is worth a closer look at its neighbors too.
        subnets = defaultdict(list)
        for host in hosts:
            try:
                subnet = ipaddress.ip_network(f"{host}/24", strict=False)
            except ValueError:
                continue
            subnets[subnet].append(host)

        for subnet, members in subnets.items():
            if any(decisions[m].escalate for m in members):
                for m in members:
                    d = decisions[m]
                    if not d.escalate and d.score >= self.config.peer_escalation_threshold:
                        decisions[m] = EscalationDecision(
                            escalate=True,
                            reason=(d.reason + "; " if d.reason else "") + "peer host in same /24 escalated",
                            score=d.score,
                        )

        # Safety cap: never escalate more than max_escalated_hosts (personal-scale
        # tool, avoid runaway scan time on large scopes).
        escalated = [h for h, d in decisions.items() if d.escalate]
        if len(escalated) > self.config.max_escalated_hosts:
            keep = set(sorted(escalated, key=lambda h: -decisions[h].score)[: self.config.max_escalated_hosts])
            for h in escalated:
                if h not in keep:
                    d = decisions[h]
                    decisions[h] = EscalationDecision(escalate=False, reason=d.reason + " (capped)", score=d.score)

        return decisions
