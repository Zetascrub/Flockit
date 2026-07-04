import unittest

from modules.adaptive import AdaptiveScanPlanner
from utils.config import AdaptiveScanConfig
from utils.models import HostResult, PortResult


def make_config(**overrides):
    config = AdaptiveScanConfig()
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


class AdaptiveScanPlannerTests(unittest.TestCase):
    def test_high_value_port_escalates_host(self):
        config = make_config(escalation_threshold=1)
        planner = AdaptiveScanPlanner(config)
        hr = HostResult(host="10.0.0.1", ports=[PortResult(port=3389, state="open", service="ms-wbt-server")])

        decision = planner.score_host(hr)

        self.assertTrue(decision.escalate)
        self.assertIn("high-value port 3389", decision.reason)

    def test_plain_host_does_not_escalate(self):
        config = make_config(escalation_threshold=2)
        planner = AdaptiveScanPlanner(config)
        hr = HostResult(host="10.0.0.2", ports=[PortResult(port=80, state="open", service="http", version="nginx 1.25")])

        decision = planner.score_host(hr)

        self.assertFalse(decision.escalate)

    def test_notable_version_pattern_escalates_host(self):
        config = make_config(escalation_threshold=2, notable_version_patterns=[r"vsftpd 2\.3\.4"])
        planner = AdaptiveScanPlanner(config)
        hr = HostResult(host="10.0.0.3", ports=[PortResult(port=21, state="open", service="ftp", version="vsftpd 2.3.4")])

        decision = planner.score_host(hr)

        self.assertTrue(decision.escalate)
        self.assertIn("notable version match", decision.reason)

    def test_plugin_escalate_opt_in_contributes_to_score(self):
        config = make_config(escalation_threshold=2)
        planner = AdaptiveScanPlanner(config)
        pr = PortResult(port=8080, state="open", service="http")
        pr.plugin_results["some_plugin"] = {"escalate": True, "escalate_weight": 3, "escalate_reason": "found admin panel"}
        hr = HostResult(host="10.0.0.4", ports=[pr])

        decision = planner.score_host(hr)

        self.assertTrue(decision.escalate)
        self.assertIn("found admin panel", decision.reason)

    def test_peer_in_same_subnet_escalates_at_lower_threshold(self):
        config = make_config(escalation_threshold=2, peer_escalation_threshold=1)
        planner = AdaptiveScanPlanner(config)
        hosts = {
            # score 2 (two high-value ports): escalates on its own via the base threshold.
            "10.0.0.10": HostResult(host="10.0.0.10", ports=[
                PortResult(port=3389, state="open", service="ms-wbt-server"),
                PortResult(port=445, state="open", service="microsoft-ds"),
            ]),
            # score 1 alone (below base threshold of 2), but a peer in the same /24
            # escalated and 1 >= peer_escalation_threshold, so it gets lifted.
            "10.0.0.11": HostResult(host="10.0.0.11", ports=[PortResult(port=445, state="open", service="microsoft-ds")]),
            # score 0: no high-value port, stays below even the peer threshold.
            "10.0.0.12": HostResult(host="10.0.0.12", ports=[PortResult(port=80, state="open", service="http")]),
        }

        decisions = planner.plan(hosts)

        self.assertTrue(decisions["10.0.0.10"].escalate)
        self.assertTrue(decisions["10.0.0.11"].escalate)
        self.assertIn("peer host in same /24 escalated", decisions["10.0.0.11"].reason)
        self.assertFalse(decisions["10.0.0.12"].escalate)

    def test_safety_cap_keeps_highest_scoring_subset(self):
        config = make_config(escalation_threshold=1, max_escalated_hosts=1)
        planner = AdaptiveScanPlanner(config)
        hosts = {
            "10.0.1.1": HostResult(host="10.0.1.1", ports=[PortResult(port=3389, state="open", service="ms-wbt-server")]),
            "10.0.2.1": HostResult(host="10.0.2.1", ports=[
                PortResult(port=3389, state="open", service="ms-wbt-server"),
                PortResult(port=445, state="open", service="microsoft-ds"),
            ]),
        }

        decisions = planner.plan(hosts)
        escalated = [h for h, d in decisions.items() if d.escalate]

        self.assertEqual(escalated, ["10.0.2.1"])  # higher score kept, other capped
        self.assertIn("capped", decisions["10.0.1.1"].reason)


if __name__ == "__main__":
    unittest.main()
