import unittest
from unittest.mock import MagicMock

from modules import correlation
from utils.config import AdaptiveScanConfig
from utils.models import CVEMatch, HostResult, PortResult, ScanRun


def make_match(cve_id="CVE-2023-1111", severity="high"):
    return CVEMatch(cve_id=cve_id, summary="test summary", cvss=7.5, severity=severity, source="nvd")


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.cfg = AdaptiveScanConfig()

        pr1 = PortResult(port=22, service="ssh", product="OpenSSH", version="7.4", cve_matches=[make_match()])
        pr2 = PortResult(port=22, service="ssh", product="OpenSSH", version="7.4", cve_matches=[make_match()])
        pr3 = PortResult(port=23, service="telnet", state="open")

        self.host_a = HostResult(host="10.0.0.1", ports=[pr1])
        self.host_b = HostResult(host="10.0.0.2", ports=[pr2, pr3])
        self.host_c = HostResult(host="10.0.0.3", ports=[PortResult(port=80, service="http", state="open")])

        self.scan_run = ScanRun(hosts={
            "10.0.0.1": self.host_a,
            "10.0.0.2": self.host_b,
            "10.0.0.3": self.host_c,
        })

    def test_repeated_cve_detected_across_hosts(self):
        findings = correlation.correlate(self.scan_run, self.cfg)
        repeated = [f for f in findings if f.category == "repeated-cve"]

        self.assertEqual(len(repeated), 1)
        self.assertEqual(sorted(repeated[0].affected_hosts), ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(repeated[0].cve_ids, ["CVE-2023-1111"])

    def test_same_vulnerable_version_detected_across_hosts(self):
        findings = correlation.correlate(self.scan_run, self.cfg)
        version_findings = [f for f in findings if f.category == "same-vulnerable-version"]

        self.assertEqual(len(version_findings), 1)
        self.assertIn("OpenSSH", version_findings[0].title)
        self.assertEqual(sorted(version_findings[0].affected_hosts), ["10.0.0.1", "10.0.0.2"])

    def test_telnet_overexposure_fires_on_single_occurrence(self):
        findings = correlation.correlate(self.scan_run, self.cfg)
        overexposure = [f for f in findings if f.category == "service-overexposure" and "telnet" in f.title]

        self.assertEqual(len(overexposure), 1)
        self.assertEqual(overexposure[0].affected_hosts, ["10.0.0.2"])

    def test_ssh_does_not_overexpose_on_single_occurrence(self):
        # Only host_a and host_b have ssh (2 hosts total), well under the
        # default ssh threshold of 10 — should not fire.
        findings = correlation.correlate(self.scan_run, self.cfg)
        ssh_overexposure = [f for f in findings if f.category == "service-overexposure" and "ssh" in f.title]

        self.assertEqual(ssh_overexposure, [])

    def test_findings_sorted_by_severity_then_host_count(self):
        findings = correlation.correlate(self.scan_run, self.cfg)
        severities = [correlation.SEVERITY_ORDER.get(f.severity, 5) for f in findings]

        self.assertEqual(severities, sorted(severities))

    def test_credential_weakness_grouped_across_hosts(self):
        pr_a = PortResult(port=21, service="ftp")
        pr_a.plugin_results["ftp_scan"] = {"anonymous_login": True}
        pr_b = PortResult(port=21, service="ftp")
        pr_b.plugin_results["ftp_scan"] = {"anonymous_login": True}

        scan_run = ScanRun(hosts={
            "10.0.0.10": HostResult(host="10.0.0.10", ports=[pr_a]),
            "10.0.0.11": HostResult(host="10.0.0.11", ports=[pr_b]),
        })

        findings = correlation.correlate(scan_run, self.cfg)
        weakness = [f for f in findings if f.category == "credential-weakness"]

        self.assertEqual(len(weakness), 1)
        self.assertEqual(sorted(weakness[0].affected_hosts), ["10.0.0.10", "10.0.0.11"])


class NarrateTests(unittest.TestCase):
    def test_narrate_only_touches_top_n_and_never_invents_findings(self):
        findings = [
            correlation.Finding(id=f"f{i}", title=f"Finding {i}", severity="high", category="repeated-cve", affected_hosts=["h1"])
            for i in range(5)
        ]
        ai_client = MagicMock()
        ai_client.chat.return_value = "narrative text"

        correlation.narrate(findings, ai_client, top_n=2)

        self.assertEqual(findings[0].narrative, "narrative text")
        self.assertEqual(findings[1].narrative, "narrative text")
        self.assertIsNone(findings[2].narrative)
        self.assertEqual(ai_client.chat.call_count, 2)
        self.assertEqual(len(findings), 5)  # narrate never adds/removes findings


if __name__ == "__main__":
    unittest.main()
