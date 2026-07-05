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
        self.assertIn("CVE-2023-1111", repeated[0].description)
        self.assertIn("vendor-recommended patch", repeated[0].recommendation)

    def test_same_vulnerable_version_detected_across_hosts(self):
        findings = correlation.correlate(self.scan_run, self.cfg)
        version_findings = [f for f in findings if f.category == "same-vulnerable-version"]

        self.assertEqual(len(version_findings), 1)
        self.assertIn("OpenSSH", version_findings[0].title)
        self.assertEqual(sorted(version_findings[0].affected_hosts), ["10.0.0.1", "10.0.0.2"])
        self.assertIn("same vulnerable", version_findings[0].description)
        self.assertIn("upgrade", version_findings[0].recommendation)

    def test_telnet_overexposure_fires_on_single_occurrence(self):
        findings = correlation.correlate(self.scan_run, self.cfg)
        overexposure = [f for f in findings if f.category == "service-overexposure" and "telnet" in f.title]

        self.assertEqual(len(overexposure), 1)
        self.assertEqual(overexposure[0].affected_hosts, ["10.0.0.2"])
        self.assertIn("exposed", overexposure[0].description)
        self.assertIn("Restrict telnet exposure", overexposure[0].recommendation)

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
        self.assertIn("credential", weakness[0].description.lower())
        self.assertIn("Disable anonymous", weakness[0].recommendation)

    def test_dns_recursion_detected_from_plugin_output(self):
        pr_a = PortResult(port=53, service="domain")
        pr_a.plugin_results["dns_scan"] = {"recursion_check": {"recursion_available": True, "rcode": 0}}
        pr_b = PortResult(port=53, service="domain")
        pr_b.plugin_results["dns_scan"] = {"recursion_check": {"recursion_available": False, "rcode": 5}}

        scan_run = ScanRun(hosts={
            "10.0.0.10": HostResult(host="10.0.0.10", ports=[pr_a]),
            "10.0.0.11": HostResult(host="10.0.0.11", ports=[pr_b]),
        })

        findings = correlation.correlate(scan_run, self.cfg)
        dns_findings = [f for f in findings if f.category == "dns-recursion"]

        self.assertEqual(len(dns_findings), 1)
        self.assertEqual(dns_findings[0].affected_hosts, ["10.0.0.10"])
        self.assertIn("recursion", dns_findings[0].description.lower())
        self.assertIn("Restrict recursive DNS", dns_findings[0].recommendation)

    def test_missing_security_headers_detected_from_web_plugin_output(self):
        pr_a = PortResult(port=80, service="http")
        pr_a.plugin_results["http_scan"] = {
            "status_line": "HTTP/1.1 200 OK",
            "missing_security_headers": ["content-security-policy", "x-frame-options"],
        }
        pr_b = PortResult(port=443, service="https")
        pr_b.plugin_results["tls_scan"] = {"http_status_line": "HTTP/1.1 200 OK", "missing_security_headers": []}
        pr_c = PortResult(port=8080, service="http-proxy")
        pr_c.plugin_results["http_scan"] = {"error": "connection refused", "missing_security_headers": ["x-frame-options"]}

        scan_run = ScanRun(hosts={
            "example.com": HostResult(host="example.com", ports=[pr_a]),
            "secure.example.com": HostResult(host="secure.example.com", ports=[pr_b]),
            "broken.example.com": HostResult(host="broken.example.com", ports=[pr_c]),
        })

        findings = correlation.correlate(scan_run, self.cfg)
        header_findings = [f for f in findings if f.category == "missing-security-headers"]

        self.assertEqual(len(header_findings), 1)
        self.assertEqual(header_findings[0].affected_hosts, ["example.com"])
        self.assertIn("example.com:80", header_findings[0].evidence[0])


class NarrateTests(unittest.TestCase):
    def test_finding_prompt_includes_report_template_fields(self):
        finding = correlation.Finding(
            id="f1",
            title="Finding 1",
            severity="high",
            category="repeated-cve",
            description="Description text",
            impact="Impact text",
            recommendation="Recommendation text",
            affected_hosts=["h1"],
            evidence=["h1:22"],
        )

        prompt = correlation._build_finding_prompt(finding)

        self.assertIn("Description: Description text", prompt)
        self.assertIn("Impact: Impact text", prompt)
        self.assertIn("Recommendation: Recommendation text", prompt)

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
        for call in ai_client.chat.call_args_list:
            self.assertTrue(call.kwargs["use_report_model"])
        self.assertEqual(len(findings), 5)  # narrate never adds/removes findings


if __name__ == "__main__":
    unittest.main()
