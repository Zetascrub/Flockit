import dataclasses
import json
import unittest
from datetime import datetime

from utils.artifacts import Artifact
from utils.models import CVEMatch, Finding, HostResult, PortResult, PreflightHint, ScanRun


class ModelSerializationTests(unittest.TestCase):
    def test_host_result_round_trips_through_asdict_to_json(self):
        pr = PortResult(
            port=22,
            service="ssh",
            version="OpenSSH 9.6",
            banner="SSH-2.0-OpenSSH_9.6",
            artifacts=[Artifact(label="Banner 22", path="Scan-Data/host/banner_22.txt", kind="banner")],
            cve_matches=[CVEMatch(cve_id="CVE-2023-1234", summary="test", cvss=7.5, severity="high", source="nvd")],
        )
        hr = HostResult(host="192.168.1.10", ports=[pr], preflight_hint=PreflightHint(responded=True, open_ports=[22]))
        scan_run = ScanRun(hosts={"192.168.1.10": hr}, targets=["192.168.1.10"], mode="quick", started_at=datetime.now())

        as_dict = dataclasses.asdict(scan_run)
        serialized = json.dumps(as_dict, default=str)
        reloaded = json.loads(serialized)

        self.assertEqual(reloaded["hosts"]["192.168.1.10"]["ports"][0]["port"], 22)
        self.assertEqual(reloaded["hosts"]["192.168.1.10"]["ports"][0]["cve_matches"][0]["cve_id"], "CVE-2023-1234")
        self.assertEqual(reloaded["hosts"]["192.168.1.10"]["preflight_hint"]["responded"], True)

    def test_finding_defaults_are_independent_across_instances(self):
        # Regression guard: dataclass mutable defaults must use field(default_factory=...),
        # not a shared list/dict literal, or findings would leak state across instances.
        f1 = Finding(id="a", title="A", severity="high", category="repeated-cve")
        f2 = Finding(id="b", title="B", severity="low", category="service-overexposure")
        f1.affected_hosts.append("host1")

        self.assertEqual(f1.affected_hosts, ["host1"])
        self.assertEqual(f2.affected_hosts, [])


if __name__ == "__main__":
    unittest.main()
