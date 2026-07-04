import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from modules.cve_lookup import CVECache, CVELookupClient, severity_from_cvss
from utils.config import CVEConfig
from utils.models import PortResult


def make_nvd_response(cve_id="CVE-2023-9999", base_score=9.8, summary="Critical remote code execution."):
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": summary}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": base_score}}]},
                    "references": [{"url": "https://nvd.nist.gov/vuln/detail/" + cve_id}],
                }
            }
        ]
    }


class SeverityTests(unittest.TestCase):
    def test_severity_buckets(self):
        self.assertEqual(severity_from_cvss(9.8), "critical")
        self.assertEqual(severity_from_cvss(7.5), "high")
        self.assertEqual(severity_from_cvss(5.0), "medium")
        self.assertEqual(severity_from_cvss(2.0), "low")
        self.assertEqual(severity_from_cvss(None), "unknown")


class CVELookupClientTests(unittest.TestCase):
    def _make_client(self, tmpdir):
        config = CVEConfig(source="nvd", request_timeout=1.0)
        cache = CVECache(os.path.join(tmpdir, "cache.sqlite3"), ttl_days=30)
        return CVELookupClient(config, cache)

    def test_lookup_by_cpe_returns_severity_bucketed_matches(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = self._make_client(tmpdir)
            pr = PortResult(port=22, service="ssh", version="9.6", cpe="cpe:/a:openbsd:openssh:9.6")

            mock_response = MagicMock(status_code=200)
            mock_response.json.return_value = make_nvd_response()
            with patch("modules.cve_lookup.requests.get", return_value=mock_response) as mock_get:
                matches = client.lookup(pr)

            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].cve_id, "CVE-2023-9999")
            self.assertEqual(matches[0].severity, "critical")
            self.assertEqual(matches[0].matched_cpe, "cpe:/a:openbsd:openssh:9.6")
            mock_get.assert_called_once()
            self.assertEqual(mock_get.call_args.kwargs["params"], {"cpeName": "cpe:/a:openbsd:openssh:9.6"})

    def test_cache_hit_avoids_second_http_call(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = self._make_client(tmpdir)
            pr = PortResult(port=22, service="ssh", version="9.6", cpe="cpe:/a:openbsd:openssh:9.6")

            mock_response = MagicMock(status_code=200)
            mock_response.json.return_value = make_nvd_response()
            with patch("modules.cve_lookup.requests.get", return_value=mock_response) as mock_get:
                client.lookup(pr)
                client.lookup(pr)

            mock_get.assert_called_once()

    def test_off_source_returns_no_matches_without_network_call(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = CVEConfig(source="off")
            cache = CVECache(os.path.join(tmpdir, "cache.sqlite3"))
            client = CVELookupClient(config, cache)
            pr = PortResult(port=22, service="ssh", version="9.6", cpe="cpe:/a:openbsd:openssh:9.6")

            with patch("modules.cve_lookup.requests.get") as mock_get:
                matches = client.lookup(pr)

            self.assertEqual(matches, [])
            mock_get.assert_not_called()

    def test_falls_back_to_keyword_search_without_cpe(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = self._make_client(tmpdir)
            pr = PortResult(port=21, service="ftp", version="vsftpd 2.3.4", cpe="")

            mock_response = MagicMock(status_code=200)
            mock_response.json.return_value = make_nvd_response(cve_id="CVE-2011-2523", base_score=10.0)
            with patch("modules.cve_lookup.requests.get", return_value=mock_response) as mock_get:
                matches = client.lookup(pr)

            self.assertIsNone(matches[0].matched_cpe)
            self.assertEqual(mock_get.call_args.kwargs["params"], {"keywordSearch": "ftp vsftpd 2.3.4"})

    def test_no_cpe_or_version_returns_no_matches(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = self._make_client(tmpdir)
            pr = PortResult(port=9999, service="", version="", cpe="")

            with patch("modules.cve_lookup.requests.get") as mock_get:
                matches = client.lookup(pr)

            self.assertEqual(matches, [])
            mock_get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
