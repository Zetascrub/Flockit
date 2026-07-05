import unittest
from unittest.mock import patch

from utils.config import WebhookConfig
from utils.models import Finding
from utils.webhooks import WebhookNotifier


class WebhookNotifierTests(unittest.TestCase):
    def test_send_is_a_noop_when_disabled(self):
        notifier = WebhookNotifier(WebhookConfig(enabled=False, url="https://example.com/hook"), "PR00000")
        with patch("utils.webhooks.requests.post") as post:
            self.assertFalse(notifier.send("run_start", targets=["10.0.0.1"]))
            post.assert_not_called()

    def test_send_is_a_noop_without_url(self):
        notifier = WebhookNotifier(WebhookConfig(enabled=True, url=""), "PR00000")
        with patch("utils.webhooks.requests.post") as post:
            self.assertFalse(notifier.send("run_start"))
            post.assert_not_called()

    def test_send_is_a_noop_for_unlisted_event(self):
        config = WebhookConfig(enabled=True, url="https://example.com/hook", events=["run_start"])
        notifier = WebhookNotifier(config, "PR00000")
        with patch("utils.webhooks.requests.post") as post:
            self.assertFalse(notifier.send("scan_failure", host="10.0.0.1", reason="boom"))
            post.assert_not_called()

    def test_send_posts_payload_with_event_and_project(self):
        config = WebhookConfig(enabled=True, url="https://example.com/hook", events=["run_start"])
        notifier = WebhookNotifier(config, "PR00099")
        with patch("utils.webhooks.requests.post") as post:
            self.assertTrue(notifier.send("run_start", targets=["10.0.0.1"]))
            post.assert_called_once()
            self.assertEqual(post.call_args.args[0], "https://example.com/hook")
            payload = post.call_args.kwargs["json"]
            self.assertEqual(payload["event"], "run_start")
            self.assertEqual(payload["project"], "PR00099")
            self.assertEqual(payload["targets"], ["10.0.0.1"])
            self.assertEqual(post.call_args.kwargs["timeout"], config.timeout)

    def test_send_failure_is_swallowed(self):
        import requests

        config = WebhookConfig(enabled=True, url="https://example.com/hook", events=["run_start"])
        notifier = WebhookNotifier(config, "PR00000")
        with patch("utils.webhooks.requests.post", side_effect=requests.RequestException("boom")):
            self.assertFalse(notifier.send("run_start"))

    def test_high_severity_finding_sends_expected_fields(self):
        config = WebhookConfig(enabled=True, url="https://example.com/hook", events=["high_severity_finding"])
        notifier = WebhookNotifier(config, "PR00000")
        finding = Finding(
            id="repeated-cve-CVE-2023-1111",
            title="CVE-2023-1111 present on 2 hosts",
            severity="high",
            category="repeated-cve",
            affected_hosts=["10.0.0.1", "10.0.0.2"],
        )
        with patch("utils.webhooks.requests.post") as post:
            notifier.high_severity_finding(finding)
            payload = post.call_args.kwargs["json"]
            self.assertEqual(payload["finding_id"], finding.id)
            self.assertEqual(payload["severity"], "high")
            self.assertEqual(payload["affected_hosts"], finding.affected_hosts)


if __name__ == "__main__":
    unittest.main()
