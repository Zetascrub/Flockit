import argparse
import os
import tempfile
import textwrap
import unittest

from utils.config import Config


class ConfigLoadTests(unittest.TestCase):
    def test_load_populates_nested_dataclasses_from_xml(self):
        settings_xml = textwrap.dedent(
            """\
            <Settings>
                <Ports>22,443</Ports>
                <Timeout>1.5</Timeout>
                <SMB>
                    <Server>fileserver</Server>
                    <Share>Media</Share>
                    <Username>tester</Username>
                </SMB>
                <DefaultAIProvider>openai</DefaultAIProvider>
                <OllamaModel>qwen3:8b</OllamaModel>
                <OllamaReportModel>qwen3:14b</OllamaReportModel>
                <OpenAI>
                    <APIKey>test-key</APIKey>
                    <Model>gpt-test</Model>
                    <ReportModel>gpt-report-test</ReportModel>
                </OpenAI>
                <CVE>
                    <Source>nvd</Source>
                    <NVDApiKey>nvd-key</NVDApiKey>
                    <CacheTTLDays>7</CacheTTLDays>
                </CVE>
                <AdaptiveScan>
                    <EscalationThreshold>3</EscalationThreshold>
                    <MaxEscalatedHosts>5</MaxEscalatedHosts>
                    <HighValuePorts>21,3389</HighValuePorts>
                    <NotableVersionPatterns>
                        <Pattern>vsftpd 2\\.3\\.4</Pattern>
                    </NotableVersionPatterns>
                </AdaptiveScan>
                <Webhook>
                    <Enabled>true</Enabled>
                    <URL>https://example.com/hook</URL>
                    <Timeout>2.5</Timeout>
                    <Events>
                        <Event>run_start</Event>
                        <Event>scan_failure</Event>
                    </Events>
                </Webhook>
            </Settings>
            """
        )
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".xml") as tmp:
            tmp.write(settings_xml)
            path = tmp.name
        try:
            config = Config.load(path, argparse.Namespace())
        finally:
            os.unlink(path)

        self.assertEqual(config.ports, [22, 443])
        self.assertEqual(config.timeout, 1.5)
        self.assertEqual(config.smb.server, "fileserver")
        self.assertEqual(config.ai.provider, "openai")
        self.assertEqual(config.ai.ollama_model, "qwen3:8b")
        self.assertEqual(config.ai.ollama_report_model, "qwen3:14b")
        self.assertEqual(config.ai.openai_api_key, "test-key")
        self.assertEqual(config.ai.openai_model, "gpt-test")
        self.assertEqual(config.ai.openai_report_model, "gpt-report-test")
        self.assertEqual(config.cve.source, "nvd")
        self.assertEqual(config.cve.nvd_api_key, "nvd-key")
        self.assertEqual(config.cve.cache_ttl_days, 7)
        self.assertEqual(config.adaptive.escalation_threshold, 3)
        self.assertEqual(config.adaptive.max_escalated_hosts, 5)
        self.assertEqual(config.adaptive.high_value_ports, [21, 3389])
        self.assertEqual(config.adaptive.notable_version_patterns, ["vsftpd 2\\.3\\.4"])
        self.assertTrue(config.webhooks.enabled)
        self.assertEqual(config.webhooks.url, "https://example.com/hook")
        self.assertEqual(config.webhooks.timeout, 2.5)
        self.assertEqual(config.webhooks.events, ["run_start", "scan_failure"])

    def test_missing_settings_file_uses_defaults(self):
        config = Config.load("this_file_does_not_exist.xml", argparse.Namespace())
        self.assertEqual(config.ai.provider, "ollama")
        self.assertEqual(config.ai.ollama_model, "qwen3:8b")
        self.assertEqual(config.ai.ollama_report_model, "qwen3:14b")
        self.assertEqual(config.cve.source, "nvd")
        self.assertEqual(config.scan_mode, "adaptive")
        self.assertFalse(config.webhooks.enabled)
        self.assertEqual(config.webhooks.url, "")
        self.assertEqual(config.webhooks.events, ["run_start", "run_complete", "high_severity_finding", "scan_failure"])

    def test_cli_overrides_win_over_xml_and_defaults(self):
        cli_args = argparse.Namespace(
            no_ai=True,
            no_upload=False,
            auto=False,
            auto_upload=True,
            auto_ai=False,
            auto_view_report=False,
            auto_plugin=False,
            scan_mode="full",
            cve_source="off",
            nvd_api_key="cli-key",
        )
        config = Config.load("this_file_does_not_exist.xml", cli_args)

        self.assertFalse(config.automation.ai_analysis)  # --no-ai forces this off
        self.assertTrue(config.automation.upload)  # --auto-upload
        self.assertEqual(config.scan_mode, "full")
        self.assertEqual(config.cve.source, "off")
        self.assertEqual(config.cve.nvd_api_key, "cli-key")

    def test_auto_flag_forces_all_automation_flags(self):
        cli_args = argparse.Namespace(auto=True, no_ai=False, no_upload=False)
        config = Config.load("this_file_does_not_exist.xml", cli_args)

        self.assertTrue(config.automation.general)
        self.assertTrue(config.automation.upload)
        self.assertTrue(config.automation.ai_analysis)
        self.assertTrue(config.automation.view_report)
        self.assertTrue(config.automation.plugin)


if __name__ == "__main__":
    unittest.main()
