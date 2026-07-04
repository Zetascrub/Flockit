import argparse
import os
import tempfile
import textwrap
import unittest
from unittest.mock import patch

import utils.common as common
from modules.plugin_manager import PluginManager
from modules.reporter import Reporter
from modules.preflight import PreFlight
from modules.scanner import Scanner
from utils.config import Config
from utils.context import ProjectContext
from utils.models import HostResult, PortResult, ScanRun


def make_ctx(project_dir, scope_source="scope.txt"):
    """Build a ProjectContext against default settings (no XML file needed)
    for use in tests."""
    config = Config.load("nonexistent_settings.xml", argparse.Namespace())
    return ProjectContext.create(project_dir, scope_source, config)


class PromptTests(unittest.TestCase):
    def test_prompt_yes_no_returns_false_for_no(self):
        with patch("builtins.input", return_value="n"):
            self.assertFalse(common.prompt_yes_no("Continue? "))

    def test_prompt_yes_no_returns_true_in_auto_mode(self):
        self.assertTrue(common.prompt_yes_no("Continue? ", auto=True))

    def test_prompt_recon_honors_automation_general_flag(self):
        # Regression test: prompt_recon used to pass AUTO["mode"] (a bool) as
        # prompt_yes_no's auto_key (a dict-key string into a global dict),
        # which only worked by accident. Automation state is now threaded
        # through Config/ProjectContext instead of a module-level global.
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            ctx.config.automation.general = True
            preflight = PreFlight(ctx)
            self.assertTrue(preflight.prompt_recon())

    def test_prompt_recon_prompts_when_not_auto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            with patch("builtins.input", return_value="n"):
                preflight = PreFlight(ctx)
                self.assertFalse(preflight.prompt_recon())


class SettingsTests(unittest.TestCase):
    def test_load_settings_normalizes_ai_keys(self):
        settings_xml = textwrap.dedent(
            """\
            <Settings>
                <OllamaHost>localhost</OllamaHost>
                <OllamaModel>llama3.2</OllamaModel>
                <DefaultAIProvider>ollama</DefaultAIProvider>
                <OpenAI>
                    <APIKey>test-key</APIKey>
                    <Model>gpt-test</Model>
                </OpenAI>
            </Settings>
            """
        )
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write(settings_xml)
            path = tmp.name
        try:
            settings = common.load_settings_xml(path)
        finally:
            os.unlink(path)

        self.assertEqual(settings["default_ai_provider"], "ollama")
        self.assertEqual(settings["ollama_host"], "localhost:11434")
        self.assertEqual(settings["ollama_model"], "llama3.2")
        self.assertEqual(settings["openai_api_key"], "test-key")
        self.assertEqual(settings["openai_model"], "gpt-test")


class ScopeTests(unittest.TestCase):
    def test_scope_split_handles_loopback_and_hyphenated_domain(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                with open("custom_scope.txt", "w", encoding="utf-8") as f:
                    f.write("127.0.0.1\nmy-test.example.com\n")

                ctx = make_ctx("PR_TEST", scope_source="custom_scope.txt")
                preflight = PreFlight(ctx)
                preflight.split_scope_file()

                with open("PR_TEST/int_scope.txt", encoding="utf-8") as f:
                    self.assertEqual(f.read().strip(), "127.0.0.1")

                with open("PR_TEST/web_scope.txt", encoding="utf-8") as f:
                    self.assertEqual(f.read().strip(), "http://my-test.example.com")
            finally:
                os.chdir(cwd)

    def test_setup_skips_external_ip_validation_without_external_scope(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                with open("scope.txt", "w", encoding="utf-8") as f:
                    f.write("127.0.0.1\n")

                ctx = make_ctx("PR_TEST")
                preflight = PreFlight(ctx)
                with patch.object(preflight, "check_external_ip_validity") as check_external:
                    preflight.setup()

                check_external.assert_not_called()
            finally:
                os.chdir(cwd)

    def test_setup_validates_external_ip_when_external_scope_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                with open("scope.txt", "w", encoding="utf-8") as f:
                    f.write("8.8.8.8\n")

                ctx = make_ctx("PR_TEST")
                preflight = PreFlight(ctx)
                with patch.object(preflight, "check_external_ip_validity") as check_external:
                    preflight.setup()

                check_external.assert_called_once()
            finally:
                os.chdir(cwd)

    def test_run_checks_does_not_fetch_external_ip_for_empty_ext_scope(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(tmpdir)
            preflight = PreFlight(ctx)
            missing_ext_scope = os.path.join(tmpdir, "ext_scope.txt")

            with patch.object(preflight, "get_external_ip") as get_external_ip:
                preflight.run_checks("ext", missing_ext_scope)

            get_external_ip.assert_not_called()


class ScannerTests(unittest.TestCase):
    def test_full_scan_without_root_skips_os_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            ctx.config.scan_mode = "full"
            with patch("modules.scanner.PluginManager") as plugin_manager:
                plugin_manager.return_value.plugins = []
                scanner = Scanner(ctx, "127.0.0.1")
            with patch("os.geteuid", return_value=1000):
                self.assertEqual(scanner.get_scan_arguments(), "-sV --version-all -sC")

    def test_full_scan_with_root_includes_os_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            ctx.config.scan_mode = "full"
            with patch("modules.scanner.PluginManager") as plugin_manager:
                plugin_manager.return_value.plugins = []
                scanner = Scanner(ctx, "127.0.0.1")
            with patch("os.geteuid", return_value=0):
                self.assertEqual(scanner.get_scan_arguments(), "-O -sV --version-all -sC")


class PluginTests(unittest.TestCase):
    def test_plugin_manager_deduplicates_base_plugin_names(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_code = textwrap.dedent(
                """\
                from modules.plugins import ScanPlugin

                class FirstPlugin(ScanPlugin):
                    def should_run(self, host, port, port_data):
                        return False

                class SecondPlugin(ScanPlugin):
                    def should_run(self, host, port, port_data):
                        return False
                """
            )
            with open(os.path.join(tmpdir, "example.py"), "w", encoding="utf-8") as f:
                f.write(plugin_code)

            plugin_manager = PluginManager(plugin_dir=tmpdir)
            names = [plugin.name for plugin in plugin_manager.plugins]

        self.assertEqual(sorted(names), ["FirstPlugin", "SecondPlugin"])


class ReporterTests(unittest.TestCase):
    def test_report_omits_guessed_artifact_links(self):
        # Regression test: Reporter used to guess artifact filenames from any
        # port key ending in "_scan"/"_output" (e.g. "plugin_x_output"),
        # producing links to files that were never actually saved. Confirm
        # only real, saved artifacts (PortResult/HostResult.artifacts) are rendered.
        pr = PortResult(port=80, state="open", service="http", version="1.0")
        pr.plugin_results["plugin_x_output"] = {"status": "ok"}
        hr = HostResult(host="127.0.0.1", ports=[pr])
        scan_run = ScanRun(hosts={"127.0.0.1": hr}, targets=["127.0.0.1"], mode="quick")

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            output_path = os.path.join(ctx.project_folder, "report.md")
            with patch("builtins.input", return_value="n"):
                reporter = Reporter(ctx, scan_run, output_path)
                report_md = reporter.generate_report()

        self.assertNotIn("plugin_x_output_output.txt", report_md)
        self.assertNotIn("AI Vulnerability Analysis", report_md)

    def test_report_notes_preflight_discrepancy_only_when_disagreeing(self):
        from utils.models import PreflightHint

        pr = PortResult(port=631, state="open", service="ipp")
        hr = HostResult(host="127.0.0.1", ports=[pr], preflight_hint=PreflightHint(responded=False, open_ports=[]))
        scan_run = ScanRun(hosts={"127.0.0.1": hr}, targets=["127.0.0.1"], mode="quick")

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            output_path = os.path.join(ctx.project_folder, "report.md")
            with patch("builtins.input", return_value="n"):
                reporter = Reporter(ctx, scan_run, output_path)
                report_md = reporter.generate_report()

        self.assertIn("Preflight vs Active Scan discrepancy", report_md)


if __name__ == "__main__":
    unittest.main()
