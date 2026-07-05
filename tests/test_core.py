import argparse
import csv
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
from modules.ai_prompts import format_ai_summary
from modules.plugins.dnsscan import DNSScan
from modules.plugins.httpscan import HTTPScan
from modules.plugins.sshscan import SSHScan
from modules.plugins.tlsscan import TLSScan
from utils.artifacts import Artifact
from utils.config import Config
from utils.context import ProjectContext
from utils.models import CVEMatch, Finding, HostResult, PortResult, ScanRun


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
                <OllamaModel>qwen3:8b</OllamaModel>
                <OllamaReportModel>qwen3:14b</OllamaReportModel>
                <DefaultAIProvider>ollama</DefaultAIProvider>
                <OpenAI>
                    <APIKey>test-key</APIKey>
                    <Model>gpt-test</Model>
                    <ReportModel>gpt-report-test</ReportModel>
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
        self.assertEqual(settings["ollama_model"], "qwen3:8b")
        self.assertEqual(settings["ollama_report_model"], "qwen3:14b")
        self.assertEqual(settings["openai_api_key"], "test-key")
        self.assertEqual(settings["openai_model"], "gpt-test")
        self.assertEqual(settings["openai_report_model"], "gpt-report-test")


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

                self.assertEqual(preflight.get_web_targets(), ["http://my-test.example.com"])
            finally:
                os.chdir(cwd)

    def test_get_web_targets_returns_empty_list_without_web_scope_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            preflight = PreFlight(ctx)
            self.assertEqual(preflight.get_web_targets(), [])

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

    def test_scan_phase_tracks_completeness_successes_and_failures(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            with patch("modules.scanner.PluginManager") as plugin_manager:
                plugin_manager.return_value.plugins = []
                scanner = Scanner(ctx, ["10.0.0.1", "10.0.0.2"])

            def fake_scan_host(host, arguments):
                if host == "10.0.0.2":
                    raise RuntimeError("scan failed")
                return HostResult(host=host, ports=[PortResult(port=22, service="ssh")])

            scan_run = ScanRun(targets=["10.0.0.1", "10.0.0.2"], mode="quick")
            with patch.object(scanner, "scan_host", side_effect=fake_scan_host):
                scanner._run_scan_phase(["10.0.0.1", "10.0.0.2"], "-F", scan_run)

        self.assertEqual(scan_run.completeness.scanned_hosts, ["10.0.0.1"])
        self.assertEqual(scan_run.completeness.failed_hosts, {"10.0.0.2": "scan failed"})
        self.assertEqual(scan_run.completeness.scan_arguments_by_host["10.0.0.1"], ["-F"])
        self.assertEqual(scan_run.completeness.scan_arguments_by_host["10.0.0.2"], ["-F"])

    def test_scan_host_skips_plugins_for_non_open_ports(self):
        class FakeHost:
            def all_protocols(self):
                return ["tcp"]

            def __getitem__(self, proto):
                return {
                    21: {"state": "filtered", "name": "ftp"},
                    22: {"state": "open", "name": "ssh"},
                }

        class FakePortScanner:
            def scan(self, host, arguments):
                return None

            def csv(self):
                return "host;protocol;port;state\n"

            def __getitem__(self, host):
                return FakeHost()

        class FakePlugin:
            name = "fake_plugin"

            def __init__(self):
                self.calls = []

            def should_run(self, host, port, port_data):
                return True

            def run(self, host, port, port_data):
                self.calls.append(port)
                return {"status": "ok"}

        plugin = FakePlugin()
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            with patch("modules.scanner.PluginManager") as plugin_manager:
                plugin_manager.return_value.plugins = [plugin]
                scanner = Scanner(ctx, "127.0.0.1")
            with patch.object(scanner, "_new_port_scanner", return_value=FakePortScanner()):
                with patch.object(scanner, "grab_banner", return_value=None):
                    result = scanner.scan_host("127.0.0.1", "-F")

        by_port = {pr.port: pr for pr in result.ports}
        self.assertEqual(plugin.calls, [22])
        self.assertEqual(by_port[21].plugin_results, {})
        self.assertIn("fake_plugin", by_port[22].plugin_results)

    def test_scan_host_keeps_per_port_plugin_artifacts_distinct(self):
        # Regression test: the same plugin running on two open ports of the
        # same host used to both save to "{plugin.name}_output.json", so the
        # second port's write silently overwrote the first port's evidence file.
        class FakeHost:
            def all_protocols(self):
                return ["tcp"]

            def __getitem__(self, proto):
                return {
                    80: {"state": "open", "name": "http"},
                    8080: {"state": "open", "name": "http-proxy"},
                }

        class FakePortScanner:
            def scan(self, host, arguments):
                return None

            def csv(self):
                return "host;protocol;port;state\n"

            def __getitem__(self, host):
                return FakeHost()

        class FakePlugin:
            name = "http_scan"

            def should_run(self, host, port, port_data):
                return True

            def run(self, host, port, port_data):
                return {"banner": f"response from port {port}"}

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            with patch("modules.scanner.PluginManager") as plugin_manager:
                plugin_manager.return_value.plugins = [FakePlugin()]
                scanner = Scanner(ctx, "127.0.0.1")
            with patch.object(scanner, "_new_port_scanner", return_value=FakePortScanner()):
                with patch.object(scanner, "grab_banner", return_value=None):
                    result = scanner.scan_host("127.0.0.1", "-F")

            by_port = {pr.port: pr for pr in result.ports}
            output_paths = {pr.artifacts[0].path for pr in by_port.values()}
            self.assertEqual(len(output_paths), 2)  # distinct files, not one overwriting the other

            with open(os.path.join(ctx.project_folder, by_port[80].artifacts[0].path)) as f:
                self.assertIn("port 80", f.read())
            with open(os.path.join(ctx.project_folder, by_port[8080].artifacts[0].path)) as f:
                self.assertIn("port 8080", f.read())

    def test_scan_web_targets_dispatches_http_and_tls_by_scheme(self):
        class FakeHTTPPlugin:
            name = "http_scan"

            def __init__(self):
                self.calls = []

            def run(self, host, port, port_data):
                self.calls.append((host, port))
                return {"status_line": "HTTP/1.1 200 OK", "missing_security_headers": ["content-security-policy"]}

        class FakeTLSPlugin:
            name = "tls_scan"

            def __init__(self):
                self.calls = []

            def run(self, host, port, port_data):
                self.calls.append((host, port))
                return {"http_status_line": "HTTP/1.1 200 OK", "missing_security_headers": []}

        http_plugin = FakeHTTPPlugin()
        tls_plugin = FakeTLSPlugin()
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            with patch("modules.scanner.PluginManager") as plugin_manager:
                plugin_manager.return_value.plugins = [http_plugin, tls_plugin]
                scanner = Scanner(ctx, [])

            results = scanner.scan_web_targets([
                "http://example.com/",
                "https://secure.example.com:8443/login",
            ])

        self.assertEqual(http_plugin.calls, [("example.com", 80)])
        self.assertEqual(tls_plugin.calls, [("secure.example.com", 8443)])

        http_pr = results["example.com"].ports[0]
        self.assertEqual(http_pr.port, 80)
        self.assertEqual(http_pr.banner, "HTTP/1.1 200 OK")
        self.assertIn("http_scan", http_pr.plugin_results)

        tls_pr = results["secure.example.com"].ports[0]
        self.assertEqual(tls_pr.port, 8443)
        self.assertIn("tls_scan", tls_pr.plugin_results)

    def test_scan_web_targets_skips_url_without_hostname(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            with patch("modules.scanner.PluginManager") as plugin_manager:
                plugin_manager.return_value.plugins = []
                scanner = Scanner(ctx, [])

            results = scanner.scan_web_targets(["not-a-valid-url"])

        self.assertEqual(results, {})

    def test_merge_host_result_deduplicates_artifacts_by_path(self):
        # Regression test: adaptive escalation re-scans a host and re-saves
        # the same deterministic artifact filenames (e.g. nmap.csv). A plain
        # list.extend() used to list every artifact twice in the report/CSVs.
        shared_host_artifact = Artifact(label="Raw Nmap CSV Output", path="Scan-Data/10.0.0.1/nmap.csv")
        shared_port_artifact = Artifact(label="ssh_scan Output", path="Scan-Data/10.0.0.1/ssh_scan_output.json")

        existing = HostResult(
            host="10.0.0.1",
            artifacts=[shared_host_artifact],
            ports=[PortResult(port=22, service="ssh", artifacts=[shared_port_artifact])],
        )
        rescanned = HostResult(
            host="10.0.0.1",
            artifacts=[shared_host_artifact],
            ports=[PortResult(port=22, service="ssh", artifacts=[shared_port_artifact])],
        )

        Scanner._merge_host_result(existing, rescanned)

        self.assertEqual(existing.artifacts, [shared_host_artifact])
        self.assertEqual(existing.ports[0].artifacts, [shared_port_artifact])


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

    def test_dns_plugin_matches_dns_services(self):
        plugin = DNSScan()

        self.assertTrue(plugin.should_run("host", 53, {"service": "domain"}))
        self.assertTrue(plugin.should_run("host", 5353, {"service": "dns"}))
        self.assertFalse(plugin.should_run("host", 80, {"service": "http"}))

    def test_tls_plugin_matches_https_services(self):
        plugin = TLSScan()

        self.assertTrue(plugin.should_run("host", 443, {"service": "http"}))
        self.assertTrue(plugin.should_run("host", 8443, {"service": "https-alt"}))
        self.assertTrue(plugin.should_run("host", 9443, {"service": ""}))
        self.assertFalse(plugin.should_run("host", 80, {"service": "http"}))

    def test_http_plugin_extracts_passive_report_evidence(self):
        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def sendall(self, data):
                self.sent = data

            def recv(self, size):
                if getattr(self, "sent_response", False):
                    return b""
                self.sent_response = True
                return (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Server: nginx\r\n"
                    b"X-Frame-Options: DENY\r\n"
                    b"\r\n"
                    b"<html><title>Router Admin</title></html>"
                )

        plugin = HTTPScan()
        with patch("socket.create_connection", return_value=FakeSocket()):
            result = plugin.run("10.0.0.1", 80, {"service": "http"})

        self.assertEqual(result["status_line"], "HTTP/1.1 200 OK")
        self.assertEqual(result["server"], "nginx")
        self.assertEqual(result["title"], "Router Admin")
        self.assertEqual(result["security_headers"]["x-frame-options"], "DENY")
        self.assertIn("content-security-policy", result["missing_security_headers"])

    def test_ssh_plugin_banner_excludes_trailing_kex_packet(self):
        # Regression test: a Dropbear/OpenSSH server's identification line is
        # immediately followed by the binary KEXINIT packet, and a single recv()
        # can capture both in one read. Only the identification line should be kept.
        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def recv(self, size):
                return (
                    b"SSH-2.0-dropbear\r\n"
                    b"\x00\x00\x01\x14\x0a\x14curve25519-sha256,ecdh-sha2-nistp521\x00binary-kex-garbage"
                )

        plugin = SSHScan()
        with patch("socket.create_connection", return_value=FakeSocket()):
            result = plugin.run("10.0.0.1", 22, {"service": "ssh"})

        self.assertEqual(result["banner"], "SSH-2.0-dropbear")
        self.assertNotIn("curve25519", result["banner"])
        self.assertTrue(result["escalate"])


class ReporterTests(unittest.TestCase):
    def test_report_collapses_hosts_without_open_ports(self):
        open_pr = PortResult(port=22, state="open", service="ssh")
        closed_pr = PortResult(port=80, state="closed", service="http")
        scan_run = ScanRun(
            hosts={
                "10.0.0.1": HostResult(host="10.0.0.1", ports=[open_pr]),
                "10.0.0.2": HostResult(host="10.0.0.2", ports=[]),
                "10.0.0.3": HostResult(host="10.0.0.3", ports=[closed_pr]),
            },
            targets=["10.0.0.0/24"],
            mode="quick",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            output_path = os.path.join(ctx.project_folder, "report.md")
            with patch("builtins.input", return_value="n"):
                reporter = Reporter(ctx, scan_run, output_path)
                report_md = reporter.generate_report()

        self.assertIn("- Hosts With Open Ports: 1", report_md)
        self.assertIn("- Open Ports: 1", report_md)
        self.assertIn("- Port Observations: 2", report_md)
        self.assertIn("### Host: 10.0.0.1", report_md)
        self.assertNotIn("### Host: 10.0.0.2", report_md)
        self.assertNotIn("### Host: 10.0.0.3", report_md)
        self.assertIn("## Hosts Without Open Ports", report_md)
        self.assertIn("- Count: 2", report_md)

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

    def test_report_omits_nmap_csv_link_for_hosts_scanned_without_it(self):
        # Regression test: a host with no recorded HostResult/PortResult
        # artifacts (e.g. a web-only target from Scanner.scan_web_targets,
        # which never saves nmap.csv) used to still get a guessed
        # "Scan-Data/<host>/nmap.csv" link even though the file was never written.
        pr = PortResult(port=80, state="open", service="http")
        hr = HostResult(host="example.com", ports=[pr])
        scan_run = ScanRun(hosts={"example.com": hr}, targets=["http://example.com"], mode="quick")

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            output_path = os.path.join(ctx.project_folder, "report.md")
            with patch("builtins.input", return_value="n"):
                reporter = Reporter(ctx, scan_run, output_path)
                report_md = reporter.generate_report()

        self.assertNotIn("nmap.csv", report_md)
        self.assertNotIn("### Host Artifacts", report_md)
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

    def test_report_renders_finding_template_fields(self):
        scan_run = ScanRun(hosts={}, targets=["127.0.0.1"], mode="quick")
        finding = Finding(
            id="f1",
            title="Example finding",
            severity="high",
            category="repeated-cve",
            description="Example description",
            impact="Example impact",
            recommendation="Example recommendation",
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            affected_hosts=["127.0.0.1"],
            evidence=["127.0.0.1:80"],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            output_path = os.path.join(ctx.project_folder, "report.md")
            with patch("builtins.input", return_value="n"):
                reporter = Reporter(ctx, scan_run, output_path, findings=[finding])
                report_md = reporter.generate_report()

        self.assertIn("**Description:** Example description", report_md)
        self.assertIn("**Impact:** Example impact", report_md)
        self.assertIn("**Recommendation:** Example recommendation", report_md)
        self.assertIn("**CVSSv4 Vector:** `CVSS:4.0/", report_md)

    def test_report_omits_empty_finding_template_fields(self):
        scan_run = ScanRun(hosts={}, targets=["127.0.0.1"], mode="quick")
        finding = Finding(
            id="f1",
            title="Example finding",
            severity="high",
            category="repeated-cve",
            affected_hosts=["127.0.0.1"],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            output_path = os.path.join(ctx.project_folder, "report.md")
            with patch("builtins.input", return_value="n"):
                reporter = Reporter(ctx, scan_run, output_path, findings=[finding])
                report_md = reporter.generate_report()

        self.assertNotIn("**Description:**", report_md)
        self.assertNotIn("**Impact:**", report_md)
        self.assertNotIn("**Recommendation:**", report_md)
        self.assertNotIn("**CVSSv4 Vector:**", report_md)

    def test_report_renders_scan_completeness(self):
        scan_run = ScanRun(hosts={}, targets=["10.0.0.1", "10.0.0.2"], mode="quick")
        scan_run.completeness.discovered_hosts = ["10.0.0.1", "10.0.0.2"]
        scan_run.completeness.scanned_hosts = ["10.0.0.1"]
        scan_run.completeness.failed_hosts = {"10.0.0.2": "scan failed"}
        scan_run.completeness.scan_arguments_by_host = {
            "10.0.0.1": ["-F"],
            "10.0.0.2": ["-F", "-sV --version-all -sC"],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            output_path = os.path.join(ctx.project_folder, "report.md")
            with patch("builtins.input", return_value="n"):
                reporter = Reporter(ctx, scan_run, output_path)
                report_md = reporter.generate_report()

        self.assertIn("## Scan Completeness", report_md)
        self.assertIn("- Discovered Hosts: 2", report_md)
        self.assertIn("- Successfully Scanned Hosts: 1", report_md)
        self.assertIn("- Failed Hosts: 1", report_md)
        self.assertIn("- 10.0.0.2: scan failed", report_md)
        self.assertIn("**Scan argument groups:**", report_md)
        self.assertIn("- `-F`: 1 host(s) (10.0.0.1)", report_md)
        self.assertIn("- `-F; -sV --version-all -sC`: 1 host(s) (10.0.0.2)", report_md)

    def test_report_sanitizes_control_characters(self):
        pr = PortResult(port=22, state="open", service="ssh", banner="SSH-2.0-test\x00\x01\nnext")
        pr.plugin_results["ssh_scan"] = {"banner": "SSH-2.0-test\x00\x02\nnext"}
        hr = HostResult(host="127.0.0.1", ports=[pr])
        scan_run = ScanRun(hosts={"127.0.0.1": hr}, targets=["127.0.0.1"], mode="quick")

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            output_path = os.path.join(ctx.project_folder, "report.md")
            with patch("builtins.input", return_value="n"):
                reporter = Reporter(ctx, scan_run, output_path)
                report_md = reporter.generate_report()

        self.assertNotIn("\x00", report_md)
        self.assertNotIn("\x01", report_md)
        self.assertNotIn("\x02", report_md)
        self.assertIn("SSH-2.0-test\\nnext", report_md)
        self.assertIn('"banner": "SSH-2.0-test\\nnext"', report_md)

    def test_report_preserves_finding_narrative_markdown_newlines(self):
        scan_run = ScanRun(hosts={}, targets=["127.0.0.1"], mode="quick")
        finding = Finding(
            id="f1",
            title="Example finding",
            severity="medium",
            category="example",
            affected_hosts=["127.0.0.1"],
            narrative="**Risk:** line one\n**Priority:** line two\x00",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            output_path = os.path.join(ctx.project_folder, "report.md")
            with patch("builtins.input", return_value="n"):
                reporter = Reporter(ctx, scan_run, output_path, findings=[finding])
                report_md = reporter.generate_report()

        self.assertIn("**Risk:** line one\n**Priority:** line two", report_md)
        self.assertNotIn("\\n**Priority:**", report_md)
        self.assertNotIn("\x00", report_md)

    def test_report_writes_findings_and_open_services_csv_exports(self):
        pr = PortResult(
            port=443,
            state="open",
            service="https",
            product="nginx",
            version="1.24",
            cpe="cpe:/a:nginx:nginx:1.24",
            banner="HTTP/1.1 200 OK\x00\nServer: nginx",
            plugin_results={"tls_scan": {"status": "ok"}},
            cve_matches=[CVEMatch(cve_id="CVE-2024-0001", summary="Example", cvss=7.5, severity="high", source="nvd")],
            artifacts=[Artifact(label="TLS Evidence", path="Scan-Data/10.0.0.1/tls_443.json", kind="plugin")],
            escalated=True,
            escalation_reason="TLS service requires deeper checks",
        )
        hr = HostResult(host="10.0.0.1", hostname="web01", ports=[pr])
        scan_run = ScanRun(hosts={"10.0.0.1": hr}, targets=["10.0.0.1"], mode="quick")
        finding = Finding(
            id="f1",
            title="Example finding",
            severity="high",
            category="repeated-cve",
            description="Line one\nLine two",
            impact="Impact",
            recommendation="Fix it",
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            affected_hosts=["10.0.0.1"],
            evidence=["10.0.0.1:443"],
            cve_ids=["CVE-2024-0001"],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = make_ctx(os.path.join(tmpdir, "PR_TEST"))
            output_path = os.path.join(ctx.project_folder, "report.md")
            with patch("builtins.input", return_value="n"):
                reporter = Reporter(ctx, scan_run, output_path, findings=[finding])
                reporter.generate_report()

            with open(os.path.join(ctx.project_folder, "findings.csv"), encoding="utf-8", newline="") as f:
                findings_rows = list(csv.DictReader(f))
            with open(os.path.join(ctx.project_folder, "open_services.csv"), encoding="utf-8", newline="") as f:
                service_rows = list(csv.DictReader(f))

        self.assertEqual(len(findings_rows), 1)
        self.assertEqual(findings_rows[0]["title"], "Example finding")
        self.assertEqual(findings_rows[0]["description"], "Line one\\nLine two")
        self.assertEqual(findings_rows[0]["affected_hosts"], "10.0.0.1")
        self.assertEqual(findings_rows[0]["cve_ids"], "CVE-2024-0001")
        self.assertEqual(len(service_rows), 1)
        self.assertEqual(service_rows[0]["host"], "10.0.0.1")
        self.assertEqual(service_rows[0]["port"], "443")
        self.assertEqual(service_rows[0]["cve_ids"], "CVE-2024-0001")
        self.assertEqual(service_rows[0]["plugin_keys"], "tls_scan")
        self.assertEqual(service_rows[0]["artifact_paths"], "Scan-Data/10.0.0.1/tls_443.json")
        self.assertEqual(service_rows[0]["banner"], "HTTP/1.1 200 OK\\nServer: nginx")
        self.assertEqual(service_rows[0]["escalated"], "true")


class AIPromptTests(unittest.TestCase):
    def test_markdown_ai_summary_uses_flush_details_and_strips_language_markers(self):
        rendered = format_ai_summary("```bash\nPasswordAuthentication no\n```", {"port": 22, "service": "ssh"})

        self.assertIn("<summary><strong>AI Recommendations for 22/tcp (ssh)</strong></summary>", rendered)
        self.assertIn("```markdown\nPasswordAuthentication no\n```", rendered)
        self.assertNotIn("    <summary>", rendered)
        self.assertNotIn("\nbash\n", rendered.lower())


if __name__ == "__main__":
    unittest.main()
