import os
import tempfile
import textwrap
import unittest

from modules.nessus_import import findings_from_nessus, parse_nessus_file


class NessusImportTests(unittest.TestCase):
    def test_parse_nessus_report_items_into_scan_run(self):
        xml = textwrap.dedent("""\
            <NessusClientData_v2>
              <Report name="LAN scan">
                <ReportHost name="router.local">
                  <HostProperties>
                    <tag name="host-ip">192.168.1.1</tag>
                    <tag name="host-fqdn">router.local</tag>
                  </HostProperties>
                  <ReportItem port="443" svc_name="www" protocol="tcp" severity="3"
                              pluginID="12345" pluginName="Example TLS Finding" pluginFamily="Web Servers">
                    <risk_factor>High</risk_factor>
                    <synopsis>The remote web server has a TLS issue.</synopsis>
                    <description>Example detailed description.</description>
                    <solution>Fix TLS configuration.</solution>
                    <cvss3_base_score>7.5</cvss3_base_score>
                    <cvss3_vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</cvss3_vector>
                    <cve>CVE-2024-0001</cve>
                    <cve>CVE-2024-0002</cve>
                    <see_also>https://example.test/advisory</see_also>
                    <plugin_output>Observed weak TLS setting.</plugin_output>
                    <cpe>cpe:/a:example:web:1.0</cpe>
                  </ReportItem>
                </ReportHost>
              </Report>
            </NessusClientData_v2>
        """)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "scan.nessus")
            with open(path, "w", encoding="utf-8") as f:
                f.write(xml)

            scan_run = parse_nessus_file(path)

        self.assertEqual(scan_run.mode, "nessus-import")
        self.assertIn("192.168.1.1", scan_run.hosts)
        host = scan_run.hosts["192.168.1.1"]
        self.assertEqual(host.hostname, "router.local")
        self.assertEqual(len(host.ports), 1)
        port = host.ports[0]
        self.assertEqual(port.port, 443)
        self.assertEqual(port.service, "www")
        self.assertEqual(port.cpe, "cpe:/a:example:web:1.0")
        self.assertEqual([match.cve_id for match in port.cve_matches], ["CVE-2024-0001", "CVE-2024-0002"])
        self.assertEqual(port.cve_matches[0].source, "nessus")
        self.assertEqual(port.plugin_results["nessus_12345"]["severity"], "high")

    def test_findings_from_nessus_groups_plugin_hits(self):
        xml = textwrap.dedent("""\
            <NessusClientData_v2>
              <Report name="LAN scan">
                <ReportHost name="192.168.1.10">
                  <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="2"
                              pluginID="90001" pluginName="SSH Example" pluginFamily="General">
                    <synopsis>SSH needs attention.</synopsis>
                    <solution>Patch SSH.</solution>
                    <cve>CVE-2024-1111</cve>
                  </ReportItem>
                </ReportHost>
                <ReportHost name="192.168.1.11">
                  <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="2"
                              pluginID="90001" pluginName="SSH Example" pluginFamily="General">
                    <synopsis>SSH needs attention.</synopsis>
                    <solution>Patch SSH.</solution>
                    <cve>CVE-2024-1111</cve>
                  </ReportItem>
                </ReportHost>
              </Report>
            </NessusClientData_v2>
        """)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "scan.nessus")
            with open(path, "w", encoding="utf-8") as f:
                f.write(xml)
            findings = findings_from_nessus(parse_nessus_file(path))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, "nessus-90001")
        self.assertEqual(findings[0].affected_hosts, ["192.168.1.10", "192.168.1.11"])
        self.assertEqual(findings[0].cve_ids, ["CVE-2024-1111"])

    def test_host_level_items_are_not_counted_as_open_ports(self):
        xml = textwrap.dedent("""\
            <NessusClientData_v2>
              <Report name="LAN scan">
                <ReportHost name="192.168.1.10">
                  <ReportItem port="0" svc_name="general" protocol="tcp" severity="3"
                              pluginID="90002" pluginName="Local Package Finding" pluginFamily="Ubuntu Local Security Checks">
                    <synopsis>Package needs attention.</synopsis>
                    <solution>Patch package.</solution>
                    <cve>CVE-2024-2222</cve>
                  </ReportItem>
                </ReportHost>
              </Report>
            </NessusClientData_v2>
        """)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "scan.nessus")
            with open(path, "w", encoding="utf-8") as f:
                f.write(xml)
            scan_run = parse_nessus_file(path)

        port = scan_run.hosts["192.168.1.10"].ports[0]
        self.assertEqual(port.port, 0)
        self.assertEqual(port.state, "info")


if __name__ == "__main__":
    unittest.main()
