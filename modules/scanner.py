import concurrent.futures
import json
import logging
import os
import re
import socket
from datetime import datetime

from modules.adaptive import AdaptiveScanPlanner
from modules.plugin_manager import PluginManager
from utils.common import print_status
from utils.context import ProjectContext
from utils.models import HostResult, PortResult, ScanRun

DEBUG_AI_PROMPT = False


# --- Active nmap scanning, adaptive escalation, and plugin execution ---
class Scanner:
    def __init__(self, ctx: ProjectContext, targets):
        self.ctx = ctx
        self.targets = targets
        self.mode = ctx.config.scan_mode
        self.results = {}  # host -> HostResult, populated after scan_network()
        self.plugin_manager = PluginManager()

    def _new_port_scanner(self):
        try:
            import nmap
            return nmap.PortScanner()
        except ImportError as exc:
            raise RuntimeError("python-nmap is not installed. Install dependencies with `pip install -r requirements.txt`.") from exc

    def discover_hosts(self):
        print_status(f"[+] Discovering live hosts in {' '.join(self.targets if isinstance(self.targets, list) else [self.targets])}...", "info")
        scanner = self._new_port_scanner()
        scanner.scan(hosts=" ".join(self.targets if isinstance(self.targets, list) else [self.targets]), arguments="-sn --noninteractive")

        live_hosts = [host for host in scanner.all_hosts() if scanner[host].state() == "up"]

        print_status(f"[+] Found {len(live_hosts)} live hosts", "success")
        return live_hosts

    def scan_network(self, live_hosts) -> ScanRun:
        scan_run = ScanRun(
            targets=self.targets if isinstance(self.targets, list) else [self.targets],
            mode=self.mode,
            started_at=datetime.now(),
        )
        if not live_hosts:
            print_status("[-] No live hosts found. Exiting.", "warning")
            scan_run.finished_at = datetime.now()
            self.results = scan_run.hosts
            return scan_run

        print_status("[+] Scanning network for open ports and services...", "info")

        # Phase A: quick pass across every live host. In adaptive mode this is
        # always "-F" regardless of the eventual per-host depth; quick/full
        # modes keep today's uniform behavior (no escalation phase).
        phase_a_arguments = "-F" if self.mode == "adaptive" else self.get_scan_arguments()
        self._run_scan_phase(live_hosts, phase_a_arguments, scan_run)

        if self.mode == "adaptive" and self.ctx.config.adaptive.enabled:
            self._run_adaptive_escalation(scan_run)

        scan_run.finished_at = datetime.now()
        self.results = scan_run.hosts
        return scan_run

    def _run_scan_phase(self, hosts, scan_arguments, scan_run: ScanRun):
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_host = {executor.submit(self.scan_host, host, scan_arguments): host for host in hosts}
                for future in concurrent.futures.as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        hr = future.result()
                        if host in scan_run.hosts:
                            self._merge_host_result(scan_run.hosts[host], hr)
                        else:
                            scan_run.hosts[host] = hr
                        print_status(f"[+] Scan completed for {host}", "success")
                    except Exception as exc:
                        print_status(f"[-] Error scanning {host}: {exc}", "error")
        except KeyboardInterrupt:
            print_status("[-] Scan interrupted by user. Shutting down.", "error")

    @staticmethod
    def _merge_host_result(existing: HostResult, new: HostResult):
        """Merge a deeper rescan's HostResult into the existing quick-scan
        HostResult: richer product/version/cpe/banner data wins, newly found
        ports are appended, and touched ports are marked escalated."""
        existing.artifacts.extend(new.artifacts)
        existing_by_port = {p.port: p for p in existing.ports}
        for new_port in new.ports:
            if new_port.port in existing_by_port:
                old_port = existing_by_port[new_port.port]
                old_port.product = new_port.product or old_port.product
                old_port.version = new_port.version or old_port.version
                old_port.extrainfo = new_port.extrainfo or old_port.extrainfo
                old_port.cpe = new_port.cpe or old_port.cpe
                old_port.banner = new_port.banner or old_port.banner
                old_port.plugin_results.update(new_port.plugin_results)
                old_port.artifacts.extend(new_port.artifacts)
                old_port.escalated = True
            else:
                new_port.escalated = True
                existing.ports.append(new_port)
        existing.escalated = True

    def _run_adaptive_escalation(self, scan_run: ScanRun):
        planner = AdaptiveScanPlanner(self.ctx.config.adaptive)
        decisions = planner.plan(scan_run.hosts)
        escalated_hosts = [host for host, decision in decisions.items() if decision.escalate]
        if not escalated_hosts:
            return

        print_status(f"[+] Adaptive scan escalating {len(escalated_hosts)} host(s) for deeper analysis...", "info")
        deep_args = self._deep_scan_arguments()
        self._run_scan_phase(escalated_hosts, deep_args, scan_run)

        for host in escalated_hosts:
            hr = scan_run.hosts.get(host)
            if not hr:
                continue
            hr.escalated = True
            reason = decisions[host].reason
            for pr in hr.ports:
                if pr.escalated and not pr.escalation_reason:
                    pr.escalation_reason = reason

    def get_scan_arguments(self):
        if self.mode != "full":
            return "-F"
        return self._deep_scan_arguments()

    def _deep_scan_arguments(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return "-O -sV --version-all -sC"
        print_status("Deep scan requested without root privileges; skipping OS detection (-O).", "warning")
        return "-sV --version-all -sC"

    @staticmethod
    def _plugin_view(pr: PortResult) -> dict:
        """Dict view of a PortResult for the ScanPlugin contract (should_run/run),
        which existing static and AI-generated plugins expect as a plain dict."""
        return {
            "port": pr.port,
            "state": pr.state,
            "service": pr.service,
            "version": pr.version,
            "banner": pr.banner,
        }

    def scan_host(self, host, scan_arguments=None) -> HostResult:
        print_status("[~] Scanning network for open ports and services...", "scan")
        hr = HostResult(host=host)

        scanner = self._new_port_scanner()
        arguments = (scan_arguments or "-F") + " --noninteractive"
        scanner.scan(host, arguments=arguments)

        nmap_raw_output = scanner.csv()
        nmap_artifact = self.ctx.artifacts.save_text(host, "nmap.csv", nmap_raw_output, label="Raw Nmap CSV Output", kind="nmap")
        if nmap_artifact:
            hr.artifacts.append(nmap_artifact)

        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                port_info = scanner[host][proto][port]
                pr = PortResult(
                    port=port,
                    protocol=proto,
                    state=port_info.get("state", ""),
                    service=port_info.get("name", ""),
                    product=port_info.get("product", ""),
                    version=port_info.get("version", ""),
                    extrainfo=port_info.get("extrainfo", ""),
                    cpe=port_info.get("cpe", ""),
                )

                print_status(f"Scanning port {port} on {host}...", "scan")

                self.grab_banner(host, port, pr)

                for plugin in self.plugin_manager.plugins:
                    if plugin.should_run(host, port, self._plugin_view(pr)):
                        try:
                            result = plugin.run(host, port, self._plugin_view(pr))
                            pr.plugin_results[plugin.name] = result

                            if isinstance(result, dict):
                                plugin_artifact = self.ctx.artifacts.save_json(
                                    host, f"{plugin.name}_output.json", result,
                                    label=f"{plugin.name} Output", kind="plugin",
                                )
                                if plugin_artifact:
                                    pr.artifacts.append(plugin_artifact)

                                if "banner" in result:
                                    banner_artifact = self.ctx.artifacts.save_text(
                                        host, f"{plugin.name}_banner.txt", result["banner"],
                                        label=f"{plugin.name} Banner", kind="banner",
                                    )
                                    if banner_artifact:
                                        pr.artifacts.append(banner_artifact)

                        except Exception as e:
                            print_status(f"❌ Plugin {plugin.name} failed on {host}:{port} - {e}", "error")
                            logging.exception(e)

                hr.ports.append(pr)

        return hr

    def grab_banner(self, host, port, pr: PortResult):
        print_status(f"[+] Grabbing banner for {host}:{port}...", "info")
        try:
            with socket.create_connection((host, port), timeout=2) as s:
                s.sendall(b"\r\n")
                banner = s.recv(1024).decode("utf-8", "ignore").strip().split("\n")[0]
                if banner:
                    banner = banner[:200]
                    pr.banner = banner
                    banner_artifact = self.ctx.artifacts.save_text(host, f"banner_{port}.txt", banner, label=f"Banner {port}", kind="banner")
                    if banner_artifact:
                        pr.artifacts.append(banner_artifact)
                    return banner
        except Exception:
            pass
        return None

    def analyse_vulnerabilities(self, hr: HostResult, ai_client):
        if not hr or not isinstance(hr, HostResult):
            return "⚠️ Invalid host data — skipping AI analysis."

        for pr in hr.ports:
            prompt = f"""Scan Results:
    - Port: {pr.port}
    - Service: {pr.service}
    - Version: {pr.version}
    - Banner: {pr.banner or 'N/A'}

    Please provide a short markdown-formatted summary of any potential risks and specific security recommendations for this service."""

            system_prompt = (
                "You are a cybersecurity analyst. Given port scan results, identify risks and give concise, technical recommendations. "
                "Respond in markdown format. Do not include unnecessary fluff."
            )

            ai_summary = ai_client.chat(system_prompt, prompt)
            pr.ai_recommendation = ai_summary.strip() if ai_summary else "No AI feedback available."

        return "✅ Per-port AI summaries attached."

    def count_vulnerabilities(self, vulnerabilities_text):
        return len(re.findall(r'\*\*Vulnerability \d+:', vulnerabilities_text))

    def is_domain(self, target):
        return any(c.isalpha() for c in target)

    def passive_recon(self, target):
        import whois
        import dns.resolver
        results = {}
        try:
            results["whois"] = whois.whois(target)
        except Exception as e:
            results["whois"] = f"WHOIS lookup failed: {e}"
        records = {}
        for rtype in ["A", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(target, rtype)
                records[rtype] = [ans.to_text() for ans in answers]
            except Exception as e:
                records[rtype] = f"DNS lookup failed: {e}"
        results["dns"] = records
        return results

    def run_passive_recon(self):
        passive_results = {}
        targets = self.targets if isinstance(self.targets, list) else self.targets.split()
        for target in targets:
            if self.is_domain(target):
                print_status(f"[~] Running passive recon on {target}...", "info")
                passive_results[target] = self.passive_recon(target)
        return passive_results
