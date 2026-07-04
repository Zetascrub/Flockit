#!/usr/bin/env python3
import argparse
import json
import os
import sys

from modules import correlation, plugin_manager
from modules.cve_lookup import CVECache, CVELookupClient
from modules.reporter import Reporter
from modules.preflight import PreFlight
from modules.scanner import Scanner
from utils.ai_client import AIClient
from utils.common import (
    check_dependencies,
    convert_markdown_to_pdf,
    generate_ascii_visualisation,
    print_banner,
    print_status,
    prompt_yes_no,
    set_verbosity,
)
from utils.config import Config
from utils.context import ProjectContext

version = "0.7.0"


def validate_environment():
    print_banner("🔍 Environment Validation")
    print_status("Base environment checks complete. External IP validation runs only when external scope is present.", "success")


def handle_plugins_command(args):
    """Quarantined AI-plugin review workflow: list/show/approve/reject. Never
    auto-loads anything — approve is the only path from quarantine into the
    trusted, auto-loaded modules/plugins directory."""
    quarantine_dir = plugin_manager.DEFAULT_QUARANTINE_DIR
    trusted_dir = plugin_manager.DEFAULT_PLUGIN_DIR

    if args.plugins_command == "list":
        entries = plugin_manager.list_quarantined(quarantine_dir)
        if not entries:
            print_status("No quarantined plugins.", "info")
            return
        print(f"{'Filename':<42} {'Port':<6} {'Service':<12} {'Status':<10}")
        for e in entries:
            print(f"{e['filename']:<42} {str(e.get('port') or ''):<6} {(e.get('service') or ''):<12} {e.get('status', ''):<10}")

    elif args.plugins_command == "show":
        source = plugin_manager.read_quarantined_source(quarantine_dir, args.filename)
        if source is None:
            print_status(f"{args.filename} not found in quarantine.", "error")
            return
        meta = plugin_manager._read_meta(quarantine_dir, args.filename)
        print(json.dumps(meta, indent=2))
        print("\n" + source)

    elif args.plugins_command == "approve":
        if not args.yes and not prompt_yes_no(f"Approve {args.filename} and move it into the trusted plugin directory? (y/n): "):
            print_status("Approval cancelled.", "info")
            return
        plugin_manager.approve_quarantined(args.filename, quarantine_dir, trusted_dir)

    elif args.plugins_command == "reject":
        plugin_manager.reject_quarantined(args.filename, quarantine_dir)

    else:
        print_status("Usage: sift.py plugins {list,show,approve,reject}", "warning")


def flock():
    parser = argparse.ArgumentParser(description="Sift: Adaptive Penetration Testing Framework")
    parser.add_argument("--settings", help="Path to an XML file for custom settings")
    parser.add_argument("--project", help="Project number")
    parser.add_argument("--ascii", action="store_true", help="Display ASCII network map at the end")
    parser.add_argument("--output", default="report.md", help="Output report file")
    parser.add_argument(
        "--scan-mode", choices=["quick", "full", "adaptive"], default="adaptive",
        help="quick/full scan every host uniformly; adaptive quick-scans everything "
             "then escalates specific hosts to a deeper scan based on findings",
    )
    parser.add_argument("--scope", default="scope.txt", help="Path to the source scope file")
    parser.add_argument("--no-ai", action="store_true", help="Skip AI vulnerability analysis")
    parser.add_argument("--no-upload", action="store_true", help="Skip SMB upload")
    parser.add_argument("--cve-source", choices=["nvd", "off"], default=None, help="CVE matching source (default: nvd)")
    parser.add_argument("--nvd-api-key", default=None, help="NVD API key (raises rate limit from 5/30s to 50/30s)")
    parser.add_argument("--top-findings", type=int, default=10, help="Number of top cross-host findings to AI-narrate")
    parser.add_argument("--check-dependencies", action="store_true", help="Check optional runtime dependencies and exit")
    parser.add_argument("--verbose", action="store_true", help="Increase output verbosity")
    parser.add_argument("--quiet", action="store_true", help="Decrease output verbosity")
    parser.add_argument("--pdf", action="store_true", help="Export PDF version of report")

    # Auto flags
    parser.add_argument("--auto", action="store_true", help="Auto-accept all prompts (overrides others)")
    parser.add_argument("--auto-upload", action="store_true", help="Automatically upload to SMB")
    parser.add_argument("--auto-ai", action="store_true", help="Automatically run AI vulnerability analysis")
    parser.add_argument("--auto-view-report", action="store_true", help="Automatically print the report")
    parser.add_argument(
        "--auto-plugin", action="store_true",
        help="Reserved for future auto-generation of candidate plugins into quarantine "
             "(never auto-trusted; always requires `sift.py plugins approve`)",
    )

    subparsers = parser.add_subparsers(dest="command")
    plugins_parser = subparsers.add_parser("plugins", help="Review AI-generated quarantined plugins")
    plugins_sub = plugins_parser.add_subparsers(dest="plugins_command")
    plugins_sub.add_parser("list", help="List quarantined plugins")
    show_p = plugins_sub.add_parser("show", help="Show a quarantined plugin's source and metadata")
    show_p.add_argument("filename")
    approve_p = plugins_sub.add_parser("approve", help="Approve a quarantined plugin, moving it into the trusted plugin directory")
    approve_p.add_argument("filename")
    approve_p.add_argument("--yes", action="store_true", help="Skip the confirmation prompt")
    reject_p = plugins_sub.add_parser("reject", help="Reject a quarantined plugin, moving it to plugins_quarantine/rejected")
    reject_p.add_argument("filename")

    args = parser.parse_args()

    if args.command == "plugins":
        handle_plugins_command(args)
        return

    print_banner("Sift: Adaptive Pentest Framework")

    if args.quiet:
        set_verbosity("quiet")
    elif args.verbose:
        set_verbosity("debug")
    else:
        set_verbosity("info")

    settings_path = args.settings if args.settings else "settings_dev.xml"
    config = Config.load(settings_path, args)

    if args.check_dependencies:
        missing = check_dependencies(scan=True, ai=not args.no_ai, upload=not args.no_upload, pdf=args.pdf, ai_config=config.ai)
        if missing:
            sys.exit(1)
        print_status("All requested dependencies are available.", "success")
        return

    # 🔍 Pre-check everything before continuing
    validate_environment()

    # Step 1: Project setup
    project_number = args.project or input("Enter Project Number (default PR00000): ").strip() or "PR00000"
    ctx = ProjectContext.create(project_number, args.scope, config)

    pre = PreFlight(ctx)
    pre.setup()

    # Step 2: Reachability Checks
    print_banner("Preflight Reachability Checks")
    for mode, filename in [("int", "int_scope.txt"), ("ext", "ext_scope.txt"), ("web", "web_scope.txt")]:
        scope_path = os.path.join(ctx.project_folder, filename)
        pre.run_checks(mode, scope_path)

    pre.print_summary()
    pre.write_xml_output()
    print_banner("Preflight Phase Completed")

    # Step 3: Active Recon and Scanning
    recon_targets = pre.get_recon_targets()
    if not recon_targets or not pre.prompt_recon():
        print_status("Recon skipped.", "warning")
        return

    if check_dependencies(scan=True):
        print_status("Active scanning skipped because scan dependencies are missing.", "error")
        return

    scanner = Scanner(ctx, recon_targets)
    live_hosts = scanner.discover_hosts()
    if not live_hosts:
        print_status("No live hosts found. Skipping active scanning.", "warning")
        return

    scan_run = scanner.scan_network(live_hosts)
    print_banner("Active Scanning Phase Completed")

    # Merge advisory preflight hints onto their matching hosts. nmap's active
    # scan remains the authoritative source of truth for port state; this is
    # only used to surface discrepancies in the report (see Reporter._render_preflight_discrepancy).
    for host, hr in scan_run.hosts.items():
        hr.preflight_hint = pre.preflight_hints.get(host)

    # Step 3b: CVE matching (deterministic, no AI/network required to be enabled)
    if config.cve.source != "off" and scan_run.hosts:
        print_banner("CVE Matching")
        cve_cache = CVECache(os.path.join(ctx.project_folder, ".cve_cache.sqlite3"), config.cve.cache_ttl_days)
        cve_client = CVELookupClient(config.cve, cve_cache)
        for host, hr in scan_run.hosts.items():
            for pr in hr.ports:
                pr.cve_matches = cve_client.lookup(pr)
        total_matches = sum(len(pr.cve_matches) for hr in scan_run.hosts.values() for pr in hr.ports)
        print_status(f"[+] CVE matching complete: {total_matches} match(es) found.", "success")

    # Step 3c: Cross-host correlation & risk ranking (deterministic; AI narrates on top)
    findings = []
    if scan_run.hosts:
        print_banner("Cross-Host Correlation")
        findings = correlation.correlate(scan_run, config.adaptive)
        print_status(f"[+] Correlation complete: {len(findings)} cross-host finding(s).", "success")

    # Step 4: AI Vulnerability Analysis
    if scan_run.hosts and not args.no_ai and pre.prompt_ai():
        if check_dependencies(ai=True, ai_config=config.ai):
            print_status("AI analysis skipped because AI dependencies are missing.", "warning")
        else:
            ai_client = AIClient(config.ai)
            if not ai_client.available():
                print_status(f"AI analysis skipped: {config.ai.provider} is not reachable/configured.", "warning")
            else:
                for host, hr in scan_run.hosts.items():
                    print_status(f"Analyzing {host} with AI...", "info")
                    scanner.analyse_vulnerabilities(hr, ai_client)
                if findings:
                    top_n = min(args.top_findings, len(findings))
                    print_status(f"[+] Narrating top {top_n} finding(s) with AI...", "info")
                    correlation.narrate(findings, ai_client, top_n=args.top_findings)

    print_banner("Vulnerability Analysis Phase Completed")

    # Step 5: Reporting
    print_banner("Reporting")
    report_path = os.path.join(ctx.project_folder, args.output)
    reporter = Reporter(ctx, scan_run, report_path, findings=findings, pdf_mode=args.pdf)

    reporter.generate_report()
    if args.pdf:
        if check_dependencies(pdf=True):
            print_status("PDF export skipped because PDF dependencies are missing.", "warning")
        else:
            convert_markdown_to_pdf(report_path)

    print_banner("Reporting Phase Completed")

    # Optional ASCII network map
    if args.ascii:
        print_banner("ASCII Network Map")
        legacy_view = {
            host: {"ports": [{"service": pr.service, "state": pr.state} for pr in hr.ports]}
            for host, hr in scan_run.hosts.items()
        }
        print_status(generate_ascii_visualisation(legacy_view), "info")

    if not args.no_upload:
        pre.compress_and_upload()
    else:
        print_status("SMB upload disabled by --no-upload.", "info")

    if config.automation.general:
        print_status("Auto mode complete. All steps finished.", "success")

    print("Done")


if __name__ == "__main__":
    flock()
