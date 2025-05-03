#!/usr/bin/env python3
from modules.preflight import PreFlight
from modules.raven import Raven
from modules.owl import Owl
from utils.common import *
import os
import sys
import atexit
import argparse

version = "0.6.3"

# Global variables for custom settings and scan results
SCAN_RESULTS = {}  # Dictionary to store scan results per mode
PROJECT_FOLDER = ""  # Set in main()

def flock():
    print_banner("Flock-It: Integrated Pentest Framework")

    parser = argparse.ArgumentParser(description="Flock-It: Modular Penetration Testing Pre-Flight Framework")
    parser.add_argument("--settings", help="Path to an XML file for custom settings")
    parser.add_argument("--project", help="Project number")
    parser.add_argument("--ascii", action="store_true", help="Display ASCII network map at the end")
    parser.add_argument("--output", default="report.md", help="Output report file")
    parser.add_argument("--mode", choices=["quick", "full"], default="quick", help="Scan mode")

    # Auto flags
    parser.add_argument("--auto", action="store_true", help="Auto-accept all prompts (overrides others)")
    parser.add_argument("--auto-upload", action="store_true", help="Automatically upload to SMB")
    parser.add_argument("--auto-ai", action="store_true", help="Automatically run AI vulnerability analysis")
    parser.add_argument("--auto-view-report", action="store_true", help="Automatically open/view the report")
    parser.add_argument("--auto-plugin", action="store_true", help="Automatically generate plugins where plugins aren't found")

    args = parser.parse_args()

    # Configure automation options
    AUTO["general"] = args.auto
    AUTO["upload"] = args.auto or args.auto_upload
    AUTO["ai_analysis"] = args.auto or args.auto_ai
    AUTO["view_report"] = args.auto or args.auto_view_report
    AUTO["plugin"] = args.auto or args.auto_plugin
    AUTO["mode"] = args.auto

    # Load settings globally
    settings_path = args.settings if args.settings else "settings.xml"
    settings = load_settings_xml(settings_path)
    set_custom_settings(settings)

    # Step 1: Project setup
    project_number = args.project or input("Enter Project Number (default PR00000): ").strip() or "PR00000"
    pre = PreFlight(project_number)
    pre.setup()

    # Step 2: Reachability Checks
    print_banner("Preflight Reachability Checks")
    for mode, filename in [("int", "int_scope.txt"), ("ext", "ext_scope.txt"), ("web", "web_scope.txt")]:
        scope_path = os.path.join(pre.project_folder, filename)
        pre.run_checks(mode, scope_path)

    pre.print_summary()
    pre.write_xml_output()

    # Step 3: Active Recon and Scanning
    recon_targets = pre.get_recon_targets()
    if not recon_targets or not pre.prompt_recon():
        print_status("Recon skipped.", "warning")
        return

    report_path = os.path.join(pre.project_folder, args.output)
    raven = Raven(recon_targets, report_path, args.mode)
    live_hosts = raven.discover_hosts()
    if not live_hosts:
        print_status("No live hosts found. Skipping active scanning.", "warning")
        return

    raven.scan_network(live_hosts)

    # Step 4: Final filter on malformed results
    raven.results = {
        h: d for h, d in raven.results.items()
        if isinstance(d, dict) and "ports" in d
    }

    # Step 5: AI Vulnerability Analysis
    if raven.results and pre.prompt_ai():
        for host, info in raven.results.items():
            print_status(f"Analyzing {host} with AI...", "info")
            if not isinstance(info, dict):
                print_status(f"Skipping malformed host data for: {host}", "warning")
                continue

            summary = raven.analyse_vulnerabilities(info, hostname=host)
            if isinstance(summary, str) and summary.strip().startswith("##"):
                info["vulnerabilities_ai"] = summary.strip()
            else:
                info["vulnerabilities_ai"] = "⚠️ AI analysis failed or returned no summary."

    # Final filter to ensure only actual hosts remain in results
    raven.results = {
        host: info for host, info in raven.results.items()
        if isinstance(info, dict) and isinstance(host, str) and "ports" in info and isinstance(info["ports"], list)
    }

    # Step 6: Reporting
    print_banner("Reporting")
    owl = Owl(raven.targets, raven.results, os.path.join(pre.project_folder, args.output))
    print(owl.generate_report())

    # Optional ASCII network map
    if args.ascii:
        print_banner("ASCII Network Map")
        print_status(generate_ascii_visualisation(raven.results), "info")

    # Step 7: Optional SMB Upload
    if pre.prompt_smb_upload():
        pre.compress_and_upload()



    print("Done")
if __name__ == "__main__":
    flock()
