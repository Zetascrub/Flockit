#!/usr/bin/env python3
from modules.preflight import PreFlight
from modules.raven import Raven
from modules.owl import Owl
from utils.common import *

import os
import sys
import atexit
import argparse

version = "0.6.4"

# Global variables for custom settings and scan results
SCAN_RESULTS = {}  # Dictionary to store scan results per mode
PROJECT_FOLDER = ""  # Set in main()

def validate_environment():
    print_banner("🔍 Environment Validation")

    # Ollama check
    if CUSTOM_SETTINGS.get("default_ai_provider") == "ollama":
        if not check_ollama():
            print_status("❌ Ollama is not running or reachable. Please start the Ollama server.", "error")
            sys.exit(1)

    # OpenAI API Key check
    if CUSTOM_SETTINGS.get("default_ai_provider") == "openai":
        api_key = CUSTOM_SETTINGS.get("openai_api_key", "")
        if not api_key or "your-api-key" in api_key:
            print_status("❌ OpenAI API key is missing or invalid in settings.xml.", "error")
            sys.exit(1)

    # VPN / External IP range check
    external_ip = requests.get(CUSTOM_SETTINGS["external_ip_url"]).text.strip()
    valid_ranges = CUSTOM_SETTINGS.get("valid_external_ranges", [])
    ip_obj = ipaddress.ip_address(external_ip)

    if not any(ip_obj in ipaddress.ip_network(net) for net in valid_ranges):
        print_status(f"⚠️ External IP {external_ip} is not within valid ranges.", "warning")
        if not prompt_yes_no("Continue anyway?", AUTO["mode"]):
            sys.exit("Aborting due to invalid VPN connection.")

    print_status("✅ Environment looks good.", "success")


def flock():
    print_banner("Flock-It: Integrated Pentest Framework")

    parser = argparse.ArgumentParser(description="Flock-It: Modular Penetration Testing Pre-Flight Framework")
    parser.add_argument("--settings", help="Path to an XML file for custom settings")
    parser.add_argument("--project", help="Project number")
    parser.add_argument("--ascii", action="store_true", help="Display ASCII network map at the end")
    parser.add_argument("--output", default="report.md", help="Output report file")
    parser.add_argument("--mode", choices=["quick", "full"], default="quick", help="Scan mode")
    parser.add_argument("--verbose", action="store_true", help="Increase output verbosity")
    parser.add_argument("--quiet", action="store_true", help="Decrease output verbosity")
    parser.add_argument("--pdf", action="store_true", help="Export PDF version of report")


    # Auto flags
    parser.add_argument("--auto", action="store_true", help="Auto-accept all prompts (overrides others)")
    parser.add_argument("--auto-upload", action="store_true", help="Automatically upload to SMB")
    parser.add_argument("--auto-ai", action="store_true", help="Automatically run AI vulnerability analysis")
    parser.add_argument("--auto-view-report", action="store_true", help="Automatically open/view the report")
    parser.add_argument("--auto-plugin", action="store_true", help="Automatically generate plugins where plugins aren't found")

    args = parser.parse_args()

    if args.quiet:
        set_verbosity("quiet")
    elif args.verbose:
        set_verbosity("debug")
    else:
        set_verbosity("info")

    # Configure automation options
    AUTO["general"] = args.auto
    AUTO["upload"] = args.auto or args.auto_upload
    AUTO["ai_analysis"] = args.auto or args.auto_ai
    AUTO["view_report"] = args.auto or args.auto_view_report
    AUTO["plugin"] = args.auto or args.auto_plugin
    AUTO["mode"] = args.auto
    CUSTOM_SETTINGS["auto_mode"] = AUTO["mode"]


    # Load settings globally
    settings_path = args.settings if args.settings else "settings_dev.xml"
    settings = load_settings_xml(settings_path)
    set_custom_settings(settings)

    # 🔍 Pre-check everything before continuing
    validate_environment()

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
    print_banner("Preflight Phase Completed")

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
    print_banner("Active Scanning Phase Completed")

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

            raven.analyse_vulnerabilities(info, hostname=host)


    # Final filter to ensure only actual hosts remain in results
    raven.results = {
        host: info for host, info in raven.results.items()
        if isinstance(info, dict) and isinstance(host, str) and "ports" in info and isinstance(info["ports"], list)
    }

    print_banner("Vulnerability Analysis Phase Completed")

    # Step 6: Reporting
    print_banner("Reporting")
    report_path = os.path.join(pre.project_folder, args.output)
    #owl = Owl(raven.targets, raven.results, os.path.join(pre.project_folder, args.output))
    owl = Owl(raven.targets, raven.results, report_path, pdf_mode=args.pdf)

    print(owl.generate_report())
    if args.pdf:
        md_path = os.path.join(pre.project_folder, args.output)
        convert_markdown_to_pdf(md_path)

    print_banner("Reporting Phase Completed")

    # Optional ASCII network map
    if args.ascii:
        print_banner("ASCII Network Map")
        print_status(generate_ascii_visualisation(raven.results), "info")

    # Step 7: Optional SMB Upload
    if not CUSTOM_SETTINGS.get("auto_mode"):
        print_banner("SMB Upload")

    pre.compress_and_upload()

    if CUSTOM_SETTINGS.get("auto_mode"):
        print_status("Auto mode complete. All steps finished.", "success")



    print("Done")
if __name__ == "__main__":
    flock()
