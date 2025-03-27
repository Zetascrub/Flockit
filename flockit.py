#!/usr/bin/env python3
from modules.preflight import PreFlight
from modules.raven import Raven
from modules.owl import Owl
from utils.common import *

import os
import sys
import termios
import atexit
import argparse
 

version = "0.6.3"

# Global variables for custom settings and scan results
CUSTOM_SETTINGS = load_settings_xml()


SCAN_RESULTS = {}  # Dictionary to store scan results per mode
PROJECT_FOLDER = ""  # Set in main()

def flock():
    print_banner("Flock-It: Integrated Pentest Framework")

    global AUTO_MODE
    
    parser = argparse.ArgumentParser(description="Flock-It: Modular Penetration Testing Pre-Flight Framework")
    parser.add_argument("--settings", help="Path to an XML file for custom settings")
    parser.add_argument("--project", help="Project number")
    parser.add_argument("--ascii", action="store_true", help="Display ASCII network map at the end")
    parser.add_argument("--output", default="report.md", help="Output report file")
    parser.add_argument("--mode", choices=["quick", "full"], default="quick", help="Scan mode")
    parser.add_argument("--auto", action="store_true", help="Auto-accept all prompts")
    args = parser.parse_args()

    AUTO_MODE = args.auto

    # Terminal restore safeguard
    fd = sys.stdin.fileno()
    original_term_settings = termios.tcgetattr(fd)
    atexit.register(restore_terminal_settings, fd, original_term_settings)

    # Project setup
    project_number = args.project or input("Enter Project Number (default PR00000): ").strip() or "PR00000"
    settings_path = args.settings if args.settings else "settings.xml"

    settings = load_settings_xml(settings_path)
    pre = PreFlight(project_number)
    pre.setup()

    # SMB optional upload
    if pre.prompt_smb_upload():
        pre.compress_and_upload()

    # Active Recon
    recon_targets = pre.get_recon_targets()
    if recon_targets and pre.prompt_recon():
        raven = Raven(recon_targets, args.output, args.mode)
        live_hosts = raven.discover_hosts()
        if live_hosts:
            raven.scan_network(live_hosts)
        else:
            print_status("No live hosts found. Skipping active scanning.", "warning")
    else:
        print_status("Recon skipped.", "warning")
        return

    # Vulnerability Analysis
    if raven.results and pre.prompt_ai():
        for host, info in raven.results.items():
            print_status(f"Analyzing {host} with AI...", "info")
            info["vulnerabilities_ai"] = raven.analyse_vulnerabilities(info)

    # Reporting
    owl = Owl(raven.targets, raven.results, os.path.join(pre.project_folder, args.output))
    owl.generate_report()

    # Optional ASCII
    if args.ascii:
        print_banner("ASCII Network Map")
        print_status(generate_ascii_visualisation(raven.results), "info")


if __name__ == "__main__":
    flock()
