from modules.plugins import ScanPlugin
from util import print_status
import socket

class SSHScan(ScanPlugin):
    name = "ssh_scan"

    def should_run(self, host, port, port_data):
        return port == 22 and port_data.get("service") == "ssh"

    def run(self, host, port, port_data):
        print_status(f"Plugin - Running {self.name} against {host}:{port}...", "scan")
        try:
            with socket.create_connection((host, port), timeout=2) as s:
                banner = s.recv(1024).decode("utf-8", "ignore").strip()
                print_status(f"[SSHScan] Banner received: {banner}", "success")
                return banner
        except Exception as e:
            print_status(f"[SSHScan] Error: {e}", "warning")
            return "No banner retrieved"
