from modules.plugins import ScanPlugin
from util import print_status
import socket

class FTPScan(ScanPlugin):
    name = "ftp_scan"

    def should_run(self, host, port, port_data):
        return port == 21 and port_data.get("service") == "ftp"

    def run(self, host, port, port_data):
        print_status(f"Plugin - Running {self.name} against {host}:{port}...", "scan")
        try:
            with socket.create_connection((host, port), timeout=2) as s:
                banner = s.recv(1024).decode("utf-8", "ignore").strip()
                print_status(f"[FTPScan] Banner received: {banner}", "success")
                return banner
        except Exception as e:
            print_status(f"[FTPScan] Error: {e}", "warning")
            return "No banner retrieved"
