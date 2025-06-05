from modules.plugins import ScanPlugin
from utils.common import print_status
import socket

class SshScan(ScanPlugin):
    """Collect SSH banner."""
    name = "ssh_scan"
    description = "Retrieve SSH server banner"

    def should_run(self, host, port, port_data):
        return port == 22 or port_data.get("service") == "ssh"

    def run(self, host, port, port_data):
        try:
            with socket.create_connection((host, port), timeout=3) as s:
                banner = s.recv(1024).decode("utf-8", "ignore").strip()
                print_status(f"[SSHScan] {banner}", "info")
                return {"banner": banner}
        except Exception as e:
            print_status(f"[SSHScan] Error: {e}", "warning")
            return {"error": str(e)}
