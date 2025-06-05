from modules.plugins import ScanPlugin
from utils.common import print_status
import socket

class FtpScan(ScanPlugin):
    """Grab banner from FTP service."""
    name = "ftp_scan"
    description = "Enumerate FTP banner"

    def should_run(self, host, port, port_data):
        return port == 21 or port_data.get("service") == "ftp"

    def run(self, host, port, port_data):
        try:
            with socket.create_connection((host, port), timeout=3) as s:
                banner = s.recv(1024).decode("utf-8", "ignore").strip()
                s.sendall(b"QUIT\r\n")
                print_status(f"[FTPScan] {banner}", "info")
                return {"banner": banner}
        except Exception as e:
            print_status(f"[FTPScan] Error: {e}", "warning")
            return {"error": str(e)}
