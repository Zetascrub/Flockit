import socket

from modules.plugins import ScanPlugin
from utils.common import print_status


class FTPScan(ScanPlugin):
    name = "ftp_scan"

    def should_run(self, host, port, port_data):
        return port == 21 or port_data.get("service") == "ftp"

    def run(self, host, port, port_data):
        print_status(f"Plugin - Running {self.name} against {host}:{port}...", "scan")
        result = {"anonymous_login": False}
        try:
            with socket.create_connection((host, port), timeout=3) as s:
                banner = s.recv(1024).decode("utf-8", "ignore").strip()
                result["banner"] = banner

                s.sendall(b"USER anonymous\r\n")
                user_resp = s.recv(1024).decode("utf-8", "ignore").strip()
                if user_resp.startswith(("331", "230")):
                    s.sendall(b"PASS anonymous@\r\n")
                    pass_resp = s.recv(1024).decode("utf-8", "ignore").strip()
                    if pass_resp.startswith("230"):
                        result["anonymous_login"] = True
                        result["escalate"] = True
                        result["escalate_reason"] = f"anonymous FTP login allowed on {host}:{port}"

            if result["anonymous_login"]:
                print_status(f"[FTPScan] Anonymous login allowed on {host}:{port}", "success")
            else:
                print_status(f"[FTPScan] Banner: {result.get('banner') or 'none'}", "info")
        except Exception as e:
            print_status(f"[FTPScan] Error: {e}", "warning")
            result["error"] = str(e)
        return result
