from modules.plugins import ScanPlugin
from utils.common import print_status
from impacket.smbconnection import SMBConnection

class SMBScan(ScanPlugin):
    name = "smb_scan"

    def should_run(self, host, port, port_data):
        return port == 445 and port_data.get("service") in ("microsoft-ds", "smb")

    def run(self, host, port, port_data):
        print_status(f"Plugin - Running {self.name} against {host}:{port}...", "scan")
        try:
            conn = SMBConnection(host, host)
            conn.login("", "")  # Anonymous
            shares = conn.listShares()
            share_names = [s.getName() for s in shares]
            print_status(f"[SMBScan] Shares found: {share_names}", "success")
            conn.logoff()
            return "Shares: " + ", ".join(share_names)
        except Exception as e:
            print_status(f"[SMBScan] Error: {e}", "warning")
            return "Could not list shares"
