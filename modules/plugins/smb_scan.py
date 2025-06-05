from modules.plugins import ScanPlugin
from utils.common import print_status
from impacket.smbconnection import SMBConnection

class SmbScan(ScanPlugin):
    """Enumerate SMB shares anonymously."""
    name = "smb_scan"
    description = "List SMB shares via anonymous login"

    def should_run(self, host, port, port_data):
        return port == 445 or port_data.get("service") in ("microsoft-ds", "smb")

    def run(self, host, port, port_data):
        try:
            conn = SMBConnection(host, host)
            conn.login("", "")
            shares = conn.listShares()
            share_names = [s.getName() for s in shares]
            conn.logoff()
            print_status(f"[SMBScan] Shares: {', '.join(share_names)}", "info")
            return {"shares": share_names}
        except Exception as e:
            print_status(f"[SMBScan] Error: {e}", "warning")
            return {"error": str(e)}
