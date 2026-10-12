from modules.plugins import ScanPlugin
from utils.common import print_status


class SMBScan(ScanPlugin):
    name = "smb_scan"

    def should_run(self, host, port, port_data):
        return port == 445 and port_data.get("service") in ("microsoft-ds", "smb", "")

    def run(self, host, port, port_data):
        print_status(f"Plugin - Running {self.name} against {host}:{port}...", "scan")
        result = {"null_session": False, "shares": [], "smb_signing_required": None}
        conn = None
        try:
            from impacket.smbconnection import SMBConnection

            conn = SMBConnection(host, host, timeout=5)
            try:
                result["smb_signing_required"] = bool(conn.isSigningRequired())
                if result["smb_signing_required"] is False:
                    result["smb_signing_not_required"] = True
                    result["escalate"] = True
                    result["escalate_weight"] = 2
                    result["escalate_reason"] = f"SMB signing is not required on {host}:{port}"
            except Exception as e:
                result["smb_signing_error"] = str(e)

            conn.login("", "")  # anonymous / null session
            shares = [s.getName() for s in conn.listShares()]
            result["shares"] = shares
            result["null_session"] = True
            result["anonymous_login"] = True
            result["banner"] = "Shares: " + (", ".join(shares) if shares else "(none)")
            result["escalate"] = True
            result["escalate_weight"] = 3
            result["escalate_reason"] = f"anonymous SMB session allowed on {host}:{port} ({len(shares)} share(s) visible)"
            print_status(f"[SMBScan] Null session allowed, shares: {shares}", "success")
        except Exception as e:
            print_status(f"[SMBScan] Error: {e}", "warning")
            result["error"] = str(e)
        finally:
            if conn:
                try:
                    conn.logoff()
                except Exception:
                    pass
        return result
