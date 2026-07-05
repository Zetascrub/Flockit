import re
import socket

from modules.plugins import ScanPlugin
from utils.common import print_status

OLD_VERSION_PATTERN = re.compile(r"OpenSSH_[0-6]\.|OpenSSH_7\.[0-3]\b|dropbear", re.IGNORECASE)


class SSHScan(ScanPlugin):
    name = "ssh_scan"

    def should_run(self, host, port, port_data):
        return port == 22 or port_data.get("service") == "ssh"

    def run(self, host, port, port_data):
        print_status(f"Plugin - Running {self.name} against {host}:{port}...", "scan")
        result = {}
        try:
            with socket.create_connection((host, port), timeout=3) as s:
                raw = s.recv(1024).decode("utf-8", "ignore")
                # The identification string (RFC 4253 §4.2) is a single CR-LF-terminated
                # line; recv() often also picks up the start of the binary KEXINIT packet
                # that follows immediately after, so only keep the first line as the banner.
                banner = raw.split("\n", 1)[0].strip()
            result["banner"] = banner
            print_status(f"[SSHScan] Banner: {banner or 'none'}", "success")
            if banner and OLD_VERSION_PATTERN.search(banner):
                result["escalate"] = True
                result["escalate_reason"] = f"outdated/weak SSH implementation on {host}:{port}: {banner}"
        except Exception as e:
            print_status(f"[SSHScan] Error: {e}", "warning")
            result["error"] = str(e)
        return result
