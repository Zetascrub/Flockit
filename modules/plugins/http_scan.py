from modules.plugins import ScanPlugin
from utils.common import print_status
import socket

class HttpScan(ScanPlugin):
    """Simple HTTP banner grabber."""
    name = "http_scan"
    description = "Retrieve HTTP response status line"

    def should_run(self, host, port, port_data):
        return port in (80, 8080) or port_data.get("service") == "http"

    def run(self, host, port, port_data):
        try:
            with socket.create_connection((host, port), timeout=3) as s:
                request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                s.sendall(request.encode("utf-8"))
                response = s.recv(1024).decode("utf-8", "ignore")
                first_line = response.splitlines()[0] if response else ""
                print_status(f"[HTTPScan] {first_line}", "info")
                return {"banner": first_line}
        except Exception as e:
            print_status(f"[HTTPScan] Error: {e}", "warning")
            return {"error": str(e)}
