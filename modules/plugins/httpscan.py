from modules.plugins import ScanPlugin
import socket
from utils.common import print_status 

import socket

class HTTPScanPlugin(ScanPlugin):
    name = "http_scan"

    def should_run(self, host, port, port_data):
        return port in [80, 8080]

    def run(self, host, port, port_data):
        try:
            print_status(f"Plugin - Running {self.name} against {host}:{port}...", "scan")
            with socket.create_connection((host, port), timeout=3) as s:
                request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                s.sendall(request.encode("utf-8"))
                response = s.recv(1024).decode("utf-8", "ignore")
                first_line = response.split("\n")[0].strip()
                print_status(f"HTTP Response: {first_line}", "success")
                return first_line
        except Exception as e:
            print_status(f"Error during HTTP scan on {host}:{port}: {e}", "warning")
            return f"Error: {e}"
