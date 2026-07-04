import socket

from modules.plugins import ScanPlugin
from utils.common import print_status

HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 8888}
HTTP_SERVICES = {"http", "http-proxy", "http-alt"}


class HTTPScan(ScanPlugin):
    name = "http_scan"

    def should_run(self, host, port, port_data):
        return port in HTTP_PORTS or port_data.get("service") in HTTP_SERVICES

    def run(self, host, port, port_data):
        print_status(f"Plugin - Running {self.name} against {host}:{port}...", "scan")
        result = {}
        try:
            with socket.create_connection((host, port), timeout=3) as s:
                request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Sift\r\nConnection: close\r\n\r\n"
                s.sendall(request.encode("utf-8"))
                response = b""
                while len(response) < 8192:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk

            text = response.decode("utf-8", "ignore")
            lines = text.split("\r\n")
            status_line = lines[0].strip() if lines else ""
            headers = {}
            for line in lines[1:]:
                if not line:
                    break
                if ":" in line:
                    key, _, value = line.partition(":")
                    headers[key.strip().lower()] = value.strip()

            result["banner"] = status_line
            result["status_line"] = status_line
            result["server"] = headers.get("server", "")
            print_status(f"[HTTPScan] {status_line} (Server: {result['server'] or 'unknown'})", "success")
        except Exception as e:
            print_status(f"[HTTPScan] Error: {e}", "warning")
            result["error"] = str(e)
        return result
