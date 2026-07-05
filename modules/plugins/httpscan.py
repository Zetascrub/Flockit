import socket
import re

from modules.plugins import ScanPlugin
from utils.common import print_status

HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 8888}
HTTP_SERVICES = {"http", "http-proxy", "http-alt"}
SECURITY_HEADERS = {
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
}


def _parse_headers(lines):
    headers = {}
    for line in lines:
        if not line:
            break
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    return headers


def _extract_title(body):
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:120]


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
            header_text, _, body = text.partition("\r\n\r\n")
            lines = header_text.split("\r\n")
            status_line = lines[0].strip() if lines else ""
            headers = _parse_headers(lines[1:])

            result["banner"] = status_line
            result["status_line"] = status_line
            result["server"] = headers.get("server", "")
            result["location"] = headers.get("location", "")
            result["title"] = _extract_title(body)
            result["security_headers"] = {name: headers.get(name, "") for name in sorted(SECURITY_HEADERS)}
            result["missing_security_headers"] = [
                name for name in sorted(SECURITY_HEADERS) if not headers.get(name)
            ]
            print_status(f"[HTTPScan] {status_line} (Server: {result['server'] or 'unknown'})", "success")
        except Exception as e:
            print_status(f"[HTTPScan] Error: {e}", "warning")
            result["error"] = str(e)
        return result
