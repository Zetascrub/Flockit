import socket
import ssl

from modules.plugins import ScanPlugin
from utils.common import print_status


TLS_PORTS = {443, 8443, 9443}
TLS_SERVICES = {"https", "https-alt", "ssl/http", "https-alt"}
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


class TLSScan(ScanPlugin):
    name = "tls_scan"
    description = "Collects safe TLS/HTTPS handshake and certificate evidence."

    def should_run(self, host, port, port_data):
        service = (port_data.get("service") or "").lower()
        return port in TLS_PORTS or service in TLS_SERVICES

    def run(self, host, port, port_data):
        print_status(f"Plugin - Running {self.name} against {host}:{port}...", "scan")
        result = {
            "handshake": False,
            "tls_version": "",
            "cipher": "",
            "certificate_present": False,
            "http_status_line": "",
            "server": "",
            "location": "",
            "security_headers": {},
            "missing_security_headers": [],
        }

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    result["handshake"] = True
                    result["tls_version"] = tls.version() or ""
                    cipher = tls.cipher()
                    result["cipher"] = " ".join(str(part) for part in cipher) if cipher else ""
                    result["certificate_present"] = bool(tls.getpeercert(binary_form=True))

                    request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Sift\r\nConnection: close\r\n\r\n"
                    tls.sendall(request.encode("utf-8"))
                    response = tls.recv(4096).decode("utf-8", "ignore")

            lines = response.split("\r\n")
            result["http_status_line"] = lines[0].strip() if lines else ""
            headers = _parse_headers(lines[1:])
            result["server"] = headers.get("server", "")
            result["location"] = headers.get("location", "")
            result["security_headers"] = {name: headers.get(name, "") for name in sorted(SECURITY_HEADERS)}
            result["missing_security_headers"] = [
                name for name in sorted(SECURITY_HEADERS) if not headers.get(name)
            ]

            if result["tls_version"] in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}:
                result["escalate"] = True
                result["escalate_reason"] = f"legacy TLS protocol accepted on {host}:{port}: {result['tls_version']}"

            print_status(
                f"[TLSScan] {result['tls_version'] or 'unknown TLS'} {result['http_status_line'] or ''}".strip(),
                "info",
            )
        except Exception as e:
            print_status(f"[TLSScan] Error: {e}", "warning")
            result["error"] = str(e)

        return result
