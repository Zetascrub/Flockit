import socket
import ssl
import tempfile
import warnings
from datetime import datetime, timezone
from fnmatch import fnmatch

from modules.plugins import ScanPlugin
from utils.common import print_status


TLS_PORTS = {443, 8009, 8443, 9443, 6238}
TLS_SERVICES = {"https", "https-alt", "ssl/http", "https-alt"}
SECURITY_HEADERS = {
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
}
TLS_VERSION_PROBES = [
    ("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)),
    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
]
WEAK_CIPHER_PROBES = {
    "3des": "DES-CBC3-SHA:@SECLEVEL=0",
    "cbc": "AES128-SHA:AES256-SHA:@SECLEVEL=0",
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


def _probe_tls_version(host, port, version):
    if version is None:
        return {"accepted": False, "error": "TLS version not supported by this Python/OpenSSL build"}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = version
    context.maximum_version = version
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            with socket.create_connection((host, port), timeout=4) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    cipher = tls.cipher()
                    return {
                        "accepted": True,
                        "version": tls.version() or "",
                        "cipher": " ".join(str(part) for part in cipher) if cipher else "",
                    }
    except Exception as e:
        return {"accepted": False, "error": str(e)}


def _probe_cipher(host, port, cipher_string):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1
    try:
        context.set_ciphers(cipher_string)
    except ssl.SSLError as e:
        return {"accepted": False, "error": str(e)}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            with socket.create_connection((host, port), timeout=4) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    cipher = tls.cipher()
                    return {
                        "accepted": True,
                        "version": tls.version() or "",
                        "cipher": " ".join(str(part) for part in cipher) if cipher else "",
                    }
    except Exception as e:
        return {"accepted": False, "error": str(e)}


def _cert_names(decoded_cert):
    names = []
    for cert_type, value in decoded_cert.get("subjectAltName", ()):
        if cert_type.lower() == "dns":
            names.append(value)
    for subject_part in decoded_cert.get("subject", ()):
        for key, value in subject_part:
            if key == "commonName":
                names.append(value)
    return names


def _hostname_matches(host, names):
    host = host.lower()
    return any(fnmatch(host, name.lower()) for name in names)


def _decode_peer_certificate(der_cert, host):
    if not der_cert:
        return {}, ["certificate_not_present"]

    pem = ssl.DER_cert_to_PEM_cert(der_cert)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=True) as f:
        f.write(pem)
        f.flush()
        decoded = ssl._ssl._test_decode_cert(f.name)

    warnings_found = []
    subject = decoded.get("subject")
    issuer = decoded.get("issuer")
    names = _cert_names(decoded)
    not_after = decoded.get("notAfter", "")
    days_until_expiry = None
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_until_expiry = (expiry - datetime.now(timezone.utc)).days
            if days_until_expiry < 0:
                warnings_found.append("certificate_expired")
            elif days_until_expiry <= 30:
                warnings_found.append("certificate_expires_soon")
        except ValueError:
            warnings_found.append("certificate_expiry_unparsed")

    if subject and issuer and subject == issuer:
        warnings_found.append("self_signed_certificate")
    if names and not _hostname_matches(host, names):
        warnings_found.append("hostname_mismatch")

    return {
        "subject": str(subject or ""),
        "issuer": str(issuer or ""),
        "names": names,
        "not_after": not_after,
        "days_until_expiry": days_until_expiry,
    }, warnings_found


def _verify_certificate(host, port):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=4) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                return {"trusted": True}
    except ssl.SSLCertVerificationError as e:
        return {"trusted": False, "error": str(e), "verify_code": e.verify_code, "verify_message": e.verify_message}
    except Exception as e:
        return {"trusted": None, "error": str(e)}


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
            "legacy_protocols": {},
            "legacy_protocols_supported": [],
            "weak_cipher_probes": {},
            "weak_ciphers_supported": [],
            "certificate": {},
            "certificate_warnings": [],
            "certificate_trust": {},
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
                    der_cert = tls.getpeercert(binary_form=True)
                    result["certificate_present"] = bool(der_cert)
                    result["certificate"], result["certificate_warnings"] = _decode_peer_certificate(der_cert, host)

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

            for label, version in TLS_VERSION_PROBES:
                probe = _probe_tls_version(host, port, version)
                result["legacy_protocols"][label] = probe
                if probe.get("accepted"):
                    result["legacy_protocols_supported"].append(label)

            for label, cipher_string in WEAK_CIPHER_PROBES.items():
                probe = _probe_cipher(host, port, cipher_string)
                result["weak_cipher_probes"][label] = probe
                if probe.get("accepted"):
                    result["weak_ciphers_supported"].append(label)

            result["certificate_trust"] = _verify_certificate(host, port)
            if result["certificate_trust"].get("trusted") is False:
                result["certificate_warnings"].append("certificate_cannot_be_trusted")

            if result["legacy_protocols_supported"] or result["weak_ciphers_supported"] or result["certificate_warnings"]:
                result["escalate"] = True
                result["escalate_reason"] = "TLS weaknesses observed: " + ", ".join(
                    result["legacy_protocols_supported"] + result["weak_ciphers_supported"] + result["certificate_warnings"]
                )

            print_status(
                f"[TLSScan] {result['tls_version'] or 'unknown TLS'} {result['http_status_line'] or ''}".strip(),
                "info",
            )
        except Exception as e:
            print_status(f"[TLSScan] Error: {e}", "warning")
            result["error"] = str(e)

        return result
