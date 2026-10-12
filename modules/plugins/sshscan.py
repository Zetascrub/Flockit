import re
import socket
import struct

from modules.plugins import ScanPlugin
from utils.common import print_status

OLD_VERSION_PATTERN = re.compile(r"OpenSSH_[0-6]\.|OpenSSH_7\.[0-3]\b|dropbear", re.IGNORECASE)
WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}
WEAK_HOST_KEYS = {"ssh-rsa", "ssh-dss"}
WEAK_CIPHERS = {"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc"}
WEAK_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96"}
KEXINIT_FIELDS = [
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
]


def _read_ssh_banner(sock):
    data = b""
    while b"\n" not in data and len(data) < 4096:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    line, _, rest = data.partition(b"\n")
    return line.decode("utf-8", "ignore").strip(), rest


def _read_kexinit_packet(sock, buffered=b""):
    data = buffered
    while len(data) < 5:
        data += sock.recv(4096)
    packet_length = struct.unpack("!I", data[:4])[0]
    total_length = 4 + packet_length
    while len(data) < total_length:
        data += sock.recv(total_length - len(data))
    padding_length = data[4]
    payload = data[5:total_length - padding_length]
    if not payload or payload[0] != 20:
        raise ValueError("server did not send SSH_MSG_KEXINIT")
    return payload


def _parse_namelist(payload, offset):
    length = struct.unpack("!I", payload[offset:offset + 4])[0]
    offset += 4
    value = payload[offset:offset + length].decode("ascii", "ignore")
    offset += length
    return [item for item in value.split(",") if item], offset


def _parse_kexinit(payload):
    # byte message-code + 16-byte cookie, then ten SSH name-list fields.
    offset = 17
    parsed = {}
    for field in KEXINIT_FIELDS:
        parsed[field], offset = _parse_namelist(payload, offset)
    return parsed


def _weak_algorithms(algorithms):
    weak = {}
    kex = sorted(set(algorithms.get("kex_algorithms", [])) & WEAK_KEX)
    host_keys = sorted(set(algorithms.get("server_host_key_algorithms", [])) & WEAK_HOST_KEYS)
    ciphers = sorted(
        (set(algorithms.get("encryption_algorithms_client_to_server", [])) |
         set(algorithms.get("encryption_algorithms_server_to_client", []))) & WEAK_CIPHERS
    )
    macs = sorted(
        (set(algorithms.get("mac_algorithms_client_to_server", [])) |
         set(algorithms.get("mac_algorithms_server_to_client", []))) & WEAK_MACS
    )
    if kex:
        weak["kex"] = kex
    if host_keys:
        weak["host_keys"] = host_keys
    if ciphers:
        weak["ciphers"] = ciphers
    if macs:
        weak["macs"] = macs
    return weak


class SSHScan(ScanPlugin):
    name = "ssh_scan"

    def should_run(self, host, port, port_data):
        return port == 22 or port_data.get("service") == "ssh"

    def run(self, host, port, port_data):
        print_status(f"Plugin - Running {self.name} against {host}:{port}...", "scan")
        result = {}
        try:
            with socket.create_connection((host, port), timeout=3) as s:
                banner, buffered = _read_ssh_banner(s)
                s.sendall(b"SSH-2.0-Sift\r\n")
                try:
                    algorithms = _parse_kexinit(_read_kexinit_packet(s, buffered))
                    result["algorithms"] = algorithms
                    result["weak_algorithms"] = _weak_algorithms(algorithms)
                except Exception as e:
                    result["algorithm_error"] = str(e)
            result["banner"] = banner
            print_status(f"[SSHScan] Banner: {banner or 'none'}", "success")
            if banner and OLD_VERSION_PATTERN.search(banner):
                result["escalate"] = True
                result["escalate_reason"] = f"outdated/weak SSH implementation on {host}:{port}: {banner}"
            if result.get("weak_algorithms"):
                result["escalate"] = True
                result["escalate_reason"] = f"SSH weak algorithms supported on {host}:{port}: {result['weak_algorithms']}"
        except Exception as e:
            print_status(f"[SSHScan] Error: {e}", "warning")
            result["error"] = str(e)
        return result
