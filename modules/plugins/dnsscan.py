import random
import socket
import struct

from modules.plugins import ScanPlugin
from utils.common import print_status


DNS_PORTS = {53}
DNS_SERVICES = {"domain", "dns"}


def _encode_name(name):
    parts = [part for part in name.rstrip(".").split(".") if part]
    encoded = b"".join(bytes([len(part)]) + part.encode("ascii", "ignore") for part in parts)
    return encoded + b"\x00"


def _query(host, name, qtype=1, qclass=1, timeout=3):
    query_id = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack("!HH", qtype, qclass)
    packet = header + question

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (host, 53))
        data, _ = s.recvfrom(4096)

    if len(data) < 12:
        return {"error": "short DNS response"}

    resp_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    return {
        "query_id_matches": resp_id == query_id,
        "rcode": flags & 0x000F,
        "recursion_available": bool(flags & 0x0080),
        "authoritative": bool(flags & 0x0400),
        "question_count": qdcount,
        "answer_count": ancount,
        "authority_count": nscount,
        "additional_count": arcount,
        "response_bytes": len(data),
    }


class DNSScan(ScanPlugin):
    name = "dns_scan"
    description = "Collects safe DNS service evidence and recursion indicators."

    def should_run(self, host, port, port_data):
        return port in DNS_PORTS or port_data.get("service") in DNS_SERVICES

    def run(self, host, port, port_data):
        print_status(f"Plugin - Running {self.name} against {host}:{port}...", "scan")
        result = {
            "tcp_connect": False,
            "recursion_check": None,
            "version_bind_check": None,
        }

        try:
            with socket.create_connection((host, port), timeout=3):
                result["tcp_connect"] = True
        except Exception as e:
            result["tcp_error"] = str(e)

        try:
            result["recursion_check"] = _query(host, "example.com", qtype=1, qclass=1)
            if result["recursion_check"].get("recursion_available"):
                result["escalate"] = True
                result["escalate_reason"] = f"DNS recursion appears available on {host}:{port}"
        except Exception as e:
            result["recursion_error"] = str(e)

        try:
            result["version_bind_check"] = _query(host, "version.bind", qtype=16, qclass=3)
        except Exception as e:
            result["version_bind_error"] = str(e)

        print_status(
            f"[DNSScan] tcp={result['tcp_connect']} recursion={bool((result.get('recursion_check') or {}).get('recursion_available'))}",
            "info",
        )
        return result
