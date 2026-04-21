import ipaddress
import random
import socket
from datetime import datetime, timezone

try:
    from scapy.all import sniff
except Exception:  # pragma: no cover - scapy can be unavailable in some environments
    sniff = None


KNOWN_PORTS = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    123: "NTP",
    443: "HTTPS",
    3389: "RDP",
    8080: "HTTP-ALT",
}

def _now():
    return datetime.now(timezone.utc).isoformat()


def _is_private(ip_address):
    try:
        return ipaddress.ip_address(ip_address).is_private
    except ValueError:
        return False


def _protocol_name(proto_number):
    mapping = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return mapping.get(proto_number, f"IP-{proto_number}")


def _process_live_packet(packet):
    if not packet.haslayer("IP"):
        return None

    ip_layer = packet["IP"]
    source_port = getattr(packet, "sport", None)
    destination_port = getattr(packet, "dport", None)
    port = destination_port or source_port

    return {
        "timestamp": _now(),
        "src": ip_layer.src,
        "dst": ip_layer.dst,
        "proto": ip_layer.proto,
        "protocol_name": _protocol_name(ip_layer.proto),
        "service": KNOWN_PORTS.get(port, "Unknown"),
        "packet_size": len(packet),
        "direction": "ingress" if not _is_private(ip_layer.src) else "internal",
        "collection_mode": "live",
    }


def _generate_demo_packets(packet_count):
    sample_ips = [
        "203.0.113.12",
        "198.51.100.22",
        "45.33.32.156",
        "192.168.1.20",
        "10.0.0.5",
        "172.16.0.8",
    ]
    destinations = ["192.168.1.10", "10.0.0.10", "172.16.0.12"]
    protocol_pool = [(6, 443), (6, 22), (6, 3389), (17, 53), (17, 123), (1, None)]

    packets = []
    for index in range(packet_count):
        proto, port = random.choice(protocol_pool)
        src = random.choice(sample_ips)
        if index > packet_count // 2:
            src = "203.0.113.250"

        packets.append(
            {
                "timestamp": _now(),
                "src": src,
                "dst": random.choice(destinations),
                "proto": proto,
                "protocol_name": _protocol_name(proto),
                "service": KNOWN_PORTS.get(port, "Unknown") if port else "Network Control",
                "packet_size": random.randint(64, 1500),
                "direction": "ingress" if not _is_private(src) else "internal",
                "collection_mode": "simulated",
            }
        )

    return packets


def _live_capture(packet_count):
    if sniff is None:
        return []

    packets = sniff(count=packet_count, timeout=3, store=True)
    parsed_packets = []
    for packet in packets:
        info = _process_live_packet(packet)
        if info:
            parsed_packets.append(info)
    return parsed_packets


def start_sniffing(mode="auto", packet_count=10):
    mode = (mode or "auto").lower()

    if mode not in {"auto", "live", "simulated"}:
        mode = "auto"

    if mode == "simulated":
        return _generate_demo_packets(packet_count)

    live_packets = []
    if mode in {"auto", "live"}:
        try:
            socket.gethostname()
            live_packets = _live_capture(packet_count)
        except Exception:
            live_packets = []

    if live_packets:
        return live_packets

    return _generate_demo_packets(packet_count)
