from collections import Counter


HIGH_RISK_SERVICES = {"RDP", "SSH"}


def _severity_rank(level):
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(level, 0)


def detect_threats(packets):
    source_counts = Counter(packet["src"] for packet in packets)
    threats = []
    seen = set()

    for packet in packets:
        src = packet["src"]
        service = packet.get("service", "Unknown")
        key_base = (src, service)

        if source_counts[src] >= 5 and (src, "flood") not in seen:
            threats.append(
                {
                    "severity": "high",
                    "type": "Traffic Spike",
                    "source": src,
                    "service": service,
                    "message": f"Repeated traffic burst detected from {src}.",
                    "recommendation": "Review upstream firewall rules and rate limiting.",
                }
            )
            seen.add((src, "flood"))

        if packet.get("direction") == "ingress" and service in HIGH_RISK_SERVICES and key_base not in seen:
            threats.append(
                {
                    "severity": "medium",
                    "type": "Sensitive Service Exposure",
                    "source": src,
                    "service": service,
                    "message": f"External traffic reached {service} on an internal asset.",
                    "recommendation": f"Confirm {service} exposure is intended and protected by MFA/VPN.",
                }
            )
            seen.add(key_base)

        if packet.get("protocol_name") == "ICMP" and (src, "icmp") not in seen:
            threats.append(
                {
                    "severity": "low",
                    "type": "Recon Activity",
                    "source": src,
                    "service": "ICMP",
                    "message": f"ICMP probing observed from {src}.",
                    "recommendation": "Check for scanning behavior and tighten edge filtering if needed.",
                }
            )
            seen.add((src, "icmp"))

    threats.sort(key=lambda alert: _severity_rank(alert["severity"]), reverse=True)
    return threats


def build_overview(events, alerts):
    severity_counter = Counter(alert.get("severity", "low") for alert in alerts)
    event_counter = Counter(event.get("event_type", "unknown") for event in events)

    recent_packets = 0
    monitor_runs = 0
    for event in events:
        if event.get("event_type") == "monitor_run":
            monitor_runs += 1
            recent_packets += int(event.get("details", {}).get("packet_count", 0))

    return {
        "metrics": {
            "total_alerts": len(alerts),
            "critical_alerts": severity_counter.get("critical", 0),
            "high_alerts": severity_counter.get("high", 0),
            "monitor_runs": monitor_runs,
            "recent_packets": recent_packets,
            "scan_runs": event_counter.get("scan", 0),
        },
        "severity_breakdown": dict(severity_counter),
        "alerts": alerts[:10],
        "events": events[:12],
    }
