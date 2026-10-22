from collections import defaultdict, deque
from datetime import datetime
import ipaddress
from pathlib import Path
import socket
import sqlite3
import subprocess

PROJECT_DIR = Path(__file__).resolve().parent
DB_PATH = str(PROJECT_DIR / "data" / "traffic.db")

# Standard RFC 1918 private subnets for VM / NAT compatibility
LOCAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

ALLOWED_SPECIAL_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("fe80::/10"),
]

# Detection thresholds
TIME_WINDOW_SECONDS = 60
TRAFFIC_SPIKE_BYTES_THRESHOLD = 50000
TRAFFIC_SPIKE_THRESHOLD = 100
REPEATED_COMMUNICATION_THRESHOLD = 20
REPEATED_TCP_THRESHOLD = 20
REPEATED_CONNECTION_REQUEST_THRESHOLD = 5
PORT_SCAN_UNIQUE_PORTS_THRESHOLD = 10


def get_local_interface_ips():
    """Return IP addresses assigned to all active network interfaces on this machine."""
    local_ips = set()

    # Query all active interfaces via iproute2
    try:
        result = subprocess.run(
            ["ip", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            check=True
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "inet" in parts:
                idx = parts.index("inet")
                ip_str = parts[idx + 1].split("/")[0]
                local_ips.add(ipaddress.ip_address(ip_str))
            if "inet6" in parts:
                idx = parts.index("inet6")
                ip_str = parts[idx + 1].split("/")[0]
                local_ips.add(ipaddress.ip_address(ip_str))
    except (subprocess.SubprocessError, OSError, ValueError):
        pass

    # Fallback to hostname resolution
    try:
        for info in socket.getaddrinfo(
            socket.gethostname(),
            None,
            type=socket.SOCK_STREAM
        ):
            ip_str = info[4][0]
            local_ips.add(ipaddress.ip_address(ip_str))
    except (OSError, ValueError):
        pass

    return local_ips


def get_packets(session_id=None):
    """Retrieve packets from a specified session, all sessions ('ALL'), or the latest session."""
    if not Path(DB_PATH).exists():
        return []

    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()

        if session_id == "ALL":
            cursor.execute("""
                SELECT timestamp, source_ip, destination_ip,
                       protocol, source_port, destination_port,
                       packet_length, tcp_flags
                FROM packets
                ORDER BY timestamp ASC
            """)
            return cursor.fetchall()

        if session_id is None:
            cursor.execute("""
                SELECT session_id
                FROM packets
                WHERE session_id IS NOT NULL
                ORDER BY id DESC
                LIMIT 1
            """)
            result = cursor.fetchone()
            if not result:
                return []
            session_id = result[0]

        cursor.execute("""
            SELECT timestamp, source_ip, destination_ip,
                   protocol, source_port, destination_port,
                   packet_length, tcp_flags
            FROM packets
            WHERE session_id = ?
            ORDER BY timestamp ASC
        """, (session_id,))

        return cursor.fetchall()


def is_multicast(ip):
    """Check whether an IP address is multicast or broadcast."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_multicast or ip == "255.255.255.255"
    except ValueError:
        return False


def is_known_ip(ip, local_interface_ips=None):
    """Check whether an IP belongs to the expected local network environment."""
    try:
        address = ipaddress.ip_address(ip)
        if local_interface_ips is None:
            local_interface_ips = get_local_interface_ips()

        if address in local_interface_ips:
            return True

        for network in LOCAL_NETWORKS + ALLOWED_SPECIAL_NETWORKS:
            if address in network:
                return True

        return False

    except ValueError:
        return True


def parse_timestamp(timestamp):
    """Parse ISO-8601 timestamps with or without microseconds."""
    try:
        return datetime.fromisoformat(timestamp)
    except (ValueError, TypeError):
        return None


def detect_unknown_ips(packets):
    """Detect communication with external/global IP addresses outside the local baseline."""
    alerts = []
    alerted_ips = set()
    local_interface_ips = get_local_interface_ips()

    for packet in packets:
        (
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            length,
            tcp_flags
        ) = packet

        event_time = parse_timestamp(timestamp)
        if not event_time:
            continue

        for ip, direction in [(src_ip, "source"), (dst_ip, "destination")]:
            if (
                not ip
                or ip == "-"
                or ip in alerted_ips
                or is_known_ip(ip, local_interface_ips)
                or is_multicast(ip)
            ):
                continue

            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                continue

            if not address.is_global:
                continue

            alerts.append({
                "type": "External IP Observed",
                "source": src_ip,
                "destination": dst_ip,
                "details": f"External {direction} IP {ip} observed over {protocol}",
                "timestamp": event_time.isoformat()
            })

            alerted_ips.add(ip)

    return alerts


def detect_traffic_spikes(packets):
    """Detect high packet count or byte volume from a single source within the time window."""
    alerts = []
    source_events = defaultdict(deque)
    alerted_sources = set()
    source_bytes = defaultdict(int)

    for packet in packets:
        (
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            length,
            tcp_flags
        ) = packet

        event_time = parse_timestamp(timestamp)
        if not event_time or not src_ip or src_ip == "-":
            continue

        if src_ip in alerted_sources:
            continue

        length = length or 0
        events = source_events[src_ip]
        cutoff = event_time.timestamp() - TIME_WINDOW_SECONDS

        while events and events[0][0].timestamp() < cutoff:
            old_time, old_length = events.popleft()
            source_bytes[src_ip] -= old_length

        events.append((event_time, length))
        source_bytes[src_ip] += length

        if (
            len(events) >= TRAFFIC_SPIKE_THRESHOLD
            or source_bytes[src_ip] >= TRAFFIC_SPIKE_BYTES_THRESHOLD
        ):
            alerts.append({
                "type": "High Traffic Volume",
                "source": src_ip,
                "destination": "Multiple",
                "details": (
                    f"{len(events)} packets ({source_bytes[src_ip]:,} bytes) "
                    f"within {TIME_WINDOW_SECONDS} seconds"
                ),
                "timestamp": event_time.isoformat()
            })
            alerted_sources.add(src_ip)

    return alerts


def detect_repeated_communication(packets):
    """Detect repeated unicast packet bursts between the same source and destination."""
    alerts = []
    communication_events = defaultdict(deque)
    alerted_pairs = set()

    for packet in packets:
        (
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            length,
            tcp_flags
        ) = packet

        event_time = parse_timestamp(timestamp)
        if (
            not event_time
            or not src_ip
            or not dst_ip
            or src_ip == "-"
            or dst_ip == "-"
            or is_multicast(dst_ip)
        ):
            continue

        key = (src_ip, dst_ip)
        if key in alerted_pairs:
            continue

        events = communication_events[key]
        cutoff = event_time.timestamp() - TIME_WINDOW_SECONDS

        while events and events[0].timestamp() < cutoff:
            events.popleft()

        events.append(event_time)

        if len(events) >= REPEATED_COMMUNICATION_THRESHOLD:
            alerts.append({
                "type": "Repeated Unicast Communication",
                "source": src_ip,
                "destination": dst_ip,
                "details": (
                    f"{len(events)} packets exchanged within {TIME_WINDOW_SECONDS} seconds"
                ),
                "timestamp": event_time.isoformat()
            })
            alerted_pairs.add(key)

    return alerts


def detect_repeated_tcp_activity(packets):
    """Detect repeated TCP packets targeting the same destination port."""
    alerts = []
    tcp_events = defaultdict(deque)
    alerted_keys = set()

    for packet in packets:
        (
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            length,
            tcp_flags
        ) = packet

        event_time = parse_timestamp(timestamp)
        if (
            protocol != "TCP"
            or not event_time
            or not src_ip
            or not dst_ip
            or src_ip == "-"
            or dst_ip == "-"
            or not dst_port
            or dst_port == "-"
        ):
            continue

        key = (src_ip, dst_ip, dst_port)
        if key in alerted_keys:
            continue

        events = tcp_events[key]
        cutoff = event_time.timestamp() - TIME_WINDOW_SECONDS

        while events and events[0].timestamp() < cutoff:
            events.popleft()

        events.append(event_time)

        if len(events) >= REPEATED_TCP_THRESHOLD:
            alerts.append({
                "type": "Repeated TCP Activity",
                "source": src_ip,
                "destination": dst_ip,
                "details": (
                    f"{len(events)} TCP packets to port {dst_port} "
                    f"within {TIME_WINDOW_SECONDS} seconds"
                ),
                "timestamp": event_time.isoformat()
            })
            alerted_keys.add(key)

    return alerts


def detect_connection_requests(packets):
    """Detect repeated TCP SYN connection attempts (SYN flood or repeated handshakes)."""
    alerts = []
    connection_events = defaultdict(deque)
    alerted_keys = set()

    for packet in packets:
        (
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            length,
            tcp_flags
        ) = packet

        event_time = parse_timestamp(timestamp)
        if (
            protocol != "TCP"
            or not event_time
            or not src_ip
            or not dst_ip
            or src_ip == "-"
            or dst_ip == "-"
            or not dst_port
            or dst_port == "-"
            or not tcp_flags
        ):
            continue

        flags = str(tcp_flags).upper()
        # SYN without ACK indicates initial TCP connection attempt
        if "S" not in flags or "A" in flags:
            continue

        key = (src_ip, dst_ip, dst_port)
        if key in alerted_keys:
            continue

        events = connection_events[key]
        cutoff = event_time.timestamp() - TIME_WINDOW_SECONDS

        while events and events[0].timestamp() < cutoff:
            events.popleft()

        events.append(event_time)

        if len(events) >= REPEATED_CONNECTION_REQUEST_THRESHOLD:
            alerts.append({
                "type": "Unusual Connection Requests",
                "source": src_ip,
                "destination": dst_ip,
                "details": (
                    f"{len(events)} TCP SYN connection requests to port {dst_port} "
                    f"within {TIME_WINDOW_SECONDS} seconds"
                ),
                "timestamp": event_time.isoformat()
            })
            alerted_keys.add(key)

    return alerts


def detect_port_scans(packets):
    """Detect port scanning where a single source IP probes multiple distinct destination ports."""
    alerts = []
    scan_tracker = defaultdict(lambda: (deque(), defaultdict(int)))
    alerted_pairs = set()

    for packet in packets:
        (
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            length,
            tcp_flags
        ) = packet

        event_time = parse_timestamp(timestamp)
        if (
            not event_time
            or not src_ip
            or not dst_ip
            or not dst_port
            or src_ip == "-"
            or dst_ip == "-"
            or dst_port == "-"
        ):
            continue

        key = (src_ip, dst_ip)
        if key in alerted_pairs:
            continue

        events, port_counts = scan_tracker[key]
        cutoff = event_time.timestamp() - TIME_WINDOW_SECONDS

        while events and events[0][0].timestamp() < cutoff:
            old_time, old_port = events.popleft()
            port_counts[old_port] -= 1
            if port_counts[old_port] <= 0:
                del port_counts[old_port]

        events.append((event_time, dst_port))
        port_counts[dst_port] += 1

        if len(port_counts) >= PORT_SCAN_UNIQUE_PORTS_THRESHOLD:
            alerts.append({
                "type": "Port Scan Detected",
                "source": src_ip,
                "destination": dst_ip,
                "details": (
                    f"Probed {len(port_counts)} unique destination ports "
                    f"within {TIME_WINDOW_SECONDS} seconds"
                ),
                "timestamp": event_time.isoformat()
            })
            alerted_pairs.add(key)

    return alerts


def run_detection(session_id=None):
    """Run all suspicious activity detection rules on the selected capture session."""
    packets = get_packets(session_id)

    if not packets:
        print("No packet data available in the capture session.")
        return []

    alerts = []
    # 1. External and unknown IP communication
    alerts.extend(detect_unknown_ips(packets))
    # 2. Traffic volume spikes
    alerts.extend(detect_traffic_spikes(packets))
    # 3. High-frequency unicast communication
    alerts.extend(detect_repeated_communication(packets))
    # 4. Repeated TCP port traffic
    alerts.extend(detect_repeated_tcp_activity(packets))
    # 5. SYN connection requests (SYN flood / brute force)
    alerts.extend(detect_connection_requests(packets))
    # 6. Reconnaissance port scans
    alerts.extend(detect_port_scans(packets))

    # Sort alerts chronologically
    alerts.sort(key=lambda item: item.get("timestamp", ""))

    print("\n--- SUSPICIOUS ACTIVITY DETECTION ---")
    print("Packets analyzed:", len(packets))
    print("Alerts generated:", len(alerts))

    if not alerts:
        print("No alerts detected.")
        return alerts

    for index, alert in enumerate(alerts, start=1):
        print(f"\nAlert #{index}")
        print("Type:", alert["type"])
        print("Source:", alert["source"])
        print("Destination:", alert["destination"])
        print("Details:", alert["details"])
        print("Timestamp:", alert["timestamp"])

    return alerts


if __name__ == "__main__":
    run_detection()
