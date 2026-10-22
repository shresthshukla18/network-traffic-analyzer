from pathlib import Path
import ipaddress
import subprocess
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime

PROJECT_DIR = Path(__file__).resolve().parent
DB_PATH = str(PROJECT_DIR / "data" / "traffic.db")


def get_local_ips():
    local_ips = {"127.0.0.1", "::1"}

    try:
        # Run across all active interfaces instead of hardcoding eth0
        result = subprocess.run(
            ["ip", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            check=True
        )

        for line in result.stdout.splitlines():
            parts = line.split()

            if "inet" in parts:
                index = parts.index("inet")
                local_ips.add(parts[index + 1].split("/")[0])

            if "inet6" in parts:
                index = parts.index("inet6")
                local_ips.add(parts[index + 1].split("/")[0])

    except (subprocess.SubprocessError, OSError, ValueError):
        pass

    return local_ips

def get_traffic_timeline(rows):
    timeline = Counter()

    for row in rows:
        timestamp = row[0]
        packet_length = row[6] or 0

        try:
            dt = datetime.fromisoformat(timestamp)
            bucket = dt.replace(microsecond=0).isoformat()
            timeline[bucket] += packet_length
        except (ValueError, TypeError):
            continue

    return timeline


def get_traffic_patterns(timeline):
    if not timeline:
        return {
            "peak_bytes": 0,
            "peak_timestamp": None,
            "average_bytes_per_second": 0,
            "active_seconds": 0,
            "burst_seconds": 0,
        }

    values = list(timeline.values())
    average = sum(values) / len(values)
    peak_timestamp, peak_bytes = max(
        timeline.items(),
        key=lambda item: item[1]
    )

    burst_seconds = sum(
        1 for value in values
        if value > average * 2
    )

    return {
        "peak_bytes": peak_bytes,
        "peak_timestamp": peak_timestamp,
        "average_bytes_per_second": round(average, 2),
        "active_seconds": len(values),
        "burst_seconds": burst_seconds,
    }


def get_connection_flows(rows):
    flows = {}

    for row in rows:
        (
            timestamp,
            protocol,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            packet_length,
            session_id
        ) = row

        if (
            not source_ip
            or not destination_ip
            or source_ip == "-"
            or destination_ip == "-"
        ):
            continue

        key = (
            protocol,
            source_ip,
            source_port,
            destination_ip,
            destination_port
        )

        if key not in flows:
            flows[key] = {
                "protocol": protocol,
                "source_ip": source_ip,
                "source_port": source_port,
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "packets": 0,
                "bytes": 0,
                "first_seen": timestamp,
                "last_seen": timestamp,
            }

        flow = flows[key]
        flow["packets"] += 1
        flow["bytes"] += packet_length or 0

        if timestamp < flow["first_seen"]:
            flow["first_seen"] = timestamp

        if timestamp > flow["last_seen"]:
            flow["last_seen"] = timestamp

    return list(flows.values())


def classify_connection_activity(flows):
    if not flows:
        return []

    timestamps = []

    for flow in flows:
        try:
            timestamps.append(
                datetime.fromisoformat(flow["last_seen"])
            )
        except (ValueError, TypeError):
            continue

    if not timestamps:
        return flows

    latest_time = max(timestamps)

    for flow in flows:
        try:
            last_seen = datetime.fromisoformat(flow["last_seen"])
            age = (latest_time - last_seen).total_seconds()

            if age <= 5:
                flow["status"] = "Active"
            elif age <= 30:
                flow["status"] = "Recent"
            else:
                flow["status"] = "Inactive"

        except (ValueError, TypeError):
            flow["status"] = "Unknown"

    return flows


def get_latest_session_id():
    """Return the ID of the most recently observed capture session."""
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("""
            SELECT session_id
            FROM packets
            WHERE session_id IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT 1
        """).fetchone()
    return row[0] if row else None


def get_traffic_stats(session_id=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    query = """
        SELECT timestamp, protocol, source_ip, destination_ip,
               source_port, destination_port, packet_length, session_id
        FROM packets
    """

    params = ()

    if session_id:
        query += " WHERE session_id = ?"
        params = (session_id,)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    total_packets = len(rows)
    total_bytes = sum(row[6] or 0 for row in rows)

    local_ips = get_local_ips()

    direction_packets = Counter()
    direction_bytes = Counter()
    device_activity = Counter()

    for row in rows:
        source_ip = row[2]
        destination_ip = row[3]
        packet_length = row[6] or 0

        # Mutually exclusive categories; multicast is kept separate.
        try:
            destination_is_multicast = (
                bool(destination_ip)
                and ipaddress.ip_address(destination_ip).is_multicast
            )
        except ValueError:
            destination_is_multicast = False

        source_is_local = source_ip in local_ips
        destination_is_local = destination_ip in local_ips

        if destination_is_multicast:
            direction = "multicast"
        elif source_is_local and destination_is_local:
            direction = "internal"
        elif destination_is_local:
            direction = "incoming"
        elif source_is_local:
            direction = "outgoing"
        else:
            direction = "unclassified"

        direction_packets[direction] += 1
        direction_bytes[direction] += packet_length

        if source_ip and source_ip != "-":
            device_activity[source_ip] += packet_length

        if destination_ip and destination_ip != "-":
            device_activity[destination_ip] += packet_length

    incoming_packets = direction_packets["incoming"]
    incoming_bytes = direction_bytes["incoming"]
    outgoing_packets = direction_packets["outgoing"]
    outgoing_bytes = direction_bytes["outgoing"]

    protocols = Counter(
        row[1] for row in rows
        if row[1]
    )

    source_ips = Counter(
        row[2] for row in rows
        if row[2] and row[2] != "-"
    )

    destination_ips = Counter(
        row[3] for row in rows
        if row[3] and row[3] != "-"
    )

    unique_ips = len(set(source_ips) | set(destination_ips))

    timestamps = []

    for row in rows:
        try:
            timestamps.append(
                datetime.fromisoformat(row[0])
            )
        except (ValueError, TypeError):
            continue

    duration = (
        (max(timestamps) - min(timestamps)).total_seconds()
        if len(timestamps) > 1
        else 0
    )

    traffic_rate = (
        total_bytes / duration
        if duration > 0
        else 0
    )

    traffic_timeline = get_traffic_timeline(rows)
    traffic_patterns = get_traffic_patterns(
        traffic_timeline
    )

    connection_flows = get_connection_flows(rows)
    connection_flows = classify_connection_activity(
        connection_flows
    )

    tcp_pairs = set()
    udp_pairs = set()

    for flow in connection_flows:
        pair = (
            flow["source_ip"],
            flow["source_port"],
            flow["destination_ip"],
            flow["destination_port"]
        )

        if flow["protocol"] == "TCP":
            tcp_pairs.add(pair)

        elif flow["protocol"] == "UDP":
            udp_pairs.add(pair)

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "protocols": protocols,
        "source_ips": source_ips,
        "destination_ips": destination_ips,
        "unique_ips": unique_ips,
        "duration": duration,
        "traffic_rate": traffic_rate,
        "tcp_pairs": tcp_pairs,
        "udp_pairs": udp_pairs,
        "incoming_packets": incoming_packets,
        "incoming_bytes": incoming_bytes,
        "outgoing_packets": outgoing_packets,
        "outgoing_bytes": outgoing_bytes,
        "direction_packets": dict(direction_packets),
        "direction_bytes": dict(direction_bytes),
        "device_activity": device_activity,
        "traffic_timeline": traffic_timeline,
        "traffic_patterns": traffic_patterns,
        "connection_flows": connection_flows,
        "active_connections": [
            flow for flow in connection_flows
            if flow["status"] == "Active"
        ],
        "recent_connections": [
            flow for flow in connection_flows
            if flow["status"] == "Recent"
        ],
    }


if __name__ == "__main__":
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT session_id, COUNT(*), MIN(timestamp), MAX(timestamp)
        FROM packets
        WHERE session_id IS NOT NULL
        GROUP BY session_id
        ORDER BY MAX(timestamp) DESC
    """)

    sessions = cursor.fetchall()
    conn.close()

    if not sessions:
        print("No capture sessions found.")
        raise SystemExit

    print("\n--- AVAILABLE CAPTURE SESSIONS ---")

    for index, (sid, count, start, end) in enumerate(
        sessions,
        1
    ):
        print(
            f"{index}. {sid} | "
            f"{count} packets | "
            f"{start} to {end}"
        )

    session_id = sessions[0][0]

    print(
        f"\nShowing latest session: {session_id}"
    )

    stats = get_traffic_stats(session_id)

    print("\n--- NETWORK TRAFFIC STATISTICS ---")
    print(
        "Total packets:",
        stats["total_packets"]
    )

    print(
        "Total traffic:",
        stats["total_bytes"],
        "bytes"
    )

    print(
        "Unique IP addresses:",
        stats["unique_ips"]
    )

    print(
        "Capture duration:",
        round(stats["duration"], 2),
        "seconds"
    )

    print(
        "Average traffic rate:",
        round(stats["traffic_rate"], 2),
        "bytes/sec"
    )

    print("\nTraffic Timeline:")

    for timestamp, byte_count in sorted(
        stats["traffic_timeline"].items()
    ):
        print(
            f"  {timestamp}: "
            f"{byte_count} bytes"
        )

    print("\nTraffic Pattern Analysis:")

    patterns = stats["traffic_patterns"]

    print(
        f"  Peak traffic: "
        f"{patterns['peak_bytes']} bytes"
    )

    print(
        f"  Peak timestamp: "
        f"{patterns['peak_timestamp']}"
    )

    print(
        f"  Average per active second: "
        f"{patterns['average_bytes_per_second']} bytes"
    )

    print(
        f"  Active seconds: "
        f"{patterns['active_seconds']}"
    )

    print(
        f"  Burst seconds: "
        f"{patterns['burst_seconds']}"
    )

    print("\nTraffic Direction:")

    print(
        f"  Incoming: "
        f"{stats['incoming_packets']} packets | "
        f"{stats['incoming_bytes']} bytes"
    )

    print(
        f"  Outgoing: "
        f"{stats['outgoing_packets']} packets | "
        f"{stats['outgoing_bytes']} bytes"
    )

    print("\nDevice Activity:")

    for ip, total_bytes in stats[
        "device_activity"
    ].most_common(10):
        print(
            f"  {ip}: "
            f"{total_bytes} bytes"
        )

    print("\nProtocol Distribution:")

    for protocol, count in stats[
        "protocols"
    ].most_common():
        print(
            f"  {protocol}: {count}"
        )

    print("\nTop Source IPs:")

    for ip, count in stats[
        "source_ips"
    ].most_common(5):
        print(
            f"  {ip}: {count} packets"
        )

    print("\nTop Destination IPs:")

    for ip, count in stats[
        "destination_ips"
    ].most_common(5):
        print(
            f"  {ip}: {count} packets"
        )

    print("\n--- CONNECTION FLOWS ---")

    print(
        "Total flows:",
        len(stats["connection_flows"])
    )

    print(
        "Active flows:",
        len(stats["active_connections"])
    )

    print(
        "Recent flows:",
        len(stats["recent_connections"])
    )

    for flow in sorted(
        stats["connection_flows"],
        key=lambda item: item["bytes"],
        reverse=True
    ):
        print(
            f"  [{flow['status']}] "
            f"{flow['protocol']} "
            f"{flow['source_ip']}:{flow['source_port']} "
            f"-> "
            f"{flow['destination_ip']}:{flow['destination_port']} "
            f"| packets={flow['packets']} "
            f"| bytes={flow['bytes']}"
        )
