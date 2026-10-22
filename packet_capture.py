from pathlib import Path
import argparse
import sqlite3
import uuid
from datetime import datetime

from scapy.all import conf, sniff, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ARP


INTERFACE = conf.iface if conf.iface else "eth0"
PROJECT_DIR = Path(__file__).resolve().parent
DATABASE_PATH = str(PROJECT_DIR / "data" / "traffic.db")


# --------------------------------------------------
# SESSION
# --------------------------------------------------

SESSION_ID = str(uuid.uuid4())


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def save_packet(packet_data):
    with sqlite3.connect(DATABASE_PATH) as connection:
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO packets (
                timestamp,
                source_ip,
                destination_ip,
                protocol,
                source_port,
                destination_port,
                packet_length,
                session_id,
                tcp_flags
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            packet_data["timestamp"],
            packet_data["source_ip"],
            packet_data["destination_ip"],
            packet_data["protocol"],
            packet_data["source_port"],
            packet_data["destination_port"],
            packet_data["packet_length"],
            packet_data["session_id"],
            packet_data["tcp_flags"]
        ))

        connection.commit()


# --------------------------------------------------
# PACKET PROCESSING
# --------------------------------------------------

def process_packet(packet):
    timestamp = datetime.now().isoformat(timespec="microseconds")

    source_ip = ""
    destination_ip = ""
    protocol = "OTHER"
    source_port = ""
    destination_port = ""
    tcp_flags = ""

    # -----------------------------
    # ARP
    # -----------------------------
    if packet.haslayer(ARP):
        source_ip = packet[ARP].psrc
        destination_ip = packet[ARP].pdst
        protocol = "ARP"

    # -----------------------------
    # IPv4
    # -----------------------------
    elif packet.haslayer(IP):

        ip_layer = packet[IP]

        source_ip = ip_layer.src
        destination_ip = ip_layer.dst

        # IPv4 protocol number 2 is IGMP, not UDP.
        if ip_layer.proto == 2:
            protocol = "IGMP"

        elif packet.haslayer(TCP):
            protocol = "TCP"
            source_port = str(packet[TCP].sport)
            destination_port = str(packet[TCP].dport)
            tcp_flags = str(packet[TCP].flags)

        elif packet.haslayer(UDP):
            source_port = str(packet[UDP].sport)
            destination_port = str(packet[UDP].dport)
            protocol = "UDP"

        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        else:
            protocol = f"IP-{ip_layer.proto}"

    # -----------------------------
    # IPv6
    # -----------------------------
    elif packet.haslayer(IPv6):

        ipv6_layer = packet[IPv6]

        source_ip = ipv6_layer.src
        destination_ip = ipv6_layer.dst

        if packet.haslayer(TCP):
            protocol = "TCP"
            source_port = str(packet[TCP].sport)
            destination_port = str(packet[TCP].dport)
            tcp_flags = str(packet[TCP].flags)

        elif packet.haslayer(UDP):
            protocol = "UDP"
            source_port = str(packet[UDP].sport)
            destination_port = str(packet[UDP].dport)

        elif packet.haslayer(ICMPv6EchoRequest):
            protocol = "ICMPv6"

        else:
            protocol = f"IPv6-{ipv6_layer.nh}"

    # -----------------------------
    # Build record
    # -----------------------------
    packet_data = {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "packet_length": len(packet),
        "session_id": SESSION_ID,
        "tcp_flags": tcp_flags
    }

    return packet_data


def process_and_save_packet(packet):
    try:
        packet_data = process_packet(packet)
        save_packet(packet_data)

        print(
            f"[{packet_data['timestamp']}] "
            f"{packet_data['protocol']:8} "
            f"{packet_data['source_ip']} -> "
            f"{packet_data['destination_ip']} "
            f"size={packet_data['packet_length']}"
        )

    except Exception as error:
        print(f"[ERROR] Could not process packet: {error}")


# --------------------------------------------------
# ARGUMENTS
# --------------------------------------------------

def parse_arguments():

    parser = argparse.ArgumentParser(
        description="Network Traffic Analyzer - Packet Capture"
    )

    group = parser.add_mutually_exclusive_group()

    group.add_argument(
        "--count",
        type=int,
        help="Number of packets to capture"
    )

    group.add_argument(
        "--continuous",
        action="store_true",
        help="Capture continuously until Ctrl+C"
    )

    return parser.parse_args()


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main():

    args = parse_arguments()

    print("=" * 60)
    print("NETWORK TRAFFIC ANALYZER")
    print("PACKET CAPTURE")
    print("=" * 60)

    print(f"Interface : {INTERFACE}")
    print(f"Session   : {SESSION_ID}")

    if args.continuous:
        print("Mode      : CONTINUOUS")
        print("Press Ctrl+C to stop.")
        print("=" * 60)

        try:
            sniff(
                iface=INTERFACE,
                prn=process_and_save_packet,
                store=False
            )

        except KeyboardInterrupt:
            print("\n")
            print("Capture stopped by user.")

    else:

        count = args.count if args.count is not None else 10

        if count <= 0:
            print("Packet count must be greater than 0.")
            return

        print(f"Mode      : LIMITED")
        print(f"Packets   : {count}")
        print("=" * 60)

        sniff(
            iface=INTERFACE,
            count=count,
            prn=process_and_save_packet,
            store=False
        )

    print("=" * 60)
    print("Capture session finished.")
    print(f"Session ID: {SESSION_ID}")
    print("=" * 60)


if __name__ == "__main__":
    main()
