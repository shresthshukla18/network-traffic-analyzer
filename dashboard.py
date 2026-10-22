import streamlit as st
import monitoring
import detection

# Refresh live traffic statistics every 5 seconds.

st.set_page_config(
    page_title="Network Traffic Analyzer",
    page_icon="🛡️",
    layout="wide"
)

@st.fragment(run_every="5s")
def render_dashboard():
    st.title("🛡️ Network Traffic Analyzer")
    from datetime import datetime
    st.caption(f"🔄 Last updated: {datetime.now().strftime('%H:%M:%S')}")
    st.caption("Real-time network traffic monitoring and suspicious activity detection")

    st.sidebar.header("Dashboard Controls")

    session_id = monitoring.get_latest_session_id()
    stats = monitoring.get_traffic_stats(session_id=session_id)

    if stats["total_packets"] == 0:
        st.warning("No captured traffic found in the database.")
        st.info(
            "Start packet capture in another terminal with: "
            "sudo python packet_capture.py --continuous"
        )
        st.stop()

    st.sidebar.success("Traffic database connected")

    st.header("Traffic Overview")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Total Packets",
            f"{stats['total_packets']:,}"
        )

    with col2:
        st.metric(
            "Total Traffic",
            f"{stats['total_bytes']:,} B"
        )

    with col3:
        st.metric(
            "Traffic Rate",
            f"{stats['traffic_rate']:.2f} B/s"
        )

    with col4:
        st.metric(
            "Unique IPs",
            f"{stats['unique_ips']:,}"
        )

    st.divider()

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Incoming Packets",
            f"{stats['incoming_packets']:,}"
        )

    with col2:
        st.metric(
            "Outgoing Packets",
            f"{stats['outgoing_packets']:,}"
        )

    with col3:
        st.metric(
            "Active Connections",
            f"{len(stats['active_connections']):,}"
        )

    with col4:
        st.metric(
            "Recent Connections",
            f"{len(stats['recent_connections']):,}"
        )

    st.divider()

    st.header("Protocol Distribution")

    protocol_data = stats["protocols"]

    if protocol_data:
        import pandas as pd
        import plotly.express as px

        protocol_df = pd.DataFrame(
            list(protocol_data.items()),
            columns=["Protocol", "Packets"]
        )

        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            fig_pie = px.pie(
                protocol_df,
                names="Protocol",
                values="Packets",
                title="Packet Share by Protocol",
                hole=0.45
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        with chart_col2:
            fig_bar = px.bar(
                protocol_df.sort_values("Packets", ascending=False),
                x="Protocol",
                y="Packets",
                title="Packet Count by Protocol",
                text="Packets"
            )
            st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.info("No protocol data is available yet.")

    st.divider()

    st.header("Device Activity & Traffic Timeline")

    device_data = stats["device_activity"]
    timeline_data = stats["traffic_timeline"]

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("Top Devices by Traffic")

        if device_data:
            device_df = pd.DataFrame(
                list(device_data.items()),
                columns=["IP Address", "Bytes"]
            ).sort_values("Bytes", ascending=False).head(10)

            fig_devices = px.bar(
                device_df.sort_values("Bytes", ascending=True),
                x="Bytes",
                y="IP Address",
                orientation="h",
                title="Top 10 IP Addresses by Traffic",
                text="Bytes"
            )
            st.plotly_chart(fig_devices, use_container_width=True)
        else:
            st.info("No device activity data available.")

    with chart_col2:
        st.subheader("Traffic Over Time")

        if timeline_data:
            timeline_df = pd.DataFrame(
                list(timeline_data.items()),
                columns=["Timestamp", "Bytes"]
            ).sort_values("Timestamp")

            fig_timeline = px.line(
                timeline_df,
                x="Timestamp",
                y="Bytes",
                markers=True,
                title="Traffic Volume by Time Bucket"
            )
            st.plotly_chart(fig_timeline, use_container_width=True)
        else:
            st.info("No traffic timeline data available.")

    st.divider()

    st.header("🚨 Suspicious Activity Detection")

    # Automatically scan when the capture session changes or packet count
    # increases. Keep the manual scan available.
    import time
    detection_key = f"detection_session_{session_id}"
    scan_state_key = f"detection_state_{session_id}"

    current_packet_count = stats["total_packets"]
    previous_state = st.session_state.get(scan_state_key, {})
    session_changed = previous_state.get("session_id") != session_id
    packets_changed = previous_state.get("packet_count") != current_packet_count
    manual_scan = st.button("Run Detection Now", type="secondary")

    if session_changed or packets_changed or manual_scan:
        with st.spinner("Analyzing captured traffic..."):
            st.session_state[detection_key] = detection.run_detection(
                session_id=session_id
            )
            st.session_state[scan_state_key] = {
                "session_id": session_id,
                "packet_count": current_packet_count,
                "scanned_at": time.time(),
            }
            st.session_state["last_detection_time"] = datetime.now().strftime(
                "%H:%M:%S"
            )

    alerts = st.session_state.get(detection_key, [])
    last_detection_time = st.session_state.get("last_detection_time", "Pending")
    st.caption(
        f"Automatic detection · Last scan: {last_detection_time} · "
        f"Packets analyzed: {current_packet_count:,}"
    )

    alerts = st.session_state.get(detection_key, [])
    last_detection_time = st.session_state.get("last_detection_time", "Pending")

    st.metric("Total Alerts", len(alerts))

    if alerts:
        st.warning(f"{len(alerts)} suspicious activity alert(s) detected.")

        alert_df = pd.DataFrame(alerts)
        st.dataframe(
            alert_df[
                ["type", "source", "destination", "details", "timestamp"]
            ].rename(columns={
                "type": "Alert Type",
                "source": "Source IP",
                "destination": "Destination IP",
                "details": "Details",
                "timestamp": "Timestamp"
            }),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.success(
            "No suspicious activity detected in the analyzed capture session. "
            "Run detection to analyze traffic."
        )

    st.divider()

    st.header("🔗 Connection Activity")

    connection_data = stats["connection_flows"]

    if connection_data:
        connection_df = pd.DataFrame(connection_data)

        display_columns = [
            "protocol",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "packets",
            "bytes",
            "status"
        ]

        available_columns = [
            column for column in display_columns
            if column in connection_df.columns
        ]

        st.dataframe(
            connection_df[available_columns].rename(columns={
                "protocol": "Protocol",
                "source_ip": "Source IP",
                "source_port": "Source Port",
                "destination_ip": "Destination IP",
                "destination_port": "Destination Port",
                "packets": "Packets",
                "bytes": "Bytes",
                "status": "Flow Status"
            }),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No connection-flow records are available.")

    st.divider()

    st.header("📄 Traffic and Security Reports")

    # Traffic summary report
    summary_rows = [
        {"Metric": "Total Packets", "Value": stats["total_packets"]},
        {"Metric": "Total Bytes", "Value": stats["total_bytes"]},
        {"Metric": "Unique IPs", "Value": stats["unique_ips"]},
        {"Metric": "Capture Duration (seconds)", "Value": stats["duration"]},
        {"Metric": "Traffic Rate (bytes/second)", "Value": stats["traffic_rate"]},
        {"Metric": "Incoming Packets", "Value": stats["incoming_packets"]},
        {"Metric": "Outgoing Packets", "Value": stats["outgoing_packets"]},
        {"Metric": "Active Flow Observations", "Value": len(stats["active_connections"])},
        {"Metric": "Recent Flow Observations", "Value": len(stats["recent_connections"])},
        {"Metric": "Alerts Detected", "Value": len(alerts)},
    ]

    for protocol, count in stats["protocols"].items():
        summary_rows.append({
            "Metric": f"Protocol Packets - {protocol}",
            "Value": count
        })

    summary_df = pd.DataFrame(summary_rows)

    # Security analysis report
    security_columns = ["type", "source", "destination", "details", "timestamp"]

    if alerts:
        security_df = pd.DataFrame(alerts)[security_columns]
    else:
        security_df = pd.DataFrame(columns=security_columns)

    # Report download controls
    report_col1, report_col2, report_col3 = st.columns(3)

    with report_col1:
        st.download_button(
            "Download Traffic Summary",
            data=summary_df.to_csv(index=False),
            file_name="traffic_summary.csv",
            mime="text/csv",
            use_container_width=True
        )

    with report_col2:
        st.download_button(
            "Download Connection Report",
            data=pd.DataFrame(connection_data).to_csv(index=False),
            file_name="connection_report.csv",
            mime="text/csv",
            use_container_width=True
        )

    with report_col3:
        st.download_button(
            "Download Security Analysis",
            data=security_df.to_csv(index=False),
            file_name="security_analysis.csv",
            mime="text/csv",
            use_container_width=True
        )

    st.caption(
        "Reports reflect the data currently loaded in the dashboard. "
        "Run detection before downloading the security analysis to refresh alerts."
    )

render_dashboard()
