import pyshark
import pandas as pd
import joblib
import time
import psutil
import asyncio

# ----------------------------
# Helper function
# ----------------------------
def str_to_int_flag(flag):
    """Convert 'True'/'False' strings from PyShark TCP flags to 1/0."""
    return 1 if flag == "True" else 0

# ----------------------------
# Detect active interface
# ----------------------------
def get_active_interface():
    interfaces = psutil.net_if_stats()
    for iface, stats in interfaces.items():
        if stats.isup:
            return iface
    raise RuntimeError("No active network interface found.")

# ----------------------------
# Packet Capture Function
# ----------------------------
def capture_live_packets(interface, packet_count=50):
    # 🔑 Ensure event loop exists for Streamlit threads
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

    cap = pyshark.LiveCapture(interface=interface)
    packets = []
    cap.sniff(packet_count=packet_count)  # blocking capture

    for packet in cap:
        try:
            pkt_dict = {
                "length": int(getattr(packet, "length", 0)),
                "time": float(getattr(packet, "sniff_timestamp", 0.0)),
                "syn": str_to_int_flag(packet.tcp.flags_syn) if hasattr(packet, "tcp") else 0,
                "ack": str_to_int_flag(packet.tcp.flags_ack) if hasattr(packet, "tcp") else 0,
                "fin": str_to_int_flag(packet.tcp.flags_fin) if hasattr(packet, "tcp") else 0,
                "psh": str_to_int_flag(packet.tcp.flags_push) if hasattr(packet, "tcp") else 0,
                "fwd_hdr_len": int(getattr(packet.tcp, "len", 0)) if hasattr(packet, "tcp") else 0,
                "bwd_hdr_len": int(getattr(packet.tcp, "len", 0)) if hasattr(packet, "tcp") else 0
            }
            packets.append(pkt_dict)
        except Exception:
            continue
    return packets

# ----------------------------
# Convert packets to features
# ----------------------------
def packet_to_features(packet):
    features = {
        "pkt_size_min": packet["length"],
        "pkt_size_max": packet["length"],
        "pkt_size_mean": packet["length"],
        "pkt_size_std": 0,
        "flow_duration": 0,
        "flow_iat_mean": 0,
        "flow_iat_std": 0,
        "syn_flag_count": packet["syn"],
        "ack_flag_count": packet["ack"],
        "fin_flag_count": packet["fin"],
        "psh_flag_count": packet["psh"],
        "fwd_header_length": packet["fwd_hdr_len"],
        "bwd_header_length": packet["bwd_hdr_len"]
    }
    return pd.DataFrame([features])

# ----------------------------
# Load model and scaler
# ----------------------------
model = joblib.load("./results/xgboost_model.pkl")
scaler = joblib.load("./results/scaler.pkl")

# ----------------------------
# Classify packets
# ----------------------------
def classify_packets(packets):
    benign = 0
    malicious = 0
    for pkt in packets:
        try:
            X = packet_to_features(pkt)
            X_scaled = scaler.transform(X)
            pred = model.predict(X_scaled)[0]
            if pred == 0:
                benign += 1
            else:
                malicious += 1
        except Exception:
            continue
    return benign, malicious

# ----------------------------
# Global variable for dashboard
# ----------------------------
packets_data = []

# ----------------------------
# Main live IDS loop (CLI)
# ----------------------------
if __name__ == "__main__":
    try:
        interface = get_active_interface()
        print(f"🔴 Using active interface: {interface}")

        while True:
            try:
                packets = capture_live_packets(interface=interface, packet_count=50)
                benign, malicious = classify_packets(packets)

                # Store latest packets globally
                packets_data = packets

                print(f"\n📊 Last {len(packets)} packets results:")
                print(f"   ✅ Benign Packets   : {benign}")
                print(f"   🚨 Malicious Packets: {malicious}")

                time.sleep(2)

            except KeyboardInterrupt:
                print("\n🛑 Live IDS stopped by user.")
                break
    except Exception as e:
        print(f"⚠️ Error: {e}")
