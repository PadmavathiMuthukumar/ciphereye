# test_capture.py
from live_ids import get_active_interface, capture_live_packets, classify_packets

iface = get_active_interface()
print("Using interface:", iface)
pkts = capture_live_packets(interface=iface, packet_count=10)
print("Captured", len(pkts), "packets")
benign, malicious = classify_packets(pkts)
print("Benign:", benign, "Malicious:", malicious)
