import pyshark
cap = pyshark.LiveCapture(interface='Wi-Fi', bpf_filter='tcp')
cap.sniff(packet_count=10)
for pkt in cap:
    print(pkt)
