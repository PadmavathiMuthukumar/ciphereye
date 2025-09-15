'''from flask import Flask, render_template, jsonify
from live_ids import capture_live_packets, classify_packets, get_active_interface
import threading
import time

app = Flask(__name__)

# ----------------------------
# Global variables to store IDS data
# ----------------------------
data = {
    "benign_total": 0,
    "malicious_total": 0,
    "packets": []
}

# ----------------------------
# Live IDS capture thread
# ----------------------------
def live_capture():
    iface = get_active_interface()
    while True:
        try:
            packets = capture_live_packets(interface=iface, packet_count=10)
            benign, malicious = classify_packets(packets)
            data["benign_total"] += benign
            data["malicious_total"] += malicious
            data["packets"] = []

            for pkt in packets:
                pred = "Benign ✅" if (pkt["syn"]+pkt["ack"]+pkt["fin"]+pkt["psh"]) == 0 else "Attack 🚨"
                data["packets"].append({
                    "length": pkt["length"],
                    "SYN": pkt["syn"],
                    "ACK": pkt["ack"],
                    "FIN": pkt["fin"],
                    "PSH": pkt["psh"],
                    "Prediction": pred
                })

            time.sleep(2)  # capture interval
        except Exception as e:
            print("Error in live_capture:", e)
            time.sleep(2)

# Start capture thread
threading.Thread(target=live_capture, daemon=True).start()

# ----------------------------
# Routes
# ----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/live_data")
def live_data():
    return jsonify(data)

if __name__ == "__main__":
    app.run(debug=True)
'''
from flask import Flask, render_template, jsonify
import random

app = Flask(__name__)

# -----------------------------
# Simulated Packet IDS Results
# -----------------------------
def capture_packets():
    packets = []
    benign_total, malicious_total = 0, 0

    for _ in range(10):  # capture 10 packets at a time
        length = random.randint(50, 200)
        syn = random.randint(0, 1)
        ack = random.randint(0, 1)
        fin = random.randint(0, 1)
        psh = random.randint(0, 1)

        prediction = "Attack 🚨" if (syn + ack + fin + psh) > 1 else "Benign ✅"

        if "Attack" in prediction:
            malicious_total += 1
        else:
            benign_total += 1

        packets.append({
            "length": length,
            "SYN": syn,
            "ACK": ack,
            "FIN": fin,
            "PSH": psh,
            "Prediction": prediction
        })

    return packets, benign_total, malicious_total


# -----------------------------
# QKD Simulation (BB84 Protocol - simplified)
# -----------------------------
def simulate_qkd(n_bits=20):
    sender_bits = [random.randint(0, 1) for _ in range(n_bits)]
    sender_bases = [random.choice(['Z', 'X']) for _ in range(n_bits)]
    receiver_bases = [random.choice(['Z', 'X']) for _ in range(n_bits)]

    key = []
    for i in range(n_bits):
        if sender_bases[i] == receiver_bases[i]:
            key.append(sender_bits[i])
    return key


# -----------------------------
# Flask Routes
# -----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/data")
def data():
    packets, benign, malicious = capture_packets()
    qkd_key = simulate_qkd(16)  # simulate 16-bit QKD key
    return jsonify({
        "benign_total": benign,
        "malicious_total": malicious,
        "packets": packets,
        "qkd_key": qkd_key
    })


if __name__ == "__main__":
    app.run(debug=True)
