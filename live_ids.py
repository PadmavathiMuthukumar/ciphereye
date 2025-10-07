'''import pyshark
import pandas as pd
import joblib
import time
import psutil
import asyncio
import os
from pyshark.tshark.tshark import get_all_tshark_interfaces_names
print(get_all_tshark_interfaces_names())



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
    """Return a sensible default interface name that tshark/dumpcap recognizes.

    Strategy:
    - If the user provides INTERFACE env var or CLI later, that will be used by main.
    - Query psutil for interfaces that are up.
    - Query tshark for interface names it understands (aliases returned by `tshark -D`).
    - Prefer common physical interfaces (contain 'wi'/'eth'/'ethernet') and avoid loopback.
    - Fall back to the first intersection between psutil up interfaces and tshark-known names.
    """
    # Get psutil interfaces that are up
    interfaces = psutil.net_if_stats()
    up_ifaces = [iface for iface, stats in interfaces.items() if stats.isup]

    # Get names known to tshark (may include aliases like 'Wi-Fi', 'Ethernet')
    try:
        tshark_names = get_all_tshark_interfaces_names()
    except Exception:
        tshark_names = []

    # Normalize and try to find a match preferring physical NICs
    def score_name(name: str) -> int:
        n = name.lower()
        if 'loopback' in n or 'loop' in n or 'pseudo' in n:
            return 0
        if 'wi' in n or 'wireless' in n or 'wifi' in n:
            return 3
        if 'eth' in n or 'ethernet' in n or 'local area connection' in n:
            return 4
        return 2

    # Find intersection preserving scores
    candidates = []
    for u in up_ifaces:
        for t in tshark_names:
            # match by exact, substring or case-insensitive equality
            if u.lower() == t.lower() or u.lower() in t.lower() or t.lower() in u.lower():
                candidates.append((score_name(t), t))

    if candidates:
        # pick highest score
        candidates.sort(reverse=True)
        return candidates[0][1]

    # If tshark didn't match, try to return any up interface that isn't obviously loopback
    for u in up_ifaces:
        lu = u.lower()
        if 'loop' not in lu and 'pseudo' not in lu:
            return u

    # Last resort: if any interface exists, return the first one
    if up_ifaces:
        return up_ifaces[0]

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
'''
import pyshark
import pandas as pd
import joblib
import time
import psutil
import asyncio
import subprocess
from pyshark.tshark.tshark import get_all_tshark_interfaces_names

# Load the model and scaler
try:
    print("Loading model and scaler...")
    model = joblib.load("./results/xgboost_model.pkl")
    scaler = joblib.load("./results/scaler.pkl")
    print("Model and scaler loaded successfully")
except Exception as e:
    print(f"Error loading model or scaler: {str(e)}")
    raise

def str_to_int_flag(flag):
    """Convert 'True'/'False' strings from PyShark TCP flags to 1/0."""
    return 1 if flag == "True" else 0

def check_tshark_installation():
    """Check if TShark is properly installed and accessible."""
    import subprocess
    import os

    try:
        # Check standard Wireshark installation path
        wireshark_path = r"C:\Program Files\Wireshark"
        tshark_exe = os.path.join(wireshark_path, "tshark.exe")
        
        if not os.path.exists(tshark_exe):
            raise RuntimeError(
                "TShark not found. Please ensure Wireshark is installed with these steps:\n"
                "1. Download Wireshark from https://www.wireshark.org/download.html\n"
                "2. During installation, ensure 'TShark' is selected\n"
                "3. Add Wireshark to system PATH during installation\n"
                "4. Restart your computer after installation"
            )

        # Try running tshark to check if it works
        result = subprocess.run([tshark_exe, "-v"], 
                              capture_output=True, 
                              text=True,
                              check=True)
        return tshark_exe
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"TShark is installed but failed to run: {e}")
    except Exception as e:
        raise RuntimeError(f"Error checking TShark installation: {e}")

def get_active_interface():
    """Return the best available network interface for packet capture."""
    try:
        # First check if TShark is properly installed
        tshark_exe = check_tshark_installation()
        
        # Get interfaces that are up
        interfaces = psutil.net_if_stats()
        up_ifaces = [iface for iface, stats in interfaces.items() if stats.isup]
        
        # Get tshark interface names using the verified tshark executable
        try:
            # Use subprocess directly to get interfaces
            result = subprocess.run(
                [tshark_exe, "-D"],
                capture_output=True,
                text=True,
                check=True
            )
            tshark_names = [line.split('.')[1].strip() for line in result.stdout.splitlines()]
        except Exception as e:
            print(f"Warning: Could not get TShark interfaces: {e}")
            tshark_names = []

        # Score interfaces based on type
        def score_interface(name):
            name = name.lower()
            if 'wi' in name or 'wireless' in name:
                return 3
            if 'eth' in name or 'ethernet' in name:
                return 2
            if 'loopback' in name or 'loop' in name:
                return 0
            return 1

        # Find best interface
        best_interface = None
        best_score = -1

        for iface in up_ifaces:
            score = score_interface(iface)
            if score > best_score:
                best_score = score
                best_interface = iface

        if not best_interface:
            raise RuntimeError("No active network interface found")
        
        return best_interface

    except Exception as e:
        raise RuntimeError(f"Error finding active interface: {str(e)}")

def extract_features(packet):
    """Extract relevant features from a packet for ML prediction."""
    try:
        # Get basic packet info
        length = int(getattr(packet, "length", 0))
        timestamp = float(getattr(packet, "sniff_timestamp", 0.0))
        
        # Initialize TCP flags
        tcp_flags = {
            "syn": 0,
            "ack": 0,
            "fin": 0,
            "psh": 0,
            "rst": 0,
            "urg": 0
        }
        
        # Extract TCP information if available
        if hasattr(packet, "tcp"):
            tcp = packet.tcp
            try:
                # Get TCP flags from the flags field
                flags = getattr(tcp, "flags", "0x000")
                if isinstance(flags, str):
                    flags = int(flags, 16)
                else:
                    flags = int(flags)
                
                # Extract individual flags
                tcp_flags["syn"] = 1 if flags & 0x002 else 0  # SYN flag
                tcp_flags["ack"] = 1 if flags & 0x010 else 0  # ACK flag
                tcp_flags["fin"] = 1 if flags & 0x001 else 0  # FIN flag
                tcp_flags["psh"] = 1 if flags & 0x008 else 0  # PSH flag
                tcp_flags["rst"] = 1 if flags & 0x004 else 0  # RST flag
                tcp_flags["urg"] = 1 if flags & 0x020 else 0  # URG flag
            except Exception as e:
                print(f"Error parsing TCP flags: {e}")
            
            # Get header length
            header_length = int(getattr(tcp, "len", 0))
        else:
            header_length = 0

        # Create feature dictionary
        features = {
            # Packet size features
            "pkt_size_min": length,
            "pkt_size_max": length,
            "pkt_size_mean": length,
            "pkt_size_std": 0,  # Single packet, so std dev is 0
            
            # Flow timing features
            "flow_duration": timestamp,
            "flow_iat_mean": 0,  # Inter-arrival time needs multiple packets
            "flow_iat_std": 0,   # Standard deviation needs multiple packets
            
            # TCP flag counts
            "syn_flag_count": tcp_flags["syn"],
            "ack_flag_count": tcp_flags["ack"],
            "fin_flag_count": tcp_flags["fin"],
            "psh_flag_count": tcp_flags["psh"],
            
            # Header lengths
            "fwd_header_length": header_length,
            "bwd_header_length": header_length
        }
        
        # Add protocol information
        features["protocol"] = getattr(packet, "highest_layer", "UNKNOWN")
        
        # Add IP information if available
        if hasattr(packet, "ip"):
            features["src_ip"] = packet.ip.src
            features["dst_ip"] = packet.ip.dst
        
        print(f"Extracted features for packet: {features}")
        return features
        
    except Exception as e:
        print(f"Feature extraction error: {str(e)}")
        print(f"Packet summary: {packet.summary() if hasattr(packet, 'summary') else 'No summary available'}")
        return None

def capture_packets(interface, packet_count=50):
    """Capture and process network packets."""
    cap = None
    loop = None
    try:
        # Verify TShark installation first
        tshark_path = check_tshark_installation()
        print(f"Using TShark at: {tshark_path}")
        
        packets_data = []
        print(f"Starting capture on interface: {interface}")
        
        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Configure capture with specific display filters
        display_filter = "tcp"  # Focus on TCP packets
        cap = pyshark.LiveCapture(
            interface=interface,
            tshark_path=tshark_path,
            display_filter=display_filter,
            include_raw=True,
            use_json=True,
            output_file=None,  # Don't save to file
            eventloop=loop  # Use our event loop
        )
        print("LiveCapture object created successfully")
        
        # Start packet capture
        print(f"Starting packet capture on interface: {interface}")
        # Use sniff_continuously to get packets in real-time
        for packet in cap.sniff_continuously(packet_count=packet_count):
            try:
                features = extract_features(packet)
                if features:
                    # Make sure we have all required features
                    required_features = [
                        "pkt_size_min", "pkt_size_max", "pkt_size_mean", "pkt_size_std",
                        "flow_duration", "flow_iat_mean", "flow_iat_std",
                        "syn_flag_count", "ack_flag_count", "fin_flag_count", "psh_flag_count",
                        "fwd_header_length", "bwd_header_length"
                    ]
                    
                    # Create DataFrame with all required features
                    df = pd.DataFrame([features])
                    
                    # Ensure all required features exist
                    for feature in required_features:
                        if feature not in df.columns:
                            df[feature] = 0
                    
                    # Reorder columns to match training data
                    df = df[required_features]
                    
                    # Scale features
                    try:
                        X_scaled = scaler.transform(df)
                        
                        # Make prediction
                        pred = model.predict(X_scaled)[0]
                        features["label"] = "Benign" if pred == 0 else "Malicious"
                        
                        # Add packet info for display
                        features["time"] = time.strftime("%H:%M:%S")
                        packets_data.append(features)
                        
                        print(f"Processed packet: size={features['pkt_size_mean']}, "
                              f"label={features['label']}")
                              
                    except Exception as e:
                        print(f"Error in prediction: {str(e)}")
                        continue
                        
            except Exception as e:
                print(f"Error processing packet: {str(e)}")
                continue

        return packets_data

    except KeyboardInterrupt:
        print("\n🛑 Capture stopped by user")
        return packets_data
    except EOFError:
        print("\n🛑 Capture stream ended")
        return packets_data
    except Exception as e:
        print(f"Packet capture error: {str(e)}")
        return []
    finally:
        # Clean up resources
        if cap:
            try:
                cap.close()
            except:
                pass
        
        # Clean up event loop
        if loop:
            try:
                loop.stop()
                loop.close()
            except:
                pass

if __name__ == "__main__":
    try:
        # Get the active interface
        interface = get_active_interface()
        print(f"🔵 Selected active interface: {interface}")
        print("Press Ctrl+C to stop the capture...")

        while True:
            try:
                # Capture and analyze packets
                packets = capture_packets(interface=interface, packet_count=50)
                
                # Count results
                benign = sum(1 for p in packets if p["label"] == "Benign")
                malicious = sum(1 for p in packets if p["label"] == "Malicious")
                
                # Print results
                print(f"\n📊 Analysis of last {len(packets)} packets:")
                print(f"✅ Benign packets: {benign}")
                print(f"⚠️ Malicious packets: {malicious}")
                
                # Small delay before next capture
                time.sleep(2)
                
            except KeyboardInterrupt:
                print("\n🛑 Packet capture stopped by user")
                break
            except Exception as e:
                print(f"⚠️ Error during capture: {str(e)}")
                time.sleep(5)  # Wait before retrying
                continue
                
    except Exception as e:
        print(f"❌ Fatal error: {str(e)}")
