import os
import pandas as pd
import numpy as np

PROCESSED_DIR = "./processed/"
FEATURES_DIR = "./features/"
os.makedirs(FEATURES_DIR, exist_ok=True)

def extract_features(df):
    """
    Extract features for each row (flow) individually.
    """
    features = pd.DataFrame()
    
    # Packet size features
    if "PacketLength" in df.columns:
        features["pkt_size_min"] = df["PacketLength"]
        features["pkt_size_max"] = df["PacketLength"]
        features["pkt_size_mean"] = df["PacketLength"]
        features["pkt_size_std"] = df["PacketLength"]
    elif "Packet Length Min" in df.columns:  # Example column from your dataset
        features["pkt_size_min"] = df["Packet Length Min"]
        features["pkt_size_max"] = df["Packet Length Max"]
        features["pkt_size_mean"] = df["Packet Length Mean"]
        features["pkt_size_std"] = df["Packet Length Std"]

    # Flow duration
    if "Flow Duration" in df.columns:
        features["flow_duration"] = df["Flow Duration"]

    # Inter-arrival time (if available)
    if "Flow IAT Mean" in df.columns:
        features["flow_iat_mean"] = df["Flow IAT Mean"]
        features["flow_iat_std"] = df["Flow IAT Std"]

    # TCP Flags
    if "SYN Flag Count" in df.columns:
        features["syn_flag_count"] = df["SYN Flag Count"]
        features["ack_flag_count"] = df["ACK Flag Count"]
        features["fin_flag_count"] = df["FIN Flag Count"]
        features["psh_flag_count"] = df["PSH Flag Count"]

    # Header lengths
    if "Fwd Header Length" in df.columns:
        features["fwd_header_length"] = df["Fwd Header Length"]
        features["bwd_header_length"] = df["Bwd Header Length"]

    # Label
    if "Label" in df.columns:
        features["label"] = df["Label"]

    return features

def process_all_files():
    files = [f for f in os.listdir(PROCESSED_DIR) if f.endswith(".csv")]
    for f in files:
        df = pd.read_csv(os.path.join(PROCESSED_DIR, f))
        features_df = extract_features(df)
        features_df.to_csv(os.path.join(FEATURES_DIR, f), index=False)
        print(f"✅ Features extracted and saved: {f}")

if __name__ == "__main__":
    process_all_files()
