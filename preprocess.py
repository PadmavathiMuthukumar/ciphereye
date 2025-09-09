# preprocess_parquet.py
import os
import pandas as pd
import numpy as np

RAW_DIR = "./data/"
PROC_DIR = "./processed/"
os.makedirs(PROC_DIR, exist_ok=True)

# Define the features to keep
FEATURE_COLUMNS = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Fwd Packet Length Max', 'Fwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Max', 'Packet Length Min',
    'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'SYN Flag Count', 'ACK Flag Count', 'FIN Flag Count', 'PSH Flag Count',
    'Fwd Header Length', 'Bwd Header Length',
    'Label'
]

def preprocess_dataset(file_path, save=True):
    # Read Parquet file
    df = pd.read_parquet(file_path)

    # Drop duplicates and NA
    df = df.drop_duplicates().dropna()

    # Convert numeric columns where possible
    for col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="ignore")

    # Detect label column
    label_col = None
    for col_name in ["Label", "Category", "FlowLabel"]:
        if col_name in df.columns:
            label_col = col_name
            break

    if label_col:
        df[label_col] = df[label_col].replace({"BENIGN": 0, "ATTACK": 1})
        df.rename(columns={label_col: "Label"}, inplace=True)
    else:
        print(f"⚠️ No label column found in {file_path}")
    
    # Keep only wanted columns if they exist
    keep_cols = [col for col in FEATURE_COLUMNS if col in df.columns]
    df = df[keep_cols]

    # Save processed CSV
    if save:
        fname = os.path.basename(file_path).replace(" ", "_").replace(".parquet", ".csv")
        out_path = os.path.join(PROC_DIR, fname)
        df.to_csv(out_path, index=False)
        print(f"✅ Saved processed dataset: {out_path}")

    return df

if __name__ == "__main__":
    files = [f for f in os.listdir(RAW_DIR) if f.endswith(".parquet")]
    if not files:
        print("⚠️ No Parquet files found in ./data/")
    for f in files:
        preprocess_dataset(os.path.join(RAW_DIR, f))
