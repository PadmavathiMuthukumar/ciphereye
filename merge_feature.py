import pandas as pd
import os

FEATURES_DIR = "./features/"
OUTPUT_DIR = "./merged_features/"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "merged_features.csv")

# Create output directory if it doesn't exist
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# List all CSV files in features folder
files = [f for f in os.listdir(FEATURES_DIR) if f.endswith(".csv")]

dfs = []
for f in files:
    df = pd.read_csv(os.path.join(FEATURES_DIR, f))
    dfs.append(df)

# Concatenate all dataframes
merged_df = pd.concat(dfs, ignore_index=True)

# Save merged CSV
merged_df.to_csv(OUTPUT_FILE, index=False)
print(f"Merged dataset saved to {OUTPUT_FILE}")

# Show count of each label
print(merged_df['label'].value_counts())
