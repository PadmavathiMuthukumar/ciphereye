import pandas as pd
from sklearn.utils import resample
import os
import random

# Paths
INPUT_FILE = "./merged_features/merged_features.csv"
OUTPUT_FILE = "./balanced_dataset/balanced_dataset.csv"


# Make sure the output folder exists
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

# Load merged dataset
df = pd.read_csv(INPUT_FILE)
print(df.head())
# Convert labels to numeric (Benign=0, Attack=1)
df['label'] = df['label'].apply(lambda x: 0 if x == 'Benign' else 1)

# Check label counts before balancing
print("Before balancing:")
print(df['label'].value_counts())

# Separate majority and minority classes (now using numbers)
df_benign = df[df['label'] == 0]
df_attack = df[df['label'] == 1]

# Decide a slightly random limit for attack samples (e.g., ~200k ± 1000)
target_attack_size = random.randint(199000, 201000)
print(f"\n🔹 Target attack size: {target_attack_size}")

# Downsample attack if it is larger than target size
if len(df_attack) > target_attack_size:
    df_attack = df_attack.sample(n=target_attack_size, random_state=42)
else:
    target_attack_size = len(df_attack)  # keep full attack size if already smaller

# Undersample benign to match attack size
df_benign_downsampled = resample(df_benign,
                                 replace=False,
                                 n_samples=target_attack_size,
                                 random_state=42)

# Combine and shuffle
df_balanced = pd.concat([df_benign_downsampled, df_attack])
df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)

# Save balanced dataset
df_balanced.to_csv(OUTPUT_FILE, index=False)

# Check label counts after balancing
print("\nAfter balancing:")
print("Benign vs Attack counts:")
print("Benign = 0 | Attack = 1")
print(df_balanced['label'].value_counts())

print(f"\nBalanced dataset saved to {OUTPUT_FILE}")
