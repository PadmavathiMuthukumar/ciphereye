import pandas as pd
import os
from sklearn.model_selection import train_test_split

# Input balanced dataset
INPUT_FILE = "./balanced_dataset/balanced_dataset.csv"

# Output folders
TRAIN_DIR = "./train_dataset/"
TEST_DIR = "./test_dataset/"

# Create output directories if they don't exist
os.makedirs(TRAIN_DIR, exist_ok=True)
os.makedirs(TEST_DIR, exist_ok=True)

# Load balanced dataset
df = pd.read_csv(INPUT_FILE)

# Split into train and test (80% train, 20% test) with stratification
train_df, test_df = train_test_split(
    df,
    test_size=0.2,
    stratify=df['label'],   # ensures same ratio of Attack/Benign
    random_state=42
)

# Save the splits
train_file = os.path.join(TRAIN_DIR, "train.csv")
test_file = os.path.join(TEST_DIR, "test.csv")

train_df.to_csv(train_file, index=False)
test_df.to_csv(test_file, index=False)

print(f"✅ Train dataset saved to {train_file}")
print(f"✅ Test dataset saved to {test_file}")

# Show class counts to confirm balance
print("\n🔹 Training set label counts:")
print(train_df['label'].value_counts())

print("\n🔹 Testing set label counts:")
print(test_df['label'].value_counts())

# Proper balance check
if train_df['label'].value_counts()[0] == train_df['label'].value_counts()[1]:
    print("\n✅ Training set is perfectly balanced (equal Attack & Benign).")
else:
    print("\n⚠️ Training set is not balanced!")

if test_df['label'].value_counts()[0] == test_df['label'].value_counts()[1]:
    print("✅ Test set is perfectly balanced (equal Attack & Benign).")
else:
    print("⚠️ Test set is not balanced!")
