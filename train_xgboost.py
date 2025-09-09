import pandas as pd
import os
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
from xgboost import XGBClassifier

# Paths
TRAIN_FILE = "./train_dataset/train.csv"
TEST_FILE = "./test_dataset/test.csv"
MODEL_FILE = "./results/xgboost_model.pkl"
CONF_MATRIX_FILE = "./results/xgboost_confusion_matrix.png"

# Create results folder
os.makedirs("./results", exist_ok=True)

# Load datasets
train_df = pd.read_csv(TRAIN_FILE)
test_df = pd.read_csv(TEST_FILE)

# Features and labels
X_train = train_df.drop(columns=["label"])
y_train = train_df["label"].map({"Benign": 0, "Attack": 1})  # Encode labels as 0/1
X_test = test_df.drop(columns=["label"])
y_test = test_df["label"].map({"Benign": 0, "Attack": 1})

# Scale features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# ------------------------
# Train XGBoost Model
# ------------------------
print("\n🔹 Training XGBoost...")
model = XGBClassifier(eval_metric="logloss", use_label_encoder=False, random_state=42)
model.fit(X_train, y_train)

# Save the model & scaler
joblib.dump(model, MODEL_FILE)
joblib.dump(scaler, "./results/scaler.pkl")
print(f"✅ Model saved to {MODEL_FILE}")

# ------------------------
# Load Model & Evaluate
# ------------------------
print("\n🔹 Loading saved model...")
loaded_model = joblib.load(MODEL_FILE)
scaler = joblib.load("./results/scaler.pkl")

y_pred = loaded_model.predict(X_test)

# Metrics
acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print(f"\n✅ XGBoost Results (Loaded Model):")
print(f"   Accuracy : {acc:.4f}")
print(f"   Precision: {prec:.4f}")
print(f"   Recall   : {rec:.4f}")
print(f"   F1-score : {f1:.4f}")

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=["Benign", "Attack"], yticklabels=["Benign", "Attack"])
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("XGBoost Confusion Matrix Heatmap (Loaded Model)")
plt.savefig(CONF_MATRIX_FILE)
plt.show()
print(f"📊 Confusion Matrix Heatmap saved to {CONF_MATRIX_FILE}")
