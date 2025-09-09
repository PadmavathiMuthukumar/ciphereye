import os
import pandas as pd
from sklearn.model_selection import cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from catboost import CatBoostClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import numpy as np

# ---------------------------
# File paths
# ---------------------------
TRAIN_FILE = "./train_dataset/train.csv"
TEST_FILE = "./test_dataset/test.csv"
OUTPUT_CSV = "./dashboard_csvfiles/model_results.csv"

# ---------------------------
# Load datasets
# ---------------------------
train_df = pd.read_csv(TRAIN_FILE)
test_df = pd.read_csv(TEST_FILE)

y_train = train_df["label"].values
y_test = test_df["label"].values

X_train = train_df.drop(columns=["label"])
X_test = test_df.drop(columns=["label"])

# ---------------------------
# Scale features
# ---------------------------
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# ---------------------------
# Models to train
# ---------------------------
attack_label = 1
models = {
    "Logistic Regression": LogisticRegression(max_iter=1000),
    "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
    "XGBoost": XGBClassifier(eval_metric="logloss"),
    "LightGBM": LGBMClassifier(random_state=42),
    "CatBoost": CatBoostClassifier(verbose=0, random_state=42)
}

# ---------------------------
# Train models and collect results
# ---------------------------
results_list = []

for name, model in models.items():
    print(f"\n🔹 Training {name}...")

    # Cross-validation
    cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring="accuracy")
    print(f"   CV Accuracy: {np.mean(cv_scores):.4f} ± {np.std(cv_scores):.4f}")

    # Train on full training data
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    # Calculate metrics
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, pos_label=attack_label)
    rec = recall_score(y_test, y_pred, pos_label=attack_label)
    f1 = f1_score(y_test, y_pred, pos_label=attack_label)

    print(f"✅ {name} Results: Accuracy={acc:.4f}, Precision={prec:.4f}, Recall={rec:.4f}, F1={f1:.4f}")

    # Append results
    results_list.append({
        "Model": name,
        "Accuracy": acc,
        "Precision": prec,
        "Recall": rec,
        "F1-score": f1
    })

# ---------------------------
# Save results to CSV
# ---------------------------
# Ensure folder exists
os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)

# Save
results_df = pd.DataFrame(results_list)
results_df.to_csv(OUTPUT_CSV, index=False)
print(f"\n✅ Results saved to {OUTPUT_CSV}")
