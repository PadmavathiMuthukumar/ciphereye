🔒 Encrypted Traffic Threat Detection with AI & Quantum-Safe Security
**📌 Project Overview**

This project focuses on detecting malicious patterns in encrypted network traffic without decrypting the payload. By leveraging metadata features and advanced ML models, the system ensures privacy preservation while enabling real-time threat detection.

To future-proof against post-quantum threats, a Quantum-Safe Security layer (QKD) is integrated, ensuring secure communication of model outputs.

**🚀 Project Workflow**

**1️⃣ Data Collection**

Dataset: CIC-IDS 2017 (Encrypted traffic dataset).

📖 Reference: [CIC-IDS 2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)


Tools: PyShark, custom packet captures.

Only metadata is collected (packet size, inter-arrival time, TLS handshake info).

✅ Payload remains private (no decryption needed).

**2️⃣ Feature Extraction**

* Packet size distribution

* Inter-arrival time

* Flow duration

* Number of packets per flow

* TLS handshake patterns

**3️⃣ Preprocessing**

Normalization & scaling

Handling class imbalance (malicious < normal)

Formatting for ML model input

**4️⃣ ML / AI Model Training & Comparison**
We evaluated five models on the dataset:
```
| Model               | Accuracy | Execution Time | Performance Notes                |
|----------------------|----------|----------------|----------------------------------|
| Logistic Regression  | Moderate | Fast           | Baseline model                   |
| Random Forest        | High     | Moderate       | Robust but heavier                |
| **XGBoost**          | **High** | **Fastest**    | ✅ Best overall (lightweight)    |
| LightGBM             | High     | Fast           | Competitive but slightly lower    |
| CatBoost             | High     | Moderate       | Strong on categorical features    |


```

➡️ XGBoost achieved the best results, offering higher accuracy, faster execution, and lightweight performance.

**5️⃣ Quantum-Safe Security Integration**

Quantum Key Distribution (QKD) is applied to transfer predicted outputs securely to the central SOC server.

Prevents hackers from tampering or intercepting predictions.

**6️⃣ Threat Detection Engine**

Real-time anomaly detection

Flags suspicious flows

Sends alerts securely to SOC

**7️⃣ Evaluation & Results**

Metrics: Accuracy, Precision, Recall, F1-score

XGBoost scored the highest accuracy with reduced execution time

Privacy fully preserved (no payload decryption)

**📊 Workflow Diagram**

```
Traffic Capture (PyShark / CIC-IDS 2017)
          ↓
   Feature Extraction (Metadata only)
          ↓
        Preprocessing
          ↓
  ML Model Comparison
 (LogReg / RF / XGBoost / LightGBM / CatBoost)
          ↓
   Best Model → XGBoost
          ↓
Quantum-Safe Security Layer (QKD)
          ↓
 Threat Detection Engine
          ↓
 Output: Benign / Malicious / Alert

```

```
📂 Repository Structure
├── data/                 # Raw datasets (CIC-IDS 2017)
├── features/             # Extracted features
├── processed/            # Preprocessed data
├── train_model.py        # ML model training & comparison
├── dashboard.py          # Results dashboard (Dash/Plotly)
├── results/              # Saved models, metrics
├── requirements.txt      # Dependencies
└── README.md             # Project documentation

```

**🛠️ Tech Stack**

Python: Pandas, Scikit-learn, XGBoost, LightGBM, CatBoost, PyTorch

Dash / Plotly: Dashboard & visualization

Wireshark: Traffic capture

Git LFS: Large dataset handling

Quantum-Safe Cryptography (QKD concepts)

**📢 Future Work**

Deploy the system on real-time network streams

Integrate with SOC dashboards (Splunk / ELK)

Explore hybrid classical + quantum ML for encrypted traffic

**✨ Highlight:**

XGBoost selected as the final model due to its higher accuracy, lightweight design, and faster execution.

QKD-secured communication ensures that model outputs are safe from interception and tampering.

**📤 Output:**

Below is the sample output screenshot from our trained XGBoost model:

![Output Screenshot](C:\Users\padma\ciphereye\results\output.png)

- The dashboard shows classification results.
- Alerts are generated for malicious flows.
- Predictions are securely transferred using QKD.

Below is the Confusion Matrix screenshot from our trained XGBoost model:

![Output Screenshot](C:\Users\padma\ciphereye\results\xgboost_confusion_matrix.png)
