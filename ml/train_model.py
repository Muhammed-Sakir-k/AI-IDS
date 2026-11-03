import pandas as pd
import numpy as np
import glob
import joblib
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report

# -----------------------------
# Load ALL 8 datasets
# -----------------------------
all_files = glob.glob("MachineLearningCVE/*.csv")

print(f"Found {len(all_files)} CSV files. Loading...")

dfs = []
for f in all_files:
    print(f"  Loading: {f}")
    dfs.append(pd.read_csv(f, low_memory=False))

df = pd.concat(dfs, ignore_index=True)
print(f"\nTotal rows loaded: {len(df):,}")

# -----------------------------
# Clean data
# -----------------------------
df.columns = df.columns.str.strip()
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Show what attack types exist
print("\nAttack types in dataset:")
print(df["Label"].value_counts())

# -----------------------------
# Encode labels
# Multi-class: BENIGN, PortScan, DDoS, etc.
# -----------------------------
label_encoder = LabelEncoder()
df["Label"] = label_encoder.fit_transform(df["Label"])

# Save label mapping so detect.py can reverse it
label_mapping = dict(
    zip(label_encoder.transform(label_encoder.classes_),
        label_encoder.classes_)
)
print("\nLabel encoding map:")
print(label_mapping)

# Save the mapping alongside the model
joblib.dump(label_mapping, "dataset/models/label_mapping.pkl")

# -----------------------------
# Features
# -----------------------------
features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s"
]

X = df[features]
y = df["Label"]

# -----------------------------
# Train / Test Split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# -----------------------------
# XGBoost — multi-class
# -----------------------------
model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    eval_metric="mlogloss",
    random_state=42
)

print("\nTraining XGBoost on all datasets...")
model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("\nClassification Report:\n")
print(classification_report(
    y_test,
    predictions,
    target_names=label_encoder.classes_
))

# Save model
joblib.dump(model, "dataset/models/ids_model.pkl")
print("\nModel saved to dataset/models/ids_model.pkl")
print("Label map saved to dataset/models/label_mapping.pkl")