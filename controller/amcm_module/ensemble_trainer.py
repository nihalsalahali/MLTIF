#!/usr/bin/env python3
"""
FLARE AFAC Ensemble Trainer
=============================
- Loads IoMT dataset (CSV)
- Trains multiple base classifiers
- Builds stacked ensemble with meta-learner
- Saves models to afac/models/
"""

import pandas as pd
import numpy as np
import os
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, accuracy_score

# Config
DATASET_PATH = 'datasets/CICIoMT2024.csv'
MODEL_DIR = 'afac/models/'

if not os.path.exists(MODEL_DIR):
    os.makedirs(MODEL_DIR)

# Load dataset
print(f"📂 Loading dataset: {DATASET_PATH}")
df = pd.read_csv(DATASET_PATH)

print(f"✅ Dataset shape: {df.shape}")

# Example: Assume last column is label
X = df.iloc[:, :-1]
y = df.iloc[:, -1]

# Encode labels if categorical
if y.dtype == 'O':
    le = LabelEncoder()
    y = le.fit_transform(y)

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Scale features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Save scaler
joblib.dump(scaler, os.path.join(MODEL_DIR, 'scaler.joblib'))

print("⚙️ Training base classifiers...")

# Base learners
base_learners = [
    ('knn', KNeighborsClassifier(n_neighbors=5)),
    ('dt', DecisionTreeClassifier(max_depth=10)),
    ('rf', RandomForestClassifier(n_estimators=100)),
    ('svm', SVC(probability=True)),
    ('xgb', XGBClassifier(use_label_encoder=False, eval_metric='logloss'))
]

# Train & save each
for name, clf in base_learners:
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"✅ {name} accuracy: {acc:.4f}")

    joblib.dump(clf, os.path.join(MODEL_DIR, f"{name}.joblib"))

# Meta-learner
meta_learner = MLPClassifier(hidden_layer_sizes=(64, 32), activation='relu', max_iter=200)

# Stacking classifier
ensemble = StackingClassifier(
    estimators=base_learners,
    final_estimator=meta_learner,
    passthrough=True,
    cv=5
)

print("⚙️ Training stacked ensemble...")
ensemble.fit(X_train, y_train)
y_pred = ensemble.predict(X_test)
print(classification_report(y_test, y_pred))

# Save ensemble
joblib.dump(ensemble, os.path.join(MODEL_DIR, "ensemble.joblib"))

print("✅ Models saved to:", MODEL_DIR)
