import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models_store")
LATEST_PATH = os.path.join(MODELS_DIR, "iforest_latest.joblib")


class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names = []

    def fit(self, X, feature_names, contamination=0.05, n_estimators=100, random_state=42):
        self.feature_names = list(feature_names)
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
        )
        self.model.fit(X_scaled)
        return self

    def predict(self, X):
        """Return (labels, scores). label 1 = anomaly. Higher score = more anomalous."""
        X_scaled = self.scaler.transform(X)
        raw_labels = self.model.predict(X_scaled)        # -1 anomaly / +1 normal
        labels = (raw_labels == -1).astype(int)
        # decision_function applies offset: negative = anomalous, positive = normal
        # Invert so higher = more anomalous; boundary sits at 0
        scores = -self.model.decision_function(X_scaled)
        return labels, scores

    def save(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(
            {"model": self.model, "scaler": self.scaler, "feature_names": self.feature_names},
            path,
        )

    def load(self, path):
        artifact = joblib.load(path)
        self.model = artifact["model"]
        self.scaler = artifact["scaler"]
        self.feature_names = artifact["feature_names"]
        return self
