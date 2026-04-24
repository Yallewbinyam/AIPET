"""
AIPET X — SHAP Explainer for Isolation Forest

Provides per-feature Shapley value explanations for anomaly predictions.

Explainer selection (at build time):
  1. shap.TreeExplainer  — fast (~15ms/sample after init), natively supports
     IsolationForest. Preferred.
  2. shap.KernelExplainer — model-agnostic fallback. Uses 100 synthetic
     normal-class samples as the background distribution. Slower (~30ms at
     nsamples=100) but correct.

Sign convention (consistent with our inverted raw_score):
  shap_value > 0 → this feature pushes the prediction toward ANOMALOUS
  shap_value < 0 → this feature pushes the prediction toward NORMAL

For TreeExplainer, which computes contributions to IsolationForest's
decision_function (higher = more normal), we negate the values so the sign
matches our raw_score = -decision_function.

Module-level cache (_explainer_cache) stores one AnomalyExplainer per model
version ID. Old entries stay in memory until the process restarts; they are
simply never looked up again once a new version becomes active. This is safe
because the cache is small (one explainer object per model version, and we
only ever have a handful of versions active over the lifetime of the process).
"""
from __future__ import annotations

import numpy as np
import shap

from dashboard.backend.ml_anomaly.features import FEATURE_ORDER

# Module-level cache: version_id (int) -> AnomalyExplainer
_explainer_cache: dict[int, "AnomalyExplainer"] = {}


def get_explainer(version_id: int, detector) -> "AnomalyExplainer":
    """Return a cached explainer for this model version, building it if needed."""
    if version_id not in _explainer_cache:
        _explainer_cache[version_id] = AnomalyExplainer(detector)
    return _explainer_cache[version_id]


def clear_cache() -> None:
    """Evict all cached explainers. Called when a new model version is trained."""
    _explainer_cache.clear()


class AnomalyExplainer:
    """SHAP explainer wrapper for a trained AnomalyDetector.

    Build with a detector instance; the explainer is tied to that model
    and scaler for the rest of its lifetime.
    """

    def __init__(self, detector):
        self.detector = detector
        self.feature_names = list(FEATURE_ORDER)

        try:
            self._inner = shap.TreeExplainer(detector.model)
            self.explainer_type = "tree"
        except Exception:
            # KernelExplainer path — build background from synthetic normal class.
            # 100 rows is enough for stable estimates; nsamples=100 at explain time.
            from dashboard.backend.ml_anomaly.training_data import generate_synthetic

            X_bg, y_bg = generate_synthetic(n_normal=5000, n_anomalous=250, seed=42)
            X_normal_scaled = detector.scaler.transform(X_bg[y_bg == 0][:100])

            # Score function matches our inverted raw_score convention:
            # positive output = more anomalous.
            def _score_fn(X_scaled):
                return -detector.model.decision_function(X_scaled)

            self._inner = shap.KernelExplainer(_score_fn, X_normal_scaled)
            self.explainer_type = "kernel"

    def explain(self, vec_raw: np.ndarray) -> list[dict]:
        """SHAP explanation for a single raw feature vector.

        Args:
            vec_raw: 1-D array of 12 raw (unscaled) feature values.

        Returns:
            List of 12 dicts sorted by |shap_value| descending.
            Each dict: {feature, shap_value, raw_value, direction}.
        """
        x_scaled = self.detector.scaler.transform(vec_raw.reshape(1, -1))
        return self._compute(x_scaled, vec_raw.reshape(1, -1))[0]

    def explain_batch(self, X_raw: np.ndarray) -> list[list[dict]]:
        """Batched explanation for N samples. X_raw shape: (N, 12)."""
        X_scaled = self.detector.scaler.transform(X_raw)
        return self._compute(X_scaled, X_raw)

    def _compute(
        self, X_scaled: np.ndarray, X_raw: np.ndarray
    ) -> list[list[dict]]:
        if self.explainer_type == "tree":
            raw_shap = np.array(self._inner.shap_values(X_scaled))
            # Some shap versions return (n_outputs, n_samples, n_features);
            # others return (n_samples, n_features). Normalise to 2-D.
            if raw_shap.ndim == 3:
                raw_shap = raw_shap[0]
            # Negate: TreeExplainer gives contributions to decision_function
            # (higher = more normal). Negating aligns with our inverted score
            # where positive = more anomalous.
            shap_vals = -raw_shap
        else:
            shap_vals = np.array(
                self._inner.shap_values(X_scaled, nsamples=100, silent=True)
            )

        results = []
        for i in range(len(X_scaled)):
            row = []
            for j, feat in enumerate(self.feature_names):
                sv = float(shap_vals[i, j])
                row.append({
                    "feature":   feat,
                    "shap_value": round(sv, 6),
                    "raw_value":  round(float(X_raw[i, j]), 6),
                    "direction":  (
                        "increases_anomaly" if sv > 0 else "decreases_anomaly"
                    ),
                })
            row.sort(key=lambda d: abs(d["shap_value"]), reverse=True)
            results.append(row)
        return results
