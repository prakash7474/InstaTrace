from __future__ import annotations

import os
import joblib
from typing import Dict, Any, Optional

import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    """Isolation Forest based traffic anomaly scoring.

    Note: This uses only simple metadata-derived numeric proxies.
    """

    def __init__(self, logger, model_path: str = "./reports/isolation_forest.joblib") -> None:
        self.logger = logger
        self.model_path = model_path
        self.model: Optional[IsolationForest] = None

        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
            except Exception:
                self.model = None

        # Default model-less scoring
        if self.model is None:
            self.model = None

    def _vector(self, features: Dict[str, Any]) -> np.ndarray:
        return np.array(
            [[
                float(features.get("packet_len", 0) or 0),
                float(features.get("has_tls", 0) or 0),
                float(features.get("has_dns", 0) or 0),
                float(features.get("has_http", 0) or 0),
            ]],
            dtype=float,
        )

    def score(self, features: Dict[str, Any]) -> float:
        if self.model is None:
            return 0.0

        x = self._vector(features)
        # IsolationForest: decision_function higher is normal; anomalies => lower
        score = float(self.model.decision_function(x)[0])
        return score

    def train_and_persist(self) -> None:
        os.makedirs(os.path.dirname(self.model_path) or "./reports", exist_ok=True)

        # Generate synthetic baseline metadata (safe for demo; no packet content)
        rng = np.random.default_rng(42)
        X = []
        for _ in range(3000):
            packet_len = rng.integers(40, 1500)
            has_tls = rng.integers(0, 2)
            has_dns = rng.integers(0, 2)
            has_http = rng.integers(0, 2)
            # Mild correlation: TLS tends to have slightly larger packets
            if has_tls and rng.random() < 0.7:
                packet_len = min(1500, int(packet_len + rng.integers(0, 200)))
            X.append([packet_len, has_tls, has_dns, has_http])

        X = np.array(X, dtype=float)

        model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
        model.fit(X)
        joblib.dump(model, self.model_path)

        # Also create a simple README entry in logs
        self.logger.log_alert(f"ML model trained + saved at {self.model_path}")

