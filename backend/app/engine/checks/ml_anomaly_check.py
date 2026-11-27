"""
Check 8: IsolationForestCheck (Feature 12)
Machine Learning anomaly detection.
Uses scikit-learn IsolationForest if available, or algorithmic z-score multivariate
isolation fallback to compute multidimensional deviation.
"""
from typing import Optional
import numpy as np
from backend.app.engine.base_check import RiskCheck, CheckResult
from backend.app.domain.transaction import Transaction
from backend.app.domain.customer import CustomerProfile


class IsolationForestCheck(RiskCheck):
    def __init__(self, weight: float = 10.0):
        super().__init__(
            name="IsolationForestCheck",
            weight=weight,
            signal_origin="ML_ANOMALY_DETECTOR"
        )
        self._model = None
        self._init_model()

    def _init_model(self):
        try:
            from sklearn.ensemble import IsolationForest
            # Pre-train a light synthetic baseline representing normal customer distributions
            # Features: [normalized_amount, hour_of_day, failed_logins, is_new_device]
            rng = np.random.RandomState(42)
            normal_amounts = rng.normal(loc=5000, scale=3000, size=(200, 1))
            normal_hours = rng.uniform(8, 22, size=(200, 1))
            normal_failed_logins = rng.choice([0, 1], size=(200, 1), p=[0.9, 0.1])
            normal_new_device = np.zeros((200, 1))
            
            X_train = np.hstack([normal_amounts, normal_hours, normal_failed_logins, normal_new_device])
            clf = IsolationForest(n_estimators=50, contamination=0.05, random_state=42)
            clf.fit(X_train)
            self._model = clf
        except Exception:
            # Fallback if sklearn is not installed
            self._model = None

    def evaluate(self, transaction: Transaction, profile: CustomerProfile) -> CheckResult:
        amount = transaction.amount
        hour = transaction.timestamp.hour
        failed_logins = transaction.failed_logins_prior
        is_new_device = 0 if profile.is_device_known(transaction.device_id) else 1

        feature_vector = np.array([[amount, hour, failed_logins, is_new_device]], dtype=float)

        raw_score = 0.0
        ml_score_detail = 0.0

        if self._model is not None:
            try:
                # decision_function gives negative score for outliers, positive for inliers
                decision = self._model.decision_function(feature_vector)[0]
                ml_score_detail = float(decision)
                if decision < -0.15:
                    raw_score = 1.0
                elif decision < 0.0:
                    raw_score = 0.60
                elif decision < 0.10:
                    raw_score = 0.25
                else:
                    raw_score = 0.0
            except Exception:
                raw_score = 0.0
        else:
            # Algorithmic Isolation Fallback
            # Multi-dimensional distance metric
            z_amount = max(0.0, (amount - profile.avg_amount) / max(1.0, profile.avg_amount))
            time_pen = 1.0 if not profile.is_within_typical_hours(hour) else 0.0
            login_pen = min(1.0, failed_logins / 3.0)
            dev_pen = float(is_new_device)

            composite = (0.4 * z_amount) + (0.2 * time_pen) + (0.2 * login_pen) + (0.2 * dev_pen)
            raw_score = min(1.0, max(0.0, composite))
            ml_score_detail = round(float(composite), 3)

        triggered = raw_score > 0.40
        reason = (
            f"Isolation Forest identified high multi-dimensional anomaly (Score: {ml_score_detail:.3f})."
            if triggered
            else f"Transaction falls within statistical normal distribution cluster (Score: {ml_score_detail:.3f})."
        )

        return CheckResult(
            check_name=self.name,
            weight=self.weight,
            raw_score=raw_score,
            score_contribution=round(raw_score * self.weight, 2),
            triggered=triggered,
            signal_origin=self.signal_origin,
            reason=reason,
            evidence={
                "features": {
                    "amount": amount,
                    "hour": hour,
                    "failed_logins": failed_logins,
                    "is_new_device": is_new_device
                },
                "anomaly_index": round(ml_score_detail, 4),
                "model_engine": "scikit-learn" if self._model else "algorithmic-isolation-fallback"
            }
        )
