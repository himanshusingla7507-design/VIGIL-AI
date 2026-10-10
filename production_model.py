"""Stable pickle interface for the production calibrated URL classifier."""
import numpy as np


class ProbabilityCalibratedModel:
    def __init__(self, estimator, calibrator):
        self.estimator = estimator
        self.calibrator = calibrator
        self.classes_ = np.array([0, 1])
        self.n_features_in_ = int(getattr(estimator, "n_features_in_", 0) or 0)

    def predict_proba(self, X):
        raw = self.estimator.predict_proba(X)[:, list(self.estimator.classes_).index(1)]
        probability = self.calibrator.predict_proba(raw.reshape(-1, 1))[:, 1]
        return np.column_stack([1.0 - probability, probability])
