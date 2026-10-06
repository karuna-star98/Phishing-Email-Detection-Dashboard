"""Load the trained model and return a phishing probability (0-1). Optional: the app works without it."""
import os

import joblib
import pandas as pd

from backend.services.feature_extractor import ML_FEATURE_COLS

DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "phishing_model.joblib")


class PhishingMLModel:
    def __init__(self, path=DEFAULT_PATH):
        self.bundle = None
        try:
            self.bundle = joblib.load(path)
        except Exception:  # missing/corrupt model -> ML simply stays disabled
            self.bundle = None

    @property
    def available(self) -> bool:
        return self.bundle is not None

    @property
    def name(self) -> str:
        return self.bundle["name"] if self.bundle else "none"

    def predict_proba(self, clean_text: str, features: dict) -> float:
        row = {"text": clean_text, **{c: features[c] for c in ML_FEATURE_COLS}}
        return round(float(self.bundle["pipeline"].predict_proba(pd.DataFrame([row]))[0, 1]), 4)
