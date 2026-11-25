"""PayloadDetector: loads the best trained model and classifies one payload.

Used by the scanner (cart/lab.py) as a small DEMONSTRATION: for every attack the
scanner proved, ask the trained model "do you also see this payload as malicious?".
It is not an evaluation of the model (only a handful of payloads) — the model's
real results come from the test set in ml/train.py.
"""
from __future__ import annotations

from pathlib import Path

from .payload_features import vector

MODEL_PATH = Path("models/request_classifier/model.joblib")


class PayloadDetector:
    def __init__(self, clf=None, name=""):
        self.clf, self.name = clf, name
        self.ready = clf is not None

    @classmethod
    def load(cls, path=MODEL_PATH) -> "PayloadDetector":
        """Returns a detector with ready=False if the model has not been trained yet."""
        try:
            import joblib
            bundle = joblib.load(path)
            return cls(bundle["clf"], bundle.get("name", "model"))
        except Exception:
            return cls(None)

    def verdict(self, payload: str) -> dict:
        label = int(self.clf.predict([vector(payload)])[0])
        return {"malicious": bool(label), "model": self.name}
