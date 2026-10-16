"""End-to-end Social Engineering detector - the component's public interface.

    Chat message -> preprocess -> text classifier (P)
                              -> manipulation detector (U, A, F)
                              -> pattern detector (R)
                              -> severity scorer (S, level) -> result (+ alert)

``SEDetector.analyze(message)`` returns the JSON-serialisable result defined in
docs/INTEGRATION_CONTRACT.md. This is what the shared Data Acquisition layer
calls and what the Behavioral Analytics engine / dashboard consume.
"""
from __future__ import annotations

import time
import uuid
from pathlib import Path

import joblib
import numpy as np

from . import manipulation, patterns, severity
from .preprocess import clean

MAX_CHARS = 2000            # chat messages are short; cap protects latency (NFR01) and memory
COMPONENT = "social_engineering"
DEFAULT_MODEL = Path(__file__).resolve().parent.parent / "models" / "se_detector.joblib"


class SEDetector:
    def __init__(self, model_path: str | Path = DEFAULT_MODEL):
        bundle = joblib.load(model_path)
        self.text_model = bundle["text_model"]
        self.weights: dict[str, float] = bundle["weights"]
        self.tau: float = bundle["tau"]
        self.version: str = bundle["version"]

    # ---- feature extraction (shared by training, evaluation and serving) ----
    def signals(self, message: str) -> dict:
        c = clean((message or "")[:MAX_CHARS])
        p = float(self.text_model.predict_proba([c.text])[0, 1]) if c.text else 0.0
        m = manipulation.detect(c.text)
        r = patterns.detect(c.text, c.urls)
        x = {"P": p, "U": m["scores"]["urgency"], "A": m["scores"]["authority"],
             "F": m["scores"]["fear"], "R": r["risk"]}
        return {"clean": c, "x": x, "manipulation": m, "patterns": r}

    def analyze(self, message: str, message_id: str | None = None, user_id: str | None = None,
                channel_id: str | None = None) -> dict:
        t0 = time.perf_counter()
        sig = self.signals(message)
        x = sig["x"]
        s = float(severity.score(x, self.weights))
        lvl = severity.level(s, self.tau)
        is_se = s >= self.tau
        tactics = sig["manipulation"]["tactics"]
        pats = sig["patterns"]["patterns"]
        return {
            "component": COMPONENT,
            "model_version": self.version,
            "message_id": message_id or str(uuid.uuid4()),
            "user_id": user_id,
            "channel_id": channel_id,
            "is_social_engineering": bool(is_se),
            "phishing_probability": round(x["P"], 4),
            "manipulation": {
                "tactics": tactics,
                "scores": sig["manipulation"]["scores"],
                "evidence": sig["manipulation"]["evidence"],
            },
            "patterns": {"detected": pats, "evidence": sig["patterns"]["evidence"], "risk": x["R"]},
            "urls": sig["clean"].urls,          # forwarded to the URL-verification component
            "severity": {
                "score": round(s, 4),
                "level": lvl,
                "threshold": self.tau,
                "contributions": severity.contributions(x, self.weights),
            },
            "alert": _alert(lvl, tactics, pats) if lvl in severity.ALERT_LEVELS else None,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 3),
        }

    def feature_matrix(self, messages) -> np.ndarray:
        rows = [self.signals(m)["x"] for m in messages]
        return np.array([[r[f] for f in severity.FEATURES] for r in rows])


def _alert(level: str, tactics: list[str], pats: list[str]) -> dict:
    why = ", ".join(tactics + [p.replace("_", " ") for p in pats]) or "high text-model probability"
    action = "remove message and timeout sender" if level == "CRITICAL" else "review message"
    return {"level": level, "summary": f"{level.title()} social-engineering risk: {why}", "recommended_action": action}
