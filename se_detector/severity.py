"""Severity scoring (Module 5, SO4 + SO5).

    S = w_p*P + w_u*U + w_a*A + w_f*F + w_r*R ,   sum(w) = 1,  all inputs in [0,1]

* P - text-classifier probability (classifier.py)
* U, A, F - urgency / authority / fear scores (manipulation.py)
* R - phishing-pattern + link risk (patterns.py)

The proposal states the weights must be *experimentally determined*, not
picked by hand. ``fit_weights`` does that: it fits a logistic regression on
validation data (features [P,U,A,F,R] -> is_SE), keeps the non-negative
coefficients (a cue should never *lower* risk) and normalises them to sum to 1.
The decision threshold ``tau`` is then chosen on the same validation data to
maximise F1. So the same interpretable number S is used both to *decide*
(S >= tau -> social engineering) and to *prioritise* (severity level).

Severity levels (TAF: HIGH or CRITICAL -> moderator alert)
    LOW       S < tau                       not flagged
    MEDIUM    tau <= S < 0.60               flagged, low priority
    HIGH      0.60 <= S < 0.80              alert
    CRITICAL  S >= 0.80                     alert, act first
"""
from __future__ import annotations

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score

FEATURES = ("P", "U", "A", "F", "R")
DEFAULT_WEIGHTS = {"P": 0.40, "U": 0.15, "A": 0.15, "F": 0.15, "R": 0.15}  # used only before training
HIGH, CRITICAL = 0.60, 0.80
ALERT_LEVELS = {"HIGH", "CRITICAL"}


def fit_weights(X: np.ndarray, y: np.ndarray, use: tuple[str, ...] = FEATURES) -> dict[str, float]:
    """Learn normalised non-negative weights for the features listed in ``use``."""
    idx = [FEATURES.index(f) for f in use]
    lr = LogisticRegression(C=1.0, max_iter=1000).fit(X[:, idx], y)
    coef = np.clip(lr.coef_[0], 0, None)
    if coef.sum() == 0:
        coef = np.ones_like(coef)
    coef = coef / coef.sum()
    w = {f: 0.0 for f in FEATURES}
    w.update({f: round(float(c), 4) for f, c in zip(use, coef)})
    return w


def score(x: dict[str, float] | np.ndarray, weights: dict[str, float]) -> float | np.ndarray:
    if isinstance(x, dict):
        return round(sum(weights[f] * float(x[f]) for f in FEATURES), 4)
    wv = np.array([weights[f] for f in FEATURES])
    return x @ wv


def tune_threshold(s: np.ndarray, y: np.ndarray) -> float:
    grid = np.round(np.arange(0.10, 0.71, 0.01), 2)
    f1s = [f1_score(y, (s >= t).astype(int), zero_division=0) for t in grid]
    return float(grid[int(np.argmax(f1s))])


def level(s: float, tau: float) -> str:
    if s >= CRITICAL:
        return "CRITICAL"
    if s >= HIGH:
        return "HIGH"
    if s >= tau:
        return "MEDIUM"
    return "LOW"


def contributions(x: dict[str, float], weights: dict[str, float]) -> dict[str, float]:
    """How much each signal added to S - shown to moderators as the 'why'."""
    return {f: round(weights[f] * float(x[f]), 4) for f in FEATURES}
