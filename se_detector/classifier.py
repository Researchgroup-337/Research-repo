"""Text classifier for phishing / social-engineering messages (Module 2, SO2).

Produces ``P`` = probability that a message is social engineering.

Models
* ``lr``  - TF-IDF (word 1-2 grams + character 3-5 grams) + Logistic Regression.
            Baseline 1 in the proposal and the current production text model:
            fast (<1 ms), calibrated probabilities, small on disk.
* ``svm`` - same features + linear SVM. Baseline 2. SVM gives a margin, not a
            probability, so it is wrapped in sigmoid calibration.

Character n-grams are used on purpose: chat scammers misspell and obfuscate
("n1tro", "dlscord"), and char n-grams are robust to that where word
features are not.

The DistilBERT text model (scripts/finetune_distilbert.py) is a drop-in
replacement exposing the same ``predict_proba(list[str])`` interface.
"""
from __future__ import annotations

from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

from .preprocess import clean


def _features() -> FeatureUnion:
    return FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, max_features=50000)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True, max_features=100000)),
    ])


def build(kind: str = "lr", seed: int = 42) -> Pipeline:
    if kind == "lr":
        clf = LogisticRegression(C=10.0, class_weight="balanced", max_iter=2000, random_state=seed)
    elif kind == "svm":
        clf = CalibratedClassifierCV(LinearSVC(C=1.0, class_weight="balanced", random_state=seed), cv=3, method="sigmoid")
    else:
        raise ValueError(f"unknown model kind {kind!r}")
    return Pipeline([("tfidf", _features()), ("clf", clf)])


def normalise(texts) -> list[str]:
    return [clean(t).text for t in texts]
