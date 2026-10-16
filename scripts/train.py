"""Train the SE detector and save models/se_detector.joblib.

Usage:
    python scripts/train.py                                  # SMS corpus + Zenodo SE dataset (if present)
    python scripts/train.py --extra data/raw/zenodo_se.xlsx  # add more datasets

Steps (proposal 3.3 / 3.5): load -> drop missing -> de-duplicate -> split 70/15/15
-> train TF-IDF+LR text model on TRAIN -> compute [P,U,A,F,R] on VALIDATION
(+ chat-scenario DEV half) -> learn severity weights + threshold -> save bundle.
The TEST splits are never touched here.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import joblib
import numpy as np
import pandas as pd

from se_detector import __version__, classifier, data, severity
from se_detector.pipeline import SEDetector


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--extra", nargs="*", default=[], help="extra dataset files (csv/tsv/xlsx)")
    ap.add_argument("--no-chat-dev", action="store_true", help="do not use chat-scenario dev half for weight fitting")
    args = ap.parse_args()

    frames = [data.load_any(ROOT / "data/raw/sms.tsv", "sms_spam_collection")]
    zenodo = ROOT / "data/raw/zenodo_se_multiclass_sample.xlsx"
    if zenodo.exists():   # Multiclass NLP Phishing & SE dataset (proposal section 3.2)
        frames.append(data.load_any(zenodo, "zenodo_se"))
    frames += [data.load_any(p) for p in args.extra]
    df = pd.concat(frames, ignore_index=True)
    split = data.prepare(df)
    out = ROOT / "data/processed"
    out.mkdir(parents=True, exist_ok=True)
    for k in ("train", "val", "test"):
        split[k].to_csv(out / f"{k}.csv", index=False)
    print("data:", split["report"])

    text_model = classifier.build("lr").fit(classifier.normalise(split["train"].text), split["train"].label)

    # temporary bundle so SEDetector can compute signals with the trained text model
    tmp = {"text_model": text_model, "weights": severity.DEFAULT_WEIGHTS, "tau": 0.5, "version": "tmp"}
    model_path = ROOT / "models/se_detector.joblib"
    model_path.parent.mkdir(exist_ok=True)
    joblib.dump(tmp, model_path)
    det = SEDetector(model_path)

    texts, y = list(split["val"].text), list(split["val"].label)
    if not args.no_chat_dev:
        sc = pd.read_csv(ROOT / "data/scenarios/chat_scenarios.csv")
        dev = sc[sc.split == "dev"]
        texts += list(dev.text); y += list(dev.is_se)
    X, y = det.feature_matrix(texts), np.array(y)
    weights = severity.fit_weights(X, y)
    tau = severity.tune_threshold(severity.score(X, weights), y)
    bundle = {"text_model": text_model, "weights": weights, "tau": tau, "version": __version__,
              "data_report": split["report"], "fit_on": len(y)}
    joblib.dump(bundle, model_path)
    meta = {"version": __version__, "weights": weights, "tau": tau, "data": split["report"], "weight_fit_samples": int(len(y))}
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports/training.json").write_text(json.dumps(meta, indent=2))
    print("weights:", weights, "tau:", tau)


if __name__ == "__main__":
    main()
