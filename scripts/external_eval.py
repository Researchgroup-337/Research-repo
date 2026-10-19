"""Independent test on REAL scam SMS messages never used for training (added by D.M.T. Dissanayaka).

data/extra/external_test_real_smishing.csv: 1,055 real smishing messages collected in the wild
(2021-22), each labelled with a scam category (Account Alert, Delivery, Prize, Romance ...).
All are scams, so the score is the detection rate (recall), overall and per category.
Writes reports/external_test.json.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import pandas as pd

from se_detector.pipeline import SEDetector

df = pd.read_csv(ROOT / "data/extra/external_test_real_smishing.csv")
det = SEDetector()
res = [det.analyze(t) for t in df.text]
df["hybrid"] = [r["is_social_engineering"] for r in res]
df["text_only"] = [r["phishing_probability"] >= 0.5 for r in res]
out = {"n": len(df),
       "hybrid_detection_rate": round(float(df.hybrid.mean()), 4),
       "text_only_detection_rate": round(float(df.text_only.mean()), 4),
       "by_category": {c: {"n": int(len(g)), "hybrid": round(float(g.hybrid.mean()), 3), "text_only": round(float(g.text_only.mean()), 3)}
                       for c, g in df.groupby("category")}}
(ROOT / "reports/external_test.json").write_text(json.dumps(out, indent=2))
print(f"{out['n']} real scam SMS: hybrid {out['hybrid_detection_rate']:.3f}, text-only {out['text_only_detection_rate']:.3f}")
for c, v in sorted(out["by_category"].items(), key=lambda kv: kv[1]["hybrid"]):
    print(f"  {c:28s} n={v['n']:4d}  hybrid {v['hybrid']:.2f}  text-only {v['text_only']:.2f}")
