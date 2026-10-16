"""Evaluate baselines vs the proposed manipulation-aware detector (SO6).

Test sets (never used for training or tuning):
  * sms_test     - 15% held-out split of the SMS corpus
  * zenodo_test  - 15% held-out split of the Zenodo multiclass SE dataset (proposal dataset)
  * chat_test    - held-out half of the chat-scenario set (target domain: live chat)
  * external tactic set - 79 unique third-party messages labelled urgency/authority/persuasion
                          (all phishing) - independent check of the tactic detector

Experiments (proposal Appendix 7):
  E1 TF-IDF + LR (text only)   E2 TF-IDF + SVM (text only)
  E4 proposed hybrid           E5 ablations (-U, -A, -F, -U-A-F, -R), rules only
  tactic detection P/R/F1, per-attack-type recall, latency.
Outputs reports/results.json, reports/RESULTS.md and figures in reports/.
"""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

from se_detector import classifier, manipulation, severity
from se_detector.pipeline import SEDetector
from se_detector.preprocess import clean

det = SEDetector()
train = pd.read_csv(ROOT / "data/processed/train.csv")
val = pd.read_csv(ROOT / "data/processed/val.csv")
test_all = pd.read_csv(ROOT / "data/processed/test.csv")
sms_test = test_all[test_all.source == "sms_spam_collection"]
zen_test = test_all[test_all.source == "zenodo_se"]
sc = pd.read_csv(ROOT / "data/scenarios/chat_scenarios.csv")
chat_dev, chat_test = sc[sc.split == "dev"], sc[sc.split == "test"]


def metrics(y, p):
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    return {"accuracy": round(accuracy_score(y, p), 4), "precision": round(precision_score(y, p, zero_division=0), 4),
            "recall": round(recall_score(y, p, zero_division=0), 4), "f1": round(f1_score(y, p, zero_division=0), 4),
            "fpr": round(fp / (fp + tn) if fp + tn else 0, 4), "fnr": round(fn / (fn + tp) if fn + tp else 0, 4),
            "cm": [[int(tn), int(fp)], [int(fn), int(tp)]]}


tests = {"sms_test": (list(sms_test.text), sms_test.label.values),
         "chat_test": (list(chat_test.text), chat_test.is_se.values)}
if len(zen_test):
    tests["zenodo_test"] = (list(zen_test.text), zen_test.label.values)
fit_texts = list(val.text) + list(chat_dev.text)
fit_y = np.concatenate([val.label.values, chat_dev.is_se.values])
X_fit = det.feature_matrix(fit_texts)
X_test = {k: det.feature_matrix(t) for k, (t, _) in tests.items()}

results = {"models": {}, "weights": det.weights, "tau": det.tau}

# E1/E2 text-only baselines
svm = classifier.build("svm").fit(classifier.normalise(train.text), train.label)
for name, model in [("E1 TF-IDF+LR (text only)", det.text_model), ("E2 TF-IDF+SVM (text only)", svm)]:
    results["models"][name] = {k: metrics(y, (model.predict_proba(classifier.normalise(t))[:, 1] >= 0.5).astype(int))
                               for k, (t, y) in tests.items()}

# E4 proposed + E5 ablations: refit weights and threshold without the removed signal(s)
variants = {
    "E4 Proposed hybrid (P+U+A+F+R)": ("P", "U", "A", "F", "R"),
    "E5 without urgency": ("P", "A", "F", "R"),
    "E5 without authority": ("P", "U", "F", "R"),
    "E5 without fear": ("P", "U", "A", "R"),
    "E5 without all manipulation (P+R)": ("P", "R"),
    "E5 without pattern risk (P+U+A+F)": ("P", "U", "A", "F"),
    "E5 rules only (U+A+F+R, no text model)": ("U", "A", "F", "R"),
}
for name, use in variants.items():
    w = severity.fit_weights(X_fit, fit_y, use)
    tau = severity.tune_threshold(severity.score(X_fit, w), fit_y)
    results["models"][name] = {k: metrics(tests[k][1], (severity.score(X_test[k], w) >= tau).astype(int)) for k in tests}
    results["models"][name]["weights"] = w
    results["models"][name]["tau"] = tau

# Tactic detection on chat test (proposal SO3)
tac = {}
for t in manipulation.TACTICS:
    pred = [int(manipulation.detect(clean(m).text)["scores"][t] >= manipulation.TACTIC_THRESHOLD) for m in chat_test.text]
    gold = chat_test[t].values
    tac[t] = {"precision": round(precision_score(gold, pred, zero_division=0), 4), "recall": round(recall_score(gold, pred, zero_division=0), 4),
              "f1": round(f1_score(gold, pred, zero_division=0), 4), "support": int(gold.sum())}
results["tactics_chat_test"] = tac

# Per attack type recall (chat test) - proposed vs text-only
p_prop = severity.score(X_test["chat_test"], det.weights) >= det.tau
p_text = det.text_model.predict_proba(classifier.normalise(chat_test.text))[:, 1] >= 0.5
by = {}
for at, g in chat_test.assign(prop=p_prop, text=p_text).groupby("attack_type"):
    col = "prop" if True else None
    by[at] = {"n": len(g), "proposed_flag_rate": round(g.prop.mean(), 3), "text_only_flag_rate": round(g.text.mean(), 3)}
results["by_attack_type_chat_test"] = by

# Severity level distribution on chat test
levels = [severity.level(s, det.tau) for s in severity.score(X_test["chat_test"], det.weights)]
results["severity_levels_chat_test"] = pd.crosstab(pd.Series(levels, name="level"), chat_test.is_se.values).to_dict()

# Zenodo test: recall per attack type (proposal classes)
if len(zen_test):
    pz = severity.score(X_test["zenodo_test"], det.weights) >= det.tau
    tz = det.text_model.predict_proba(classifier.normalise(zen_test.text))[:, 1] >= 0.5
    results["zenodo_by_attack_type"] = {at: {"n": len(g), "proposed_flag_rate": round(float(g.prop.mean()), 3), "text_only_flag_rate": round(float(g.text.mean()), 3)}
                                        for at, g in zen_test.assign(prop=pz, text=tz).groupby("attack_type")}

# External, third-party tactic-labelled set (evaluation only)
ext_path = ROOT / "data/external/phishing_tactic_category.csv"
if ext_path.exists():
    from se_detector import data as _data
    ext = _data.load_tactic_set(ext_path)
    Xe = det.feature_matrix(list(ext.text))
    pe = severity.score(Xe, det.weights) >= det.tau
    te = det.text_model.predict_proba(classifier.normalise(ext.text))[:, 1] >= 0.5
    tac_pred = {t: [manipulation.detect(clean(m).text)["scores"][t] >= manipulation.TACTIC_THRESHOLD for m in ext.text] for t in manipulation.TACTICS}
    ext_res = {"n": len(ext), "detection_recall_proposed": round(float(pe.mean()), 3), "detection_recall_text_only": round(float(te.mean()), 3), "by_category": {}}
    for cat, g in ext.assign(prop=pe, text=te, **{f"has_{t}": tac_pred[t] for t in tac_pred}).groupby("category"):
        ext_res["by_category"][cat] = {"n": len(g), "proposed": round(float(g.prop.mean()), 3), "text_only": round(float(g.text.mean()), 3),
                                       **{f"tactic_{t}_rate": round(float(g[f"has_{t}"].mean()), 3) for t in tac_pred}}
    results["external_tactic_set"] = ext_res

# Latency (NFR01): full analyze() per message, single thread, warm
msgs = list(sms_test.text) + list(sc.text)
for m in msgs[:50]:
    det.analyze(m)
lat = []
for m in msgs:
    t0 = time.perf_counter(); det.analyze(m); lat.append((time.perf_counter() - t0) * 1000)
lat = np.array(lat)
t0 = time.perf_counter()
for m in msgs:
    det.analyze(m)
results["latency_ms"] = {"n": len(lat), "mean": round(lat.mean(), 3), "p50": round(np.percentile(lat, 50), 3),
                         "p95": round(np.percentile(lat, 95), 3), "p99": round(np.percentile(lat, 99), 3), "max": round(lat.max(), 3),
                         "throughput_msgs_per_s": round(len(msgs) / (time.perf_counter() - t0), 1)}

(ROOT / "reports/results.json").write_text(json.dumps(results, indent=2, default=str))

# Markdown summary
sizes = {k: len(v[1]) for k, v in tests.items()}
L = ["# Evaluation results", "", f"Model version {det.version}. Weights {det.weights}, threshold tau={det.tau}.",
     f"Test-set sizes: {sizes}", "",
     "## Detection (held-out test sets)", "",
     "| Model | SMS F1 | SMS FPR | Zenodo F1 | Zenodo FPR | Chat F1 | Chat Recall | Chat FPR |", "|---|---|---|---|---|---|---|---|"]
for name, r in results["models"].items():
    a, b = r["sms_test"], r["chat_test"]
    z = r.get("zenodo_test", {"f1": float("nan"), "fpr": float("nan")})
    L.append(f"| {name} | {a['f1']:.3f} | {a['fpr']:.3f} | {z['f1']:.3f} | {z['fpr']:.3f} | {b['f1']:.3f} | {b['recall']:.3f} | {b['fpr']:.3f} |")
L += ["", "## Manipulation tactic detection (chat test)", "", "| Tactic | Precision | Recall | F1 | Support |", "|---|---|---|---|---|"]
for t, r in tac.items():
    L.append(f"| {t} | {r['precision']:.3f} | {r['recall']:.3f} | {r['f1']:.3f} | {r['support']} |")
L += ["", "## Flag rate by attack type (chat test)", "", "| Type | n | Proposed | Text-only |", "|---|---|---|---|"]
for at, r in by.items():
    L.append(f"| {at} | {r['n']} | {r['proposed_flag_rate']:.2f} | {r['text_only_flag_rate']:.2f} |")
if "zenodo_by_attack_type" in results:
    L += ["", "## Zenodo test: flag rate by attack type", "", "| Type | n | Proposed | Text-only |", "|---|---|---|---|"]
    for at, r in results["zenodo_by_attack_type"].items():
        L.append(f"| {at} | {r['n']} | {r['proposed_flag_rate']:.2f} | {r['text_only_flag_rate']:.2f} |")
if "external_tactic_set" in results:
    e = results["external_tactic_set"]
    L += ["", f"## External tactic-labelled set (third-party, n={e['n']} unique, all phishing)", "",
          f"Detection recall: proposed {e['detection_recall_proposed']:.2f} vs text-only {e['detection_recall_text_only']:.2f}", "",
          "| Labelled category | n | Proposed recall | Text-only recall | urgency found | authority found | fear found |", "|---|---|---|---|---|---|---|"]
    for cat, r in e["by_category"].items():
        L.append(f"| {cat} | {r['n']} | {r['proposed']:.2f} | {r['text_only']:.2f} | {r['tactic_urgency_rate']:.2f} | {r['tactic_authority_rate']:.2f} | {r['tactic_fear_rate']:.2f} |")
lt = results["latency_ms"]
L += ["", "## Latency (single CPU thread, full pipeline)", "",
      f"mean {lt['mean']} ms, p50 {lt['p50']} ms, p95 {lt['p95']} ms, p99 {lt['p99']} ms, throughput {lt['throughput_msgs_per_s']} msg/s (n={lt['n']})"]
(ROOT / "reports/RESULTS.md").write_text("\n".join(L) + "\n")
print("\n".join(L))

# ---- Bootstrap 95% CI for chat-test F1 (small n=80, so show uncertainty) ----
rng = np.random.default_rng(0)
yc = tests["chat_test"][1]
pt = (det.text_model.predict_proba(classifier.normalise(tests["chat_test"][0]))[:, 1] >= 0.5).astype(int)
pp = (severity.score(X_test["chat_test"], det.weights) >= det.tau).astype(int)
diffs, a_s, b_s = [], [], []
for _ in range(2000):
    i = rng.integers(0, len(yc), len(yc))
    a, b = f1_score(yc[i], pt[i], zero_division=0), f1_score(yc[i], pp[i], zero_division=0)
    a_s.append(a); b_s.append(b); diffs.append(b - a)
ci = lambda v: [round(float(np.percentile(v, 2.5)), 3), round(float(np.percentile(v, 97.5)), 3)]
results["bootstrap_chat_f1"] = {"text_only_ci": ci(a_s), "proposed_ci": ci(b_s), "improvement_ci": ci(diffs),
                                "p_improvement_le_0": round(float(np.mean(np.array(diffs) <= 0)), 4)}

# ---- Error analysis: chat-test mistakes of the proposed model (NOT used for tuning) ----
errs = []
for (_, r), pred, s in zip(chat_test.iterrows(), pp, severity.score(X_test["chat_test"], det.weights)):
    if pred != r.is_se:
        errs.append({"id": r.id, "type": "FN" if r.is_se else "FP", "score": round(float(s), 3), "text": r.text})
results["errors_chat_test"] = errs
miss_auth = [r.text for _, r in chat_test.iterrows()
             if r.authority == 1 and manipulation.detect(clean(r.text).text)["scores"]["authority"] < manipulation.TACTIC_THRESHOLD]
results["authority_misses_chat_test"] = miss_auth
(ROOT / "reports/results.json").write_text(json.dumps(results, indent=2, default=str))
with open(ROOT / "reports/RESULTS.md", "a") as f:
    b = results["bootstrap_chat_f1"]
    f.write(f"\n## Uncertainty (bootstrap, 2000 resamples of chat test)\n\nText-only F1 95% CI {b['text_only_ci']}; "
            f"proposed F1 95% CI {b['proposed_ci']}; improvement CI {b['improvement_ci']} (share of resamples with no improvement: {b['p_improvement_le_0']}).\n")
    f.write("\n## Error analysis - proposed model mistakes on chat test\n\n| id | type | S | message |\n|---|---|---|---|\n")
    for e in errs:
        f.write(f"| {e['id']} | {e['type']} | {e['score']} | {e['text']} |\n")
    f.write("\n## Authority cues missed (chat test)\n\n" + "\n".join(f"- {t}" for t in miss_auth) + "\n")
print(json.dumps({k: results[k] for k in ["bootstrap_chat_f1", "errors_chat_test", "authority_misses_chat_test"]}, indent=1))
