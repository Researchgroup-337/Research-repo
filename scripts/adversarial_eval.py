"""Security test: can an attacker evade the detector? (added by D.M.T. Dissanayaka)

Takes the held-out ATTACK messages (chat test + Zenodo test) and rewrites each one
with evasion tricks that real scammers use against keyword filters:

  homoglyph   - swap Latin letters for look-alike Cyrillic ones ("аccount")
  invisible   - hide zero-width characters inside words ("acc​ount")
  spacing     - space out the longest words ("v e r i f y")
  leetspeak   - "acc0unt", "v3rify"
  combined    - homoglyph + invisible together

Each attack is scored WITHOUT the evasion defence (preprocess.HARDEN = False) and
WITH it (HARDEN = True). Also checks that the defence does not add false alarms on
the held-out benign messages.

Outputs reports/adversarial.json and reports/ADVERSARIAL.md
"""
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pandas as pd

from se_detector import preprocess, severity
from se_detector.pipeline import SEDetector

SEED = 7
CYR = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у", "i": "і",
       "A": "А", "E": "Е", "O": "О", "P": "Р", "C": "С", "X": "Х", "T": "Т", "H": "Н", "K": "К", "M": "М", "B": "В"}
LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"}


def homoglyph(t, rng):
    return "".join(CYR[c] if c in CYR and rng.random() < 0.5 else c for c in t)


def invisible(t, rng):
    out = []
    for w in t.split(" "):
        if len(w) > 3:
            k = rng.randint(1, len(w) - 1)
            w = w[:k] + "​" + w[k:]
        out.append(w)
    return " ".join(out)


def spacing(t, rng):
    words = t.split(" ")
    longest = sorted(range(len(words)), key=lambda i: -len(words[i]))[:3]
    for i in longest:
        if words[i].isalpha():
            words[i] = " ".join(words[i])
    return " ".join(words)


def leetspeak(t, rng):
    return "".join(LEET[c] if c in LEET and rng.random() < 0.5 else c for c in t)


ATTACKS = {"none (original)": lambda t, r: t, "homoglyph": homoglyph, "invisible": invisible,
           "spacing": spacing, "leetspeak": leetspeak,
           "combined": lambda t, r: invisible(homoglyph(t, r), r)}


def score_all(det, texts, harden):
    preprocess.HARDEN = harden
    res = [det.analyze(t) for t in texts]
    preprocess.HARDEN = True
    return res


def main():
    det = SEDetector()
    sc = pd.read_csv(ROOT / "data/scenarios/chat_scenarios.csv")
    test_all = pd.read_csv(ROOT / "data/processed/test.csv")
    chat_test = sc[sc.split == "test"]
    zen = test_all[test_all.source == "zenodo_se"]
    attacks = list(chat_test[chat_test.is_se == 1].text) + list(zen[zen.label == 1].text)
    benign = list(chat_test[chat_test.is_se == 0].text) + list(test_all[test_all.label == 0].text)

    out = {"n_attacks": len(attacks), "n_benign": len(benign), "seed": SEED, "attacks": {}}
    for name, fn in ATTACKS.items():
        rng = random.Random(SEED)
        adv = [fn(t, rng) for t in attacks]
        row = {}
        for label, harden in (("no_defence", False), ("with_defence", True)):
            r = score_all(det, adv, harden)
            row[label] = {
                "detection_rate": round(sum(x["is_social_engineering"] for x in r) / len(r), 4),
                "alert_rate": round(sum(x["severity"]["level"] in severity.ALERT_LEVELS for x in r) / len(r), 4),
                "mean_severity": round(sum(x["severity"]["score"] for x in r) / len(r), 4),
            }
        out["attacks"][name] = row
        print(f"{name:16s} no defence {row['no_defence']['detection_rate']:.2f}  ->  with defence {row['with_defence']['detection_rate']:.2f}")

    for label, harden in (("no_defence", False), ("with_defence", True)):
        r = score_all(det, benign, harden)
        out.setdefault("benign_false_positive_rate", {})[label] = round(sum(x["is_social_engineering"] for x in r) / len(r), 4)
    print("benign FPR", out["benign_false_positive_rate"])

    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports/adversarial.json").write_text(json.dumps(out, indent=2))
    lines = ["# Evasion-attack test (security hardening)", "",
             f"{out['n_attacks']} held-out attack messages (chat test + Zenodo test), each rewritten with an evasion trick (seed {SEED}).",
             "Detection rate = share still flagged as social engineering (S >= tau).", "",
             "| Evasion trick | Detection: no defence | Detection: with defence | Alerts (HIGH+): no defence | Alerts: with defence |",
             "|---|---|---|---|---|"]
    for name, row in out["attacks"].items():
        a, b = row["no_defence"], row["with_defence"]
        lines.append(f"| {name} | {a['detection_rate']:.2f} | {b['detection_rate']:.2f} | {a['alert_rate']:.2f} | {b['alert_rate']:.2f} |")
    fp = out["benign_false_positive_rate"]
    lines += ["", f"Benign false-positive rate ({out['n_benign']} held-out benign messages): "
                  f"no defence {fp['no_defence']:.3f}, with defence {fp['with_defence']:.3f}."]
    (ROOT / "reports/ADVERSARIAL.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
