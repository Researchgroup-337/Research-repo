"""Data-pipeline tests: dataset parsing and leakage-free splitting (SO1)."""
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from se_detector import data

ZEN = ROOT / "data/raw/zenodo_se_multiclass_sample.xlsx"


def test_tab_label_repair():
    raw = pd.DataFrame({"Corpus": ["Your PC is infected, download the fix\tScareware", "See you tomorrow\tNOT-Malicious General Class"],
                        "Labels": [None, None]})
    fixed = data._split_tab_labels(raw, "Corpus", "Labels")
    assert list(fixed["Labels"]) == ["Scareware", "NOT-Malicious General Class"]
    assert fixed["Corpus"].iloc[0] == "Your PC is infected, download the fix"


def test_benign_label_mapping():
    lab = pd.Series(["NOT-Malicious General Class", "ham", "Pretexting", "phishing", "legit"])
    assert list(data._is_benign(lab)) == [True, True, False, False, True]


def test_zenodo_dataset_loads():
    if not ZEN.exists():
        return
    z = data.load_any(ZEN, "zenodo_se")
    assert len(z) == 624
    assert set(z.attack_type) == {"legitimate", "Phishing", "Scareware", "Baiting", "Malware", "Pretexting"}


def test_split_has_no_near_duplicate_leakage():
    texts = [f"your computer is infected, download the attachment to remove it {w}" for w in ["now", "fast", "today", "completely"]]
    texts += [f"normal chat message number {i} about the game" for i in range(40)]
    texts += [f"claim your free prize {w} at the link" for w in ["now", "today", "fast"]]
    df = pd.DataFrame({"text": texts, "label": [1] * 4 + [0] * 40 + [1] * 3, "source": "t", "attack_type": "x"})
    groups = data.near_duplicate_groups(df, 0.8)
    assert len(set(groups[:4])) == 1          # the 4 template variants form one group
    split = data.prepare(df)
    sides = {}
    for name in ("train", "val", "test"):
        for t in split[name].text:
            sides[t] = name
    assert len({sides[t] for t in texts[:4]}) == 1   # never split across train/val/test
