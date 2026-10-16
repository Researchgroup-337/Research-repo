"""Dataset loading and preparation (SO1).

``load_any`` reads CSV / TSV / XLSX files with different column names and label
schemes and returns one standard frame::

    text | label (1 = social engineering, 0 = legitimate) | attack_type | source

Supported out of the box
* SMS Spam Collection (``label<TAB>text`` with ham/spam)
* Multiclass NLP Dataset for Phishing and Social Engineering Threat Detection
  (Zenodo 10.5281/zenodo.15235123) - classes Phishing, Malware, Scareware,
  Baiting, Pretexting, NOT-Malicious. Every class except "NOT-Malicious" maps to
  label 1 and the original class is kept in ``attack_type``. The distributed
  .xlsx stores the label *inside* the text cell after a TAB ("text\tPhishing")
  and long texts spill into the second column; ``_split_tab_labels`` repairs it.
* Any file with a text-like column and a label-like column (phishing/legit,
  spam/ham, 1/0, true/false, ...).

``prepare`` runs the proposal's cleaning steps: drop missing text, drop
duplicate messages, group near-duplicate variants (cosine >= 0.8), and a
stratified, group-aware train / validation / test split (~72 / 14 / 14), so
that no message or close variant of it appears on both sides (no leakage).
"""
from __future__ import annotations

import csv
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold, train_test_split

TEXT_COLS = ["text", "corpus", "message", "msg", "content", "body", "sms", "email", "email text", "text_message", "v2"]
LABEL_COLS = ["label", "labels", "class", "category", "type", "target", "is_phishing", "is_se", "spam", "v1"]
BENIGN = {"ham", "legit", "legitimate", "benign", "safe", "not malicious", "not_malicious", "not-malicious",
          "not-malicious general class", "normal", "0", "false", "no", "safe email"}


def _is_benign(label: pd.Series) -> pd.Series:
    low = label.str.lower().str.strip()
    return low.isin(BENIGN) | low.str.startswith("not-malicious") | low.str.startswith("not malicious")


def _split_tab_labels(raw: pd.DataFrame, tcol: str, lcol: str) -> pd.DataFrame:
    """Repair files where the label is appended to the text after a TAB."""
    joined = raw[tcol].fillna("").astype(str) + raw[lcol].fillna("").astype(str).map(lambda v: " " + v if v else "")
    parts = joined.str.extract(r"^(?P<text>.*)\t\s*(?P<label>[^\t]+?)\s*$", expand=True)
    return pd.DataFrame({tcol: parts["text"].str.strip(), lcol: parts["label"]}).dropna()


def _pick(cols: list[str], wanted: list[str]) -> str | None:
    lower = {c.lower().strip(): c for c in cols}
    for w in wanted:
        if w in lower:
            return lower[w]
    return None


def _read(path: Path) -> pd.DataFrame:
    suffix = path.suffix.lower()
    if suffix in {".xlsx", ".xls"}:
        return pd.read_excel(path)
    if suffix == ".tsv" or path.name == "sms.tsv":
        df = pd.read_csv(path, sep="\t", header=None, quoting=csv.QUOTE_NONE, names=["label", "text"])
        if str(df.iloc[0, 0]).lower() in {"label", "class"}:
            df = df.iloc[1:]
        return df
    return pd.read_csv(path, encoding_errors="replace")


def load_any(path: str | Path, source: str | None = None) -> pd.DataFrame:
    path = Path(path)
    raw = _read(path)
    tcol = _pick(list(raw.columns), TEXT_COLS)
    lcol = _pick(list(raw.columns), LABEL_COLS)
    if tcol is None or lcol is None:
        raise ValueError(f"{path.name}: could not find text/label columns in {list(raw.columns)}")
    if raw[lcol].isna().mean() > 0.5 and raw[tcol].astype(str).str.contains("\t").mean() > 0.5:
        raw = _split_tab_labels(raw, tcol, lcol)
    raw = raw.dropna(subset=[tcol, lcol])
    lab = raw[lcol].astype(str).str.strip()
    benign = _is_benign(lab)
    out = pd.DataFrame({
        "text": raw[tcol].astype(str),
        "label": (~benign).astype(int),
        "attack_type": lab.where(~benign, "legitimate"),
        "source": source or path.stem,
    })
    return out


def near_duplicate_groups(df: pd.DataFrame, threshold: float = 0.8) -> np.ndarray:
    """Group near-identical messages (char 3-5-gram TF-IDF cosine >= threshold) within each source.

    Public SE datasets contain template variants ("...remove it immediately" /
    "...remove it completely"). If variants land in both train and test the
    score is inflated, so whole groups are kept on one side of the split.
    """
    from scipy.sparse.csgraph import connected_components
    from sklearn.feature_extraction.text import TfidfVectorizer
    groups = np.empty(len(df), dtype=object)
    for src, idx in df.groupby("source").indices.items():
        texts = df["text"].iloc[idx].str.lower()
        X = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), dtype=np.float32).fit_transform(texts)
        sim = (X @ X.T).tocsr()
        sim.data = (sim.data >= threshold).astype(np.int8)
        sim.eliminate_zeros()
        _, comp = connected_components(sim, directed=False)
        groups[idx] = [f"{src}:{c}" for c in comp]
    return groups


def prepare(df: pd.DataFrame, seed: int = 42, near_dup_threshold: float | None = 0.8) -> dict[str, pd.DataFrame]:
    """Clean and split. Returns dict with train/val/test frames and a report."""
    n0 = len(df)
    df = df[df["text"].notna() & (df["text"].str.strip() != "") & (df["text"] != "nan")]
    n_missing = n0 - len(df)
    key = df["text"].str.lower().str.strip()
    dup = key.duplicated()
    df = df[~dup].reset_index(drop=True)
    strat = (df["source"].astype(str) + "_" + df["label"].astype(str)).values  # keep each dataset's class balance
    if near_dup_threshold:
        # group-aware split: near-duplicate variants never straddle train/val/test
        groups = near_duplicate_groups(df, near_dup_threshold)
        outer = StratifiedGroupKFold(n_splits=7, shuffle=True, random_state=seed)
        rest_idx, test_idx = next(outer.split(df, strat, groups))
        inner = StratifiedGroupKFold(n_splits=6, shuffle=True, random_state=seed)
        tr_i, va_i = next(inner.split(rest_idx, strat[rest_idx], groups[rest_idx]))
        train, val, test = df.iloc[rest_idx[tr_i]], df.iloc[rest_idx[va_i]], df.iloc[test_idx]
        n_groups = int(len(set(groups)))
    else:
        train, rest = train_test_split(df, test_size=0.30, stratify=strat, random_state=seed)
        val, test = train_test_split(rest, test_size=0.50, stratify=strat[rest.index], random_state=seed)
        n_groups = len(df)
    report = {
        "per_source": {k: int(v) for k, v in df["source"].value_counts().items()},
        "raw_rows": n0, "missing_removed": int(n_missing), "duplicates_removed": int(dup.sum()),
        "final_rows": len(df), "near_duplicate_groups": n_groups, "positive_rate": round(float(df["label"].mean()), 4),
        "train": len(train), "val": len(val), "test": len(test),
    }
    return {"train": train.reset_index(drop=True), "val": val.reset_index(drop=True),
            "test": test.reset_index(drop=True), "report": report}


def load_tactic_set(path: str | Path) -> pd.DataFrame:
    """Independent tactic-labelled set (one tactic per message: urgency / authority / persuasion).

    Used ONLY for evaluation: it is labelled by a third party, unlike the
    chat scenarios, so it gives an unbiased check of the tactic detector.
    Exact duplicate messages are removed (the public file repeats templates).
    """
    raw = pd.read_csv(path, encoding_errors="replace")
    raw = raw.dropna(subset=["text", "category"])
    raw["text"] = raw["text"].astype(str).str.strip()
    return raw.drop_duplicates("text").reset_index(drop=True)[["text", "category"]]
