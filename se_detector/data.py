"""Dataset loading and preparation (SO1).

``load_any`` reads CSV / TSV / XLSX files with different column names and label
schemes and returns one standard frame::

    text | label (1 = social engineering, 0 = legitimate) | attack_type | source

Supported out of the box
* SMS Spam Collection (``label<TAB>text`` with ham/spam)
* Multiclass NLP Dataset for Phishing and Social Engineering Threat Detection
  (Zenodo 10.5281/zenodo.15235123) - classes Phishing, Malware, Scareware,
  Baiting, Pretexting, NOT Malicious. Every class except "NOT Malicious" maps to
  label 1 and the original class is kept in ``attack_type``.
* Any file with a text-like column and a label-like column (phishing/legit,
  spam/ham, 1/0, true/false, ...).

``prepare`` runs the proposal's cleaning steps: drop missing text, drop
duplicate messages (prevents train/test leakage), and stratified
train / validation / test split (70 / 15 / 15).
"""
from __future__ import annotations

import csv
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

TEXT_COLS = ["text", "message", "msg", "content", "body", "sms", "email", "email text", "text_message", "v2"]
LABEL_COLS = ["label", "class", "category", "type", "target", "is_phishing", "is_se", "spam", "v1"]
BENIGN = {"ham", "legit", "legitimate", "benign", "safe", "not malicious", "not_malicious", "normal", "0", "false", "no", "safe email"}


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
    lab = raw[lcol].astype(str).str.strip()
    out = pd.DataFrame({
        "text": raw[tcol].astype(str),
        "label": (~lab.str.lower().isin(BENIGN)).astype(int),
        "attack_type": lab.where(~lab.str.lower().isin(BENIGN), "legitimate"),
        "source": source or path.stem,
    })
    return out


def prepare(df: pd.DataFrame, seed: int = 42) -> dict[str, pd.DataFrame]:
    """Clean and split. Returns dict with train/val/test frames and a report."""
    n0 = len(df)
    df = df[df["text"].notna() & (df["text"].str.strip() != "") & (df["text"] != "nan")]
    n_missing = n0 - len(df)
    key = df["text"].str.lower().str.strip()
    dup = key.duplicated()
    df = df[~dup].reset_index(drop=True)
    train, rest = train_test_split(df, test_size=0.30, stratify=df["label"], random_state=seed)
    val, test = train_test_split(rest, test_size=0.50, stratify=rest["label"], random_state=seed)
    report = {
        "raw_rows": n0, "missing_removed": int(n_missing), "duplicates_removed": int(dup.sum()),
        "final_rows": len(df), "positive_rate": round(float(df["label"].mean()), 4),
        "train": len(train), "val": len(val), "test": len(test),
    }
    return {"train": train.reset_index(drop=True), "val": val.reset_index(drop=True),
            "test": test.reset_index(drop=True), "report": report}
