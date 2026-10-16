# Dataset audit and usage (SO1)

Every dataset was inspected **before** use: size, label distribution, duplicates, near-duplicates and how it was built.

| Dataset | Rows | Unique | Labels | Decision | Why |
|---|---|---|---|---|---|
| SMS Spam Collection (UCI) — `data/raw/sms.tsv` | 5,574 | 5,159 | ham 4,827 / spam 747 | **Train + test** | Real messages; many SMS scams use the same lures as chat scams |
| Multiclass NLP Phishing & SE dataset (Zenodo 10.5281/zenodo.15235123, sample) — `data/raw/zenodo_se_multiclass_sample.xlsx` | 624 | 609 | Phishing 117, Scareware 100, Baiting 80, Malware 78, Pretexting 78, NOT-Malicious 171 | **Train + test** | The dataset named in the proposal (§3.2); covers SE attack types beyond phishing |
| Phishing with tactic category — `data/external/phishing_tactic_category.csv` | 1,000 | **79** | urgency 25, authority 25, persuasion 29 (all phishing) | **Evaluation only** | Labelled by a third party → independent check of the tactic detector (our chat scenarios were written by us) |
| Phishing/spam "large" — `phishing_spam_large_dataset.csv` | 20,000 | **3 templates** | ham / spam / phishing | **Rejected** | Only three sentences repeated with a number appended ("WIN BIG! Click here for free prize 61!"). Any model scores ~100%, which says nothing about real performance |

## Problems found and fixed

1. **Broken file format (Zenodo .xlsx).** The label is stored inside the text cell after a TAB (`"…your package\tPhishing"`), and long texts spill into the second column. `data._split_tab_labels()` repairs this; all 624 rows are recovered (`tests/test_data.py`).
2. **Exact duplicates.** 430 duplicate messages removed across datasets.
3. **Near-duplicate leakage.** Public SE datasets contain template variants ("…remove it *immediately*" / "…remove it *completely*"). With a normal random split, **43% of Zenodo test messages had a ≥0.8-cosine near-copy in the training set**, and Zenodo F1 was a meaningless 1.000. `data.near_duplicate_groups()` links variants (char 3–5-gram TF-IDF cosine ≥ 0.8) and `prepare()` uses a stratified **group-aware** split, so a variant family is never on both sides. Leakage after the fix: **0%** for both datasets.

## Splits (v0.4.0)

Stratified by source × label, grouped by near-duplicate family: train 4,119 / validation 824 / test 825
(test: SMS 738, Zenodo 87). Chat scenarios: dev 80 / test 80. Third-party tactic set: 79, evaluation only.

## Licences — to verify before submission
SMS Spam Collection: UCI, research use with citation. Zenodo dataset: check the licence on the Zenodo record.
Tactic-category CSV: record where it was downloaded from and its licence.
