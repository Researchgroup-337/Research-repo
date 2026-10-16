# Social Engineering Attack Detection & Severity Scoring for Real-Time Chat

**Component 4 of J26-CS-337:** *Privacy-Preserving Real-Time Cyberbullying Detection Using Transformer-Based NLP and Behavioral Analytics*
**Owner:** D.M.T. Dissanayaka (IT23223462) · Supervisor: Prof. Harinda Fernando · Co-supervisor: Ms. Thriyashi Silva

Detects social-engineering messages in live-stream chat, explains **which manipulation tactics** they use
(urgency, authority, fear) and **what the attacker wants** (credentials, payment, a click), and gives a
**severity score** so moderators handle the dangerous ones first.

```
message → preprocess → text model (P) ─┐
                     → urgency U, authority A, fear F ─┼→ S = Σ wᵢxᵢ (learned weights) → LOW/MEDIUM/HIGH/CRITICAL → alert
                     → attack patterns + link risk (R) ┘
```

## Quick start

```bash
pip install -r requirements.txt
python scripts/train.py            # trains + saves models/se_detector.joblib
python scripts/evaluate.py         # baselines, ablation, latency → reports/RESULTS.md
python scripts/make_figures.py     # charts → reports/fig_*.png
python -m pytest -q                # 49 tests (48 pass + 1 documented known limitation)
uvicorn se_detector.api:app --port 8004   # open http://localhost:8004 for the live demo
```

`train.py` uses the SMS corpus and the Zenodo SE dataset (`data/raw/zenodo_se_multiclass_sample.xlsx`) automatically.
Add more datasets (CSV/TSV/XLSX with a text column and a label column):

```bash
python scripts/train.py --extra data/raw/your_dataset.xlsx && python scripts/evaluate.py
```

## Current results (v0.4.0, held-out, leakage-free test sets)

Trained on SMS Spam Collection + Zenodo multiclass SE dataset; near-duplicate variants are grouped so they never
straddle train/test (see `docs/DATASETS.md`).

| Model | SMS F1 | Zenodo F1 | Chat F1 | Chat recall | Chat FPR |
|---|---|---|---|---|---|
| E1 TF-IDF + LR (text only) | 0.957 | 1.000 | 0.822 | 0.750 | 0.075 |
| E2 TF-IDF + SVM (text only) | 0.958 | 0.984 | 0.853 | 0.800 | 0.075 |
| **E4 Proposed hybrid** | 0.933 | 0.977 | **0.940** | **0.975** | 0.100 |

Chat F1 gain over text-only: +0.12 (bootstrap 95% CI +0.04 to +0.21). The hybrid trades a little in-domain precision
(SMS/Zenodo FPR 1.9% / 12.5%) for much higher recall on live-chat attacks. Independent third-party set (79 phishing
messages): detection recall 1.00 vs 0.95 text-only.
Latency: p50 2.2 ms, p95 3.7 ms per message on one CPU thread (~390–450 msg/s). Full tables, ablation and error
analysis are in `reports/RESULTS.md`.

## Layout

| path | what |
|---|---|
| `se_detector/preprocess.py` | normalisation, URL extraction, de-leet |
| `se_detector/classifier.py` | TF-IDF + LR / SVM text models |
| `se_detector/manipulation.py` | urgency / authority / fear detector with evidence |
| `se_detector/patterns.py` | attack-pattern + URL heuristics |
| `se_detector/severity.py` | learned-weight severity score, levels |
| `se_detector/pipeline.py` | `SEDetector.analyze()`, the component interface |
| `se_detector/api.py` + `static/index.html` | REST API + live demo |
| `scripts/` | train, evaluate, figures, DistilBERT fine-tuning (Colab) |
| `data/raw/sms.tsv` | SMS Spam Collection (UCI, 5,574 msgs) |
| `data/raw/zenodo_se_multiclass_sample.xlsx` | Multiclass NLP Phishing & SE dataset sample (624 msgs, 6 classes) |
| `data/external/phishing_tactic_category.csv` | Third-party tactic-labelled phishing set (evaluation only) |
| `data/scenarios/chat_scenarios.csv` | 160 annotated chat scenarios (dev/test) |
| `docs/` | integration contract, function specs, annotation guide, risk register, AI-use log |

## Data sources

* T. A. Almeida, J. M. G. Hidalgo, A. Yamakami, "SMS Spam Collection v.1", UCI ML Repository, 2011.
* Engineering Ingegneria Informatica S.p.A., *Multiclass NLP Dataset for Phishing and Social Engineering Threat Detection*, Zenodo, 2025, doi:10.5281/zenodo.15235123 (624-message sample used).
* Public tactic-labelled phishing set (`phishing_dataset_with_category.csv`, source to be cited, evaluation only).
* See `docs/DATASETS.md` for the dataset audit, including one rejected dataset.
