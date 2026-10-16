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
python -m pytest -q                # 45 tests
uvicorn se_detector.api:app --port 8004   # open http://localhost:8004 for the live demo
```

Add your own dataset (CSV/TSV/XLSX with a text column and a label column, e.g. the Zenodo multiclass SE dataset):

```bash
python scripts/train.py --extra data/raw/your_dataset.xlsx && python scripts/evaluate.py
```

## Current results (v0.3.0, held-out test sets)

| Model | SMS F1 | Chat F1 | Chat recall | Chat FPR |
|---|---|---|---|---|
| E1 TF-IDF + LR (text only) | 0.973 | 0.667 | 0.500 | 0.000 |
| E2 TF-IDF + SVM (text only) | 0.973 | 0.644 | 0.475 | 0.000 |
| **E4 Proposed hybrid** | **0.979** | **0.923** | **0.900** | 0.050 |

Latency: p50 2.7 ms, p95 3.7 ms per message on one CPU thread (~465 msg/s). Full tables, ablation and error analysis are in `reports/RESULTS.md`.

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
| `data/scenarios/chat_scenarios.csv` | 160 annotated chat scenarios (dev/test) |
| `docs/` | integration contract, function specs, annotation guide, risk register, AI-use log |

## Data sources

* T. A. Almeida, J. M. G. Hidalgo, A. Yamakami, "SMS Spam Collection v.1", UCI ML Repository, 2011.
* Planned: Engineering Ingegneria Informatica S.p.A., *Multiclass NLP Dataset for Phishing and Social Engineering Threat Detection*, Zenodo, 2025, doi:10.5281/zenodo.15235123.
