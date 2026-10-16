# PP1 key functions (Lecture 8 template)

## Function 1: Hybrid social-engineering detection (status: working)

| | |
|---|---|
| **Function name** | `SEDetector.signals()` / `POST /analyze` (detection part) |
| **Owner** | D.M.T. Dissanayaka (IT23223462) |
| **Input** | raw chat message (+ optional message/user/channel ids) |
| **Processing logic** | 1) preprocessing: Unicode NFKC, URL extraction, emoji removal, de-leet ("n1tro" → "nitro"), stretched-word folding · 2) text classifier: TF-IDF word + char n-grams → logistic regression → P · 3) manipulation detector: weighted cue lexicons for urgency / authority / fear → U, A, F with matched evidence · 4) pattern detector: credential request, account verification, reward bait, payment request, call to action, off-platform/secrecy, suspicious link → R |
| **Output** | P, U, A, F, R, tactics present, patterns, evidence spans, extracted URLs |
| **Dependency** | Data Acquisition layer (input stream); forwards URLs to Gunarathna's URL verification |
| **Test evidence** | 45 automated tests (`pytest`), held-out evaluation in `reports/RESULTS.md`, live demo page |
| **Objective** | SO1, SO2, SO3 |

## Function 2: Severity scoring + moderator alert (status: working; DistilBERT upgrade in progress)

| | |
|---|---|
| **Function name** | `severity.fit_weights / score / level`, `SEDetector.analyze()` |
| **Owner** | D.M.T. Dissanayaka |
| **Input** | signal vector x = [P, U, A, F, R] |
| **Processing logic** | S = wₚP + wᵤU + wₐA + w_fF + wᵣR. The weights are **learned** from validation data (logistic regression, non-negative, normalised to 1), and the decision threshold τ is tuned for F1 on validation. Levels LOW / MEDIUM / HIGH / CRITICAL; HIGH or CRITICAL → alert with summary + recommended action |
| **Output** | S, level, per-signal contributions ("why"), alert object |
| **Dependency** | Function 1. Output consumed by Behavioral Analytics (Jayarathna) and the dashboard |
| **Test evidence** | weights sum to 1, level boundaries, deterministic output, latency budget tests; ablation study |
| **Objective** | SO4, SO5, SO6 |
| **In progress** | DistilBERT text model (`scripts/finetune_distilbert.py`, needs GPU), severity validation against expert labels |

## Objective → Function → Metric → Evidence

| Objective | Function | Metric | PP1 evidence |
|---|---|---|---|
| SO1 data | loader + cleaning | rows, duplicates removed, split sizes | 5,574 → 5,159 after removing 415 duplicates; 70/15/15 stratified split |
| SO2 classifier | F1 text model | F1, FPR | SMS test F1 0.973, FPR 0.000 |
| SO3 tactics | F1 manipulation detector | per-tactic P/R/F1 | urgency F1 0.89, fear 0.93, authority 0.57 (chat test) |
| SO4 hybrid | F1 + F2 | chat F1 vs text-only | 0.667 → 0.923 (95% CI of the gain +0.13 to +0.40) |
| SO5 severity | F2 | level distribution, alerts | severity bands working; validation vs expert labels planned |
| SO6 comparison | evaluate.py | F1, FPR, FNR, latency | E1/E2 baselines, ablation, p95 latency 3.7 ms |
