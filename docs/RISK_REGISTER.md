# Risk register: SE detection component

| # | Risk | Likelihood | Impact | Mitigation | Status |
|---|---|---|---|---|---|
| R1 | Text model doesn't transfer to chat (domain shift) | High (observed: text-only recall 0.50 SMS-only, 0.75 with Zenodo) | High | hybrid manipulation + pattern features (recall 1.000); more chat-like data; DistilBERT | mitigated, monitoring |
| R2 | Implied authority (brand + official format) missed by lexicon | High (chat recall 0.40; third-party set 4%) | Medium | institutional-authority cues tuned on a dev half of the third-party set; DistilBERT tactic classifier | open, next task |
| R3 | Small, single-annotator scenario set → biased estimates | High | Medium | dev/test split, bootstrap CIs, independent third-party tactic set added; second annotator + κ | partially mitigated |
| R9 | Train/test leakage from near-duplicate template variants (found: 43% of Zenodo test had a ≥0.8 near-copy in train) | High | High (inflated scores) | near-duplicate grouping + group-aware split; leakage now 0% | mitigated |
| R10 | Protective advice ("never share your password", "don't click fake links") scored as a scam | Medium (was 4 of 40 benign chat msgs flagged) | Medium (alert fatigue) | protective-advice detector damps signals ×0.4 when no link is present; chat FPR 10% → 5% | mitigated |
| R11 | Low-quality public datasets (synthetic, 3 templates × 20,000 rows) | Medium | High | dataset audit before use; rejected `phishing_spam_large_dataset.csv` | mitigated |
| R4 | False positives annoy moderators (alert fatigue) | Medium | High | alerts only HIGH/CRITICAL; evidence shown; FPR tracked (0.05 chat) | mitigated |
| R5 | No GPU for DistilBERT fine-tuning | Medium | Medium | Colab T4; TF-IDF model is the fallback with the same interface | mitigated |
| R6 | Severity bands not validated against expert ratings | High | Medium | Experiment 6: moderator/supervisor rating of 50 messages | open |
| R7 | Adversarial evasion (l33t, homoglyphs, spacing) | Medium | Medium | NFKC + de-leet + char n-grams; adversarial test set planned | partially mitigated |
| R8 | Privacy: storing chat text | Low | High | local only, no disk writes, alert buffer stores ids only | mitigated |
