# Risk register: SE detection component

| # | Risk | Likelihood | Impact | Mitigation | Status |
|---|---|---|---|---|---|
| R1 | Text model trained on SMS doesn't transfer to chat (domain shift) | High (observed: recall 0.50) | High | hybrid manipulation + pattern features (recall 0.90); add Zenodo + chat data; DistilBERT | mitigated, monitoring |
| R2 | Implied authority (brand + official format) missed by lexicon | High (authority recall 0.40) | Medium | DistilBERT tactic classifier; brand-impersonation features | open, PP2 |
| R3 | Small, single-annotator scenario set → biased estimates | High | Medium | dev/test split, bootstrap CIs, second annotator + κ | partially mitigated |
| R4 | False positives annoy moderators (alert fatigue) | Medium | High | alerts only HIGH/CRITICAL; evidence shown; FPR tracked (0.05 chat) | mitigated |
| R5 | No GPU for DistilBERT fine-tuning | Medium | Medium | Colab T4; TF-IDF model is the fallback with the same interface | mitigated |
| R6 | Severity bands not validated against expert ratings | High | Medium | Experiment 6: moderator/supervisor rating of 50 messages | open |
| R7 | Adversarial evasion (l33t, homoglyphs, spacing) | Medium | Medium | NFKC + de-leet + char n-grams; adversarial test set planned | partially mitigated |
| R8 | Privacy: storing chat text | Low | High | local only, no disk writes, alert buffer stores ids only | mitigated |
