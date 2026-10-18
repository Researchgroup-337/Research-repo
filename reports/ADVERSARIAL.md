# Evasion-attack test (security hardening)

103 held-out attack messages (chat test + Zenodo test), each rewritten with an evasion trick (seed 7).
Detection rate = share still flagged as social engineering (S >= tau).

| Evasion trick | Detection: no defence | Detection: with defence | Alerts (HIGH+): no defence | Alerts: with defence |
|---|---|---|---|---|
| none (original) | 0.99 | 0.99 | 0.46 | 0.46 |
| homoglyph | 0.69 | 1.00 | 0.00 | 0.66 |
| invisible | 0.76 | 1.00 | 0.01 | 0.66 |
| spacing | 0.94 | 0.99 | 0.22 | 0.62 |
| leetspeak | 0.99 | 0.99 | 0.41 | 0.41 |
| combined | 0.23 | 1.00 | 0.00 | 0.66 |

Benign false-positive rate (710 held-out benign messages): no defence 0.024, with defence 0.024.
