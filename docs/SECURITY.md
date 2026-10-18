# Security design and hardening: Social Engineering Detection component

Author: D.M.T. Dissanayaka (IT23223462), J26-CS-337. Added 18 Oct 2026.

## 1. What the component defends against (MITRE ATT&CK mapping)

| What the detector finds | Example | MITRE ATT&CK technique |
|---|---|---|
| Authority / impersonation cues | "I'm from Twitch Trust & Safety", `SteamSupport#0001` | T1656 Impersonation |
| Credential / code request | "send me the 6 digit code you just got" | T1598 Phishing for Information |
| Suspicious link in chat or DM | `twitch-verify-support.com`, `dlscord-gifts.xyz` | T1566.003 Spearphishing via Service, T1204.001 User Execution: Malicious Link |
| Payment / crypto scams | "send 50 USDT and get 500 back" | T1657 Financial Theft |
| Urgency and fear pressure | "in the next 30 minutes or you'll be banned" | (persuasion used inside the techniques above; Cialdini) |

## 2. Threat model for the component itself (STRIDE, short)

| Threat | Example against this component | Control |
|---|---|---|
| **Spoofing** | Someone pretends to be a moderator and blocks innocent users through `/block` | API keys (`X-API-Key`), role check |
| **Tampering** | Attacker hides scam words so the detector misses them (evasion) | Evasion defence in `preprocess.py` (section 3) |
| **Repudiation** | A moderator denies blocking a user | Audit log of every action and every refused request |
| **Information disclosure** | Behavioral events leak chat content | Events and audit log contain ids, levels and tactics only, never message text; pseudonymous ids |
| **Denial of service** | Huge messages slow the service | Input length cap (2,000 characters analysed), batch limit 200, ~3 ms per message |
| **Elevation of privilege** | Analytics component uses its key to block users | Separate keys per role: the analytics key can read `/events` but gets 403 on `/block` |

## 3. Evasion-attack test (adversarial robustness)

Scammers dodge keyword filters by (1) swapping letters for look-alikes from other alphabets
("аccount" with a Cyrillic "а"), (2) hiding invisible zero-width characters inside words,
(3) spacing letters out ("v e r i f y"), and (4) leetspeak ("acc0unt").

**Defence (`preprocess.py`):** invisible characters are removed, look-alike letters are mapped
back to Latin (only when the message is mainly Latin script, so real Russian/Greek text is not
touched), and spaced-out letters are joined (runs of one repeated letter, like "x x x x", are left
alone). Each trick that was undone is recorded and becomes the attack pattern
`evasion_obfuscation`, because hiding words from a filter is itself evidence of an attack.

**Test (`scripts/adversarial_eval.py`, results in `reports/ADVERSARIAL.md`):** 103 held-out attack
messages (chat test + Zenodo test), each rewritten with every trick (fixed seed 7).

| Evasion trick | Detected: no defence | Detected: with defence |
|---|---|---|
| none (original) | 0.99 | 0.99 |
| look-alike letters (homoglyphs) | 0.69 | **1.00** |
| invisible characters | 0.76 | **1.00** |
| spaced-out letters | 0.94 | **0.99** |
| leetspeak (already handled before) | 0.99 | 0.99 |
| homoglyphs + invisible combined | **0.23** | **1.00** |

False alarms on 710 held-out benign messages: 2.4% with and without the defence (no increase).
Because the trick itself is evidence, alerts (HIGH+) on evaded attacks rise to 0.66, above the
0.46 for the original messages.

**Cost, reported honestly:** after retraining with the defence, the learned threshold moved from
τ = 0.17 to 0.18 (one benign validation SMS really is written "G o o d n i g h t"). One borderline
chat attack (S = 0.172) now falls just below τ, so chat F1 is 0.963 instead of 0.976 (one message
of 80, within noise). Spaced letters therefore count less (0.4) than look-alikes and invisible
characters (0.8), which never appear in the 4,943 training/validation messages.

**Not covered yet:** mixed-language scams (e.g. Sinhala/Singlish), images of text, and letters
from alphabets not in the look-alike table. Planned: Unicode TR39 confusables list, DistilBERT.

## 4. Access control and audit (API)

| Endpoint | Who may call it |
|---|---|
| `POST /analyze`, `/analyze/batch`, `GET /health`, `/` | open on localhost (data acquisition, demo page) |
| `/block`, `/unblock`, `/blocked`, `/warn`, `/warnings`, `/alerts`, `/audit` | **moderator key** |
| `/events` | **analytics key** (Jayarathna's component), read-only |

* Keys come from `SE_MODERATOR_KEY` / `SE_ANALYTICS_KEY`; if unset, random keys are generated at
  start-up and printed in the server terminal. Keys are compared with a timing-safe function.
* Missing/wrong key → 401; valid key with the wrong role → 403. Both are written to the audit log.
* Audit log: in memory (`GET /audit`) and appended to `logs/audit.jsonl` (time, action, role,
  allowed, client address, user/message ids, no message text). `logs/` is git-ignored.
* Tests: `tests/test_security.py` (evasion) and `tests/test_api.py` (401/403, least privilege, audit).

**Next:** HTTPS and rate limiting when deployed beyond localhost; key rotation.
