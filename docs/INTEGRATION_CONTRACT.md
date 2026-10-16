# Integration contract: Social Engineering Detection component

**Owner:** D.M.T. Dissanayaka (IT23223462) · **Project:** J26-CS-337 · **Version:** 0.3.0

## Position in the group pipeline

```
Live chat → Data Acquisition (shared) → ┬→ Malicious URL Verification (Gunarathna)
                                        ├→ Hate Speech Detection (Mendis)
                                        ├→ SOCIAL ENGINEERING DETECTION (this component)
                                        └→ (all verdicts) → Behavioral Analytics + Risk (Jayarathna) → Dashboard
```

## Input (produced by Data Acquisition, owner: shared)

`POST /analyze` with `Content-Type: application/json`

| field | type | required | notes |
|---|---|---|---|
| `text` | string | yes | raw message, longer than 2,000 chars is truncated; empty → HTTP 422 |
| `message_id` | string | no | generated (UUID) if absent |
| `user_id` | string | no | **pseudonymous** id only, never a real username |
| `channel_id` | string | no | stream/channel id |

Batch: `POST /analyze/batch` with `{"messages": [ ...up to 200 ]}`.

## Output (consumed by Behavioral Analytics, URL Verification and the Dashboard)

Real output for: *"Hi, I'm from Twitch Trust & Safety. Your channel was reported for a violation. Verify your account in the next 30 minutes or it will be permanently banned: twitch-verify-support.com"* (evidence lists shortened)

```json
{
  "component": "social_engineering",
  "model_version": "0.3.0",
  "message_id": "m6", "user_id": "u_3fa2", "channel_id": "demo",
  "is_social_engineering": true,
  "phishing_probability": 0.9234,
  "manipulation": {
    "tactics": ["urgency", "authority", "fear"],
    "scores": {"urgency": 0.5934, "authority": 0.9649, "fear": 0.9502},
    "evidence": [{"tactic": "urgency", "cue": "explicit time limit", "match": "in the next 30 minutes", "weight": 0.9}]
  },
  "patterns": {"detected": ["account_verification", "suspicious_link"], "evidence": {}, "risk": 0.6199},
  "urls": ["twitch-verify-support.com"],
  "severity": {"score": 0.8384, "level": "CRITICAL", "threshold": 0.18,
               "contributions": {"P": 0.362, "U": 0.0511, "A": 0.1608, "F": 0.1275, "R": 0.137}},
  "alert": {"level": "CRITICAL", "summary": "Critical social-engineering risk: urgency, authority, fear, account verification, suspicious link", "recommended_action": "remove message and timeout sender"},
  "latency_ms": 2.7
}
```

| consumer | fields used |
|---|---|
| Behavioral Analytics (Jayarathna) | `user_id`, `severity.score`, `severity.level`, `manipulation.tactics`: an extra risk signal for repeat-offender scoring |
| URL Verification (Gunarathna) | `urls`: deep check (blacklist, homograph, sandbox). This component only does cheap local URL heuristics |
| Dashboard / reports | `alert`, `severity`, `manipulation.evidence` (the "why") |

## Severity levels

| level | S range | action |
|---|---|---|
| LOW | S < τ (0.18) | not flagged |
| MEDIUM | τ ≤ S < 0.60 | flagged, moderator queue |
| HIGH | 0.60 ≤ S < 0.80 | **alert** |
| CRITICAL | S ≥ 0.80 | **alert**, act first |

## Failure behaviour

* Empty text → 422. Missing field → 422. Over 200 messages in a batch → 422.
* Odd input (emoji only, control characters, 50k chars) → never crashes; truncated and scored.
* If this service is down, the other components keep working; the dashboard shows "SE: unavailable".
* Health check: `GET /health` returns the model version, weights and threshold.

## Privacy

The service runs locally (localhost), nothing is written to disk, and the alert buffer keeps ids and verdicts only. It never keeps message text.
