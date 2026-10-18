"""REST API for the Social Engineering detector (FR01, FR10, FR12).

Run:  uvicorn se_detector.api:app --port 8004
      then open http://localhost:8004  (live demo page)

Endpoints
  GET  /health            liveness + model version (NFR08)
  POST /analyze           one message  -> detection result (contract: docs/INTEGRATION_CONTRACT.md)
  POST /analyze/batch     up to 200 messages -> list of results (NFR04)
  GET  /alerts            last 100 HIGH/CRITICAL alerts (in-memory, pseudonymous ids only)
  GET  /events            last 500 behavioral events for Behavioral Analytics (Jayarathna)
  POST /block             moderator blocks a sender (pseudonymous user_id)
  POST /unblock           moderator removes a block
  GET  /blocked           currently blocked user ids
  POST /warn              moderator sends the prepared warning to the receiver (DM user or whole channel)
  GET  /warnings          warnings sent so far (what the platform connector would deliver)

Security notes (NFR05): input length is capped, nothing is written to disk,
the alert buffer stores only ids + verdicts (not raw message text), and the
service binds to localhost by default, matching the group's local-processing
privacy design.
"""
from __future__ import annotations

from collections import deque
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .pipeline import MAX_CHARS, SEDetector

STATIC = Path(__file__).resolve().parent / "static"
app = FastAPI(title="J26-CS-337 Social Engineering Detector", version="0.4.0")
detector = SEDetector()
ALERTS: deque = deque(maxlen=100)
# --- added by D.M.T. Dissanayaka: block list + events for Behavioral Analytics ---
BLOCKED: set[str] = set()
EVENTS: deque = deque(maxlen=500)
WARNINGS: deque = deque(maxlen=200)


class Message(BaseModel):
    text: str = Field(..., max_length=MAX_CHARS * 5, description="raw chat message")
    message_id: str | None = None
    user_id: str | None = Field(None, description="pseudonymous user id from the acquisition layer")
    channel_id: str | None = None
    # --- for the behavioral analytics component (added by D.M.T. Dissanayaka) ---
    receiver_id: str | None = Field(None, description="pseudonymous id of the receiver (DMs); None for public chat")
    timestamp: str | None = Field(None, description="when the message was sent (ISO 8601); server time if missing")


class BlockRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=200)


class WarnRequest(BaseModel):
    message_id: str = Field(..., min_length=1, max_length=200)
    receiver_id: str | None = Field(None, max_length=200, description="DM receiver; None = all viewers in the channel")
    channel_id: str | None = Field(None, max_length=200)
    text: str = Field(..., min_length=1, max_length=500)


class Batch(BaseModel):
    messages: list[Message] = Field(..., max_length=200)


def _run(m: Message) -> dict:
    blocked = m.user_id in BLOCKED if m.user_id else False
    res = detector.analyze(m.text, m.message_id, m.user_id, m.channel_id, m.receiver_id, m.timestamp,
                           sender_blocked=blocked)
    EVENTS.appendleft(res["behavioral_event"])      # forwarded to Behavioral Analytics
    if res["alert"]:
        ALERTS.appendleft({k: res[k] for k in ("message_id", "user_id", "channel_id", "receiver_id", "timestamp")} |
                          {"level": res["severity"]["level"], "score": res["severity"]["score"],
                           "tactics": res["manipulation"]["tactics"], "patterns": res["patterns"]["detected"]})
    return res


@app.get("/health")
def health():
    return {"status": "ok", "component": "social_engineering", "model_version": detector.version,
            "weights": detector.weights, "threshold": detector.tau}


@app.post("/analyze")
def analyze(m: Message):
    if not m.text.strip():
        raise HTTPException(status_code=422, detail="text must not be empty")
    return _run(m)


@app.post("/analyze/batch")
def analyze_batch(b: Batch):
    return [_run(m) for m in b.messages if m.text.strip()]


@app.get("/alerts")
def alerts():
    return list(ALERTS)


@app.get("/events")
def events():
    """Behavioral Analytics (Jayarathna) reads this: ids, timestamp, level, tactics. No raw text."""
    return list(EVENTS)


@app.post("/block")
def block(b: BlockRequest):
    BLOCKED.add(b.user_id)
    return {"blocked": b.user_id}


@app.post("/unblock")
def unblock(b: BlockRequest):
    BLOCKED.discard(b.user_id)
    return {"unblocked": b.user_id}


@app.get("/blocked")
def blocked():
    return sorted(BLOCKED)


@app.post("/warn")
def warn(w: WarnRequest):
    """Send the prepared warning. In the integrated system the platform connector
    (Discord / Twitch / YouTube) delivers it; here it is recorded and shown in the chat."""
    from datetime import datetime, timezone
    item = {"message_id": w.message_id, "show_to": w.receiver_id or "all viewers in the channel",
            "receiver_id": w.receiver_id, "channel_id": w.channel_id, "text": w.text,
            "sent_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    WARNINGS.appendleft(item)
    return item


@app.get("/warnings")
def warnings():
    return list(WARNINGS)


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
