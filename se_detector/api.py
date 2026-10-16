"""REST API for the Social Engineering detector (FR01, FR10, FR12).

Run:  uvicorn se_detector.api:app --port 8004
      then open http://localhost:8004  (live demo page)

Endpoints
  GET  /health            liveness + model version (NFR08)
  POST /analyze           one message  -> detection result (contract: docs/INTEGRATION_CONTRACT.md)
  POST /analyze/batch     up to 200 messages -> list of results (NFR04)
  GET  /alerts            last 100 HIGH/CRITICAL alerts (in-memory, pseudonymous ids only)

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
app = FastAPI(title="J26-CS-337 Social Engineering Detector", version="0.3.0")
detector = SEDetector()
ALERTS: deque = deque(maxlen=100)


class Message(BaseModel):
    text: str = Field(..., max_length=MAX_CHARS * 5, description="raw chat message")
    message_id: str | None = None
    user_id: str | None = Field(None, description="pseudonymous user id from the acquisition layer")
    channel_id: str | None = None


class Batch(BaseModel):
    messages: list[Message] = Field(..., max_length=200)


def _run(m: Message) -> dict:
    res = detector.analyze(m.text, m.message_id, m.user_id, m.channel_id)
    if res["alert"]:
        ALERTS.appendleft({k: res[k] for k in ("message_id", "user_id", "channel_id")} |
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


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
