"""Integration tests for the REST interface used by the other components."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fastapi.testclient import TestClient

from se_detector.api import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_analyze_ok():
    r = client.post("/analyze", json={"text": "free nitro, claim now at dlscord-gifts.xyz", "user_id": "u1"})
    assert r.status_code == 200 and r.json()["user_id"] == "u1"


def test_analyze_rejects_empty():
    assert client.post("/analyze", json={"text": "  "}).status_code == 422


def test_analyze_rejects_missing_field():
    assert client.post("/analyze", json={}).status_code == 422


def test_batch_and_alert_buffer():
    msgs = [{"text": "gg"}, {"text": "I'm from Discord support, your account will be banned in 1 hour, send your password now"}]
    r = client.post("/analyze/batch", json={"messages": msgs})
    assert r.status_code == 200 and len(r.json()) == 2
    alerts = client.get("/alerts").json()
    assert alerts and "text" not in alerts[0]       # privacy: raw text not retained
