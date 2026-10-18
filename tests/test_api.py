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


# --- Block, receiver warning and Behavioral Analytics events (added 17 Oct) ---
def test_block_and_repeat_offender_event():
    client.post("/block", json={"user_id": "u_bad"})
    assert "u_bad" in client.get("/blocked").json()
    r = client.post("/analyze", json={"text": "I'm a mod, send me the code you just got or you'll lose your account",
                                      "user_id": "u_bad", "receiver_id": "u_victim"}).json()
    ev = r["behavioral_event"]
    assert ev["sender_blocked"] and ev["repeat_offender"] and ev["receiver_id"] == "u_victim"
    assert client.get("/events").json()[0]["message_id"] == r["message_id"]
    client.post("/unblock", json={"user_id": "u_bad"})
    assert "u_bad" not in client.get("/blocked").json()


def test_events_have_no_raw_text():
    client.post("/analyze", json={"text": "free nitro claim now dlscord-gifts.xyz", "user_id": "u2"})
    ev = client.get("/events").json()[0]
    assert "text" not in ev and {"timestamp", "level", "message_id", "receiver_id"} <= set(ev)


def test_send_warning_to_receiver():
    r = client.post("/warn", json={"message_id": "m9", "receiver_id": "u_victim", "text": "Warning: may be a scam"}).json()
    assert r["show_to"] == "u_victim" and r["sent_at"]
    pub = client.post("/warn", json={"message_id": "m10", "text": "Warning: may be a scam"}).json()
    assert pub["show_to"] == "all viewers in the channel"
    assert client.get("/warnings").json()[0]["message_id"] == "m10"
