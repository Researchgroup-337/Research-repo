"""Unit, component and failure-path tests (Lecture 9 testing hierarchy).

Run:  python -m pytest -q
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from se_detector import manipulation, patterns, severity
from se_detector.pipeline import SEDetector
from se_detector.preprocess import clean


@pytest.fixture(scope="module")
def det():
    return SEDetector()


# ---------------- unit: preprocessing (FR02) ----------------
def test_clean_deleets_obfuscation():
    assert "free nitro" in clean("FR33 N1TRO").text


def test_clean_keeps_times_and_phone_numbers():
    c = clean("meet at 5pm, call +1-800-555-0199")
    assert "5pm" in c.text and "555" in c.text


def test_clean_extracts_urls():
    c = clean("claim at dlscord-gifts.xyz/claim now")
    assert c.urls == ["dlscord-gifts.xyz/claim"] and "URL" in c.text


@pytest.mark.parametrize("bad", [None, "", "   ", "🔥🔥🔥", "a" * 10000, "\x00\x01"])
def test_clean_never_raises(bad):
    clean(bad)


# ---------------- unit: manipulation (FR04-FR06) ----------------
@pytest.mark.parametrize("text,tactic", [
    ("verify within 10 minutes", "urgency"),
    ("last chance to claim", "urgency"),
    ("i'm from discord support", "authority"),
    ("this is the stream admin", "authority"),
    ("your account will be permanently banned", "fear"),
    ("pay now to avoid arrest", "fear"),
])
def test_tactic_detected(text, tactic):
    assert tactic in manipulation.detect(text)["tactics"]


@pytest.mark.parametrize("text", ["lol that play was insane", "what settings do you use?", "gg everyone"])
def test_no_tactic_on_benign(text):
    assert manipulation.detect(text)["tactics"] == []


def test_evidence_is_explainable():
    r = manipulation.detect("your account will be banned")
    assert any(e["match"] == "your account will be banned" for e in r["evidence"])


# ---------------- unit: patterns (FR07) ----------------
def test_credential_request():
    assert "credential_request" in patterns.detect("send me your password")["patterns"]


def test_suspicious_link_signals():
    r = patterns.url_signals(["bit.ly/abc", "twitch-verify-support.com"])
    assert r["score"] > 0.8


def test_benign_link_low_risk():
    assert patterns.url_signals(["youtube.com"])["score"] < 0.5


# ---------------- unit: severity (FR08, FR09) ----------------
def test_weights_sum_to_one(det):
    assert abs(sum(det.weights.values()) - 1) < 1e-3 and all(w >= 0 for w in det.weights.values())


@pytest.mark.parametrize("s,expected", [(0.05, "LOW"), (0.3, "MEDIUM"), (0.7, "HIGH"), (0.9, "CRITICAL")])
def test_levels(s, expected):
    assert severity.level(s, 0.18) == expected


def test_score_bounded():
    w = {"P": .4, "U": .1, "A": .2, "F": .1, "R": .2}
    assert severity.score({k: 1.0 for k in w}, w) == pytest.approx(1.0)
    assert severity.score({k: 0.0 for k in w}, w) == 0


# ---------------- component: full pipeline (FR01, FR10, FR11) ----------------
def test_attack_is_flagged_with_alert(det):
    r = det.analyze("Hi, I'm from Twitch Trust & Safety. Verify your account in the next 30 minutes or it will be "
                    "permanently banned: twitch-verify-support.com")
    assert r["is_social_engineering"] and r["severity"]["level"] in {"HIGH", "CRITICAL"} and r["alert"]
    assert set(r["manipulation"]["tactics"]) == {"urgency", "authority", "fear"}
    assert r["urls"] == ["twitch-verify-support.com"]


@pytest.mark.parametrize("text", ["gg everyone, see you tomorrow", "can you play the next map please",
                                  "PSA: there are scammers sending fake nitro links, don't click them"])
def test_benign_not_flagged(det, text):
    r = det.analyze(text)
    assert not r["is_social_engineering"] and r["alert"] is None


def test_result_contract_keys(det):
    r = det.analyze("hello")
    for k in ["component", "model_version", "message_id", "is_social_engineering", "phishing_probability",
              "manipulation", "patterns", "urls", "severity", "alert", "latency_ms"]:
        assert k in r


def test_deterministic(det):          # NFR03 reliability
    a = det.analyze("claim free nitro now at dlscord.xyz", message_id="x")
    b = det.analyze("claim free nitro now at dlscord.xyz", message_id="x")
    a.pop("latency_ms"); b.pop("latency_ms")
    assert a == b


@pytest.mark.parametrize("bad", ["", "   ", None, "x" * 50000, "<script>alert(1)</script>"])
def test_failure_paths(det, bad):     # failure path: empty / huge / hostile input
    r = det.analyze(bad)
    assert 0 <= r["severity"]["score"] <= 1


def test_latency_budget(det):          # NFR01 - well under 50 ms per message on CPU
    import time
    t = time.perf_counter()
    for _ in range(100):
        det.analyze("Your account will be suspended today. Verify at bit.ly/x")
    assert (time.perf_counter() - t) / 100 < 0.05
