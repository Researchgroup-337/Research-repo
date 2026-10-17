"""Live-stream chat scam cues (added by D.M.T. Dissanayaka)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from se_detector import manipulation, patterns
from se_detector.pipeline import SEDetector
from se_detector.preprocess import clean


@pytest.fixture(scope="module")
def det():
    return SEDetector()


def tactics(text):
    return manipulation.detect(clean(text).text)["tactics"]


def pats(text):
    c = clean(text)
    return patterns.detect(c.text, c.urls)["patterns"]


def test_platform_name_as_sender_is_authority():
    assert "authority" in tactics("Discord: Your account has been flagged, verify via the official bot")


def test_fake_support_handle_is_authority():
    assert "authority" in tactics("talk to SteamSupport#0001 to fix it")


def test_accidentally_reported_scam_is_fear():
    assert "fear" in tactics("bro I accidentally reported your account")


def test_crypto_giveaway_pattern():
    assert "livestream_scam" in pats("MrBeast is giving away 1000 USDT, send 50 USDT and get 500 back")


def test_off_platform_fake_support_pattern():
    assert "livestream_scam" in pats("talk to Steam support on Discord to fix it")


@pytest.mark.parametrize("text", [
    "nice stream bro, what game is next?",
    "the discord: server rules are pinned",
    "I accidentally reported the wrong guy lol sorry",
])
def test_normal_chat_not_flagged(det, text):
    assert not det.analyze(text)["is_social_engineering"]


@pytest.mark.parametrize("text", [
    "MrBeast is giving away 1000 USDT to everyone watching this live! Send 50 USDT to the wallet and get 500 back",
    "Discord: Your account has been flagged for suspicious activity. Please verify via the official bot to avoid suspension",
    "Hey bro I accidentally reported your Steam account, talk to Steam support on Discord: SteamSupport#0001 to fix it",
])
def test_livechat_scams_flagged(det, text):
    assert det.analyze(text)["is_social_engineering"]


# --- Review notice (added after user feedback, 17 Oct) ---
def test_medium_gets_review_notice_not_alert(det):
    r = det.analyze("your account has blocked")
    assert r["severity"]["level"] == "MEDIUM"
    assert r["review"] is not None and r["alert"] is None


def test_low_and_high_have_no_review(det):
    assert det.analyze("lets goooo that clutch was insane")["review"] is None
    r = det.analyze("Hi, I'm from Twitch Trust & Safety. Verify your account in the next 30 minutes or it will be permanently banned: twitch-verify-support.com")
    assert r["alert"] is not None and r["review"] is None


# --- Timestamp and receiver id for behavioral analytics (added 17 Oct) ---
def test_timestamp_and_receiver_are_passed_on(det):
    r = det.analyze("send me the code you just got", user_id="u1", receiver_id="u2",
                    timestamp="2026-10-17T14:00:00+00:00")
    assert r["receiver_id"] == "u2" and r["timestamp"] == "2026-10-17T14:00:00+00:00"


def test_timestamp_is_added_when_missing(det):
    r = det.analyze("hello chat")
    assert r["timestamp"] and r["timestamp"].startswith("20") and r["receiver_id"] is None


def test_receiver_warning_only_for_high_and_critical(det):
    hi = det.analyze("Hi, I'm from Twitch Trust & Safety. Verify your account in the next 30 minutes or it will be permanently banned: twitch-verify-support.com", receiver_id="u_v")
    assert hi["receiver_warning"]["show_to"] == "u_v"
    assert det.analyze("your account has blocked")["receiver_warning"] is None
    assert det.analyze("lets goooo")["receiver_warning"] is None
