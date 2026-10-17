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
    