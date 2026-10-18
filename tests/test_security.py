"""Security tests: evasion tricks and the moderator API (added by D.M.T. Dissanayaka)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from se_detector.pipeline import SEDetector
from se_detector.preprocess import clean

SCAM = ("Hi, I'm from Twitch Trust & Safety. Verify your account in the next 30 minutes "
        "or it will be permanently banned: twitch-verify-support.com")


@pytest.fixture(scope="module")
def det():
    return SEDetector()


# --- evasion defence -------------------------------------------------------
def test_cyrillic_lookalikes_are_undone_and_recorded():
    c = clean(SCAM.replace("a", "а").replace("o", "о"))
    assert "verify your account" in c.text
    assert "look-alike letters from another alphabet" in c.obfuscation
    assert c.urls == ["twitch-verify-support.com"]      # the hidden link is recovered too


def test_invisible_characters_are_removed():
    c = clean("ver​ify your acc‍ount")
    assert c.text == "verify your account" and "invisible characters" in c.obfuscation


def test_spaced_letters_are_joined_but_kisses_are_not():
    assert clean("v e r i f y your a c c o u n t").text == "verify your account"
    assert clean("love u x x x x").obfuscation == []


def test_real_russian_text_is_not_changed():
    c = clean("Привет, как дела?")
    assert c.text == "привет, как дела?" and c.obfuscation == []


@pytest.mark.parametrize("trick", [
    lambda t: t.replace("a", "а").replace("e", "е").replace("o", "о"),
    lambda t: " ".join(w[:2] + "​" + w[2:] if len(w) > 3 else w for w in t.split(" ")),
    lambda t: t.replace("Verify", "V e r i f y").replace("banned", "b a n n e d"),
], ids=["homoglyph", "invisible", "spacing"])
def test_evasion_does_not_lower_the_level(det, trick):
    base = det.analyze(SCAM)["severity"]["level"]
    r = det.analyze(trick(SCAM))
    assert r["severity"]["level"] == base == "CRITICAL"
    assert "evasion_obfuscation" in r["patterns"]["detected"]
