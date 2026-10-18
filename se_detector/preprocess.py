"""Text preprocessing for live-chat messages.

Chat text is noisy: emojis, l33t-speak ("fr33 n1tro"), stretched words
("freeeee"), homoglyphs and URLs. This module turns a raw message into a
clean, lower-cased string the classifier and the rule detectors can share,
while keeping the original URLs aside for the pattern detector.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

URL_RE = re.compile(
    r"(?:(?:https?://|www\.)[^\s<>\"']+)"
    r"|(?:\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|gg|xyz|ru|tk|ml|ga|cf|top|info|biz|link|site|online|app|me|co|ly)\b(?:/[^\s<>\"']*)?)",
    re.IGNORECASE,
)
EMOJI_RE = re.compile(
    "[\U0001F000-\U0001FAFF\U00002600-\U000027BF\U0001F900-\U0001F9FF️‍]+"
)
REPEAT_RE = re.compile(r"([a-z!?.])\1{2,}")  # 3+ repeated letters/punct -> 2 ("freeee" -> "free"); digits untouched (phone numbers)
SPACE_RE = re.compile(r"\s+")

# --- Evasion defence (added by D.M.T. Dissanayaka, security hardening) -------------
# Attackers hide keywords from filters with (1) invisible characters inside words,
# (2) look-alike letters from other alphabets ("аccount" with a Cyrillic "а"), and
# (3) spaced-out letters ("v e r i f y"). Each trick is undone here AND recorded,
# because using an evasion trick is itself evidence of bad intent.
HARDEN = True    # switch off only to measure the "no defence" baseline (scripts/adversarial_eval.py)
INVISIBLE_RE = re.compile("[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")
CONFUSABLES = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "к": "k", "ո": "n", "ѵ": "v",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S",
    # Greek
    "α": "a", "ο": "o", "ι": "i", "κ": "k", "ν": "v", "ρ": "p", "υ": "u", "Α": "A", "Β": "B", "Ε": "E",
    "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}
CONFUSABLE_TABLE = str.maketrans(CONFUSABLES)
LATIN_RE = re.compile(r"[A-Za-z]")
SPACED_RE = re.compile(r"(?<![a-z])(?:[a-z][ .\-_*]){3,}[a-z](?![a-z])")   # "v e r i f y" (4+ single letters)

# Common l33t substitutions used to dodge keyword filters.
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
LEET_TOKEN_RE = re.compile(r"\b(?=\w*[a-z])(?=\w*[0-9@$])[\w@$]+\b", re.IGNORECASE)


@dataclass
class CleanMessage:
    original: str
    text: str                      # normalised text used for analysis
    urls: list[str] = field(default_factory=list)
    obfuscation: list[str] = field(default_factory=list)   # evasion tricks found (security evidence)


# Tokens that legitimately mix digits and letters and must NOT be de-leeted:
# times/units/ordinals ("5pm", "10min", "2fa", "1st", "100k") and ids ("cs2", "ps5").
KEEP_TOKEN_RE = re.compile(r"^\d+(?:am|pm|st|nd|rd|th|k|m|s|h|fa|min|hr|hrs|gb|mb|p|x|v)$", re.IGNORECASE)
KEEP_IDS = {"cs2", "ps4", "ps5", "mp3", "mp4", "gta5", "r6", "fifa23", "fifa24", "2fa", "b2b"}


def _deleet(match: re.Match) -> str:
    token = match.group(0)
    if KEEP_TOKEN_RE.match(token) or token.lower() in KEEP_IDS:
        return token
    return token.translate(LEET)


def clean(message: str) -> CleanMessage:
    """Normalise one chat message. Never raises on odd input."""
    if message is None:
        message = ""
    original = str(message)
    text = unicodedata.normalize("NFKC", original)   # fold full-width / stylised letters
    obfuscation: list[str] = []
    if HARDEN:
        text, obfuscation = _undo_evasion(text)
    urls = URL_RE.findall(text)
    text = URL_RE.sub(" URL ", text)
    text = EMOJI_RE.sub(" ", text)
    text = text.lower()
    text = LEET_TOKEN_RE.sub(_deleet, text)
    if HARDEN:
        text, spaced = _join_spaced(text)
        if spaced:
            obfuscation.append("spaced-out letters")
    text = REPEAT_RE.sub(r"\1\1", text)
    text = SPACE_RE.sub(" ", text).strip()
    text = text.replace("url", "URL")
    return CleanMessage(original=original, text=text, urls=urls, obfuscation=obfuscation)


def _join_spaced(text: str) -> tuple[str, bool]:
    """Join "v e r i f y" -> "verify". Runs of one repeated letter ("x x x x" kisses) are left alone."""
    hit = False

    def fix(m: re.Match) -> str:
        nonlocal hit
        letters = re.sub(r"[ .\-_*]", "", m.group(0))
        if len(set(letters)) < 3:
            return m.group(0)
        hit = True
        return letters
    return SPACED_RE.sub(fix, text), hit


def _undo_evasion(text: str) -> tuple[str, list[str]]:
    found: list[str] = []
    if INVISIBLE_RE.search(text):
        found.append("invisible characters")
        text = INVISIBLE_RE.sub("", text)
    if any(ch in CONFUSABLES for ch in text):
        # Only fold look-alikes when the message is mainly Latin script, so real
        # Russian / Greek messages are left alone. A word that mixes scripts is the trick.
        mixed = any(LATIN_RE.search(w) and any(ch in CONFUSABLES for ch in w) for w in text.split())
        latin = len(LATIN_RE.findall(text))
        foreign = sum(ch in CONFUSABLES for ch in text)
        if mixed or latin > foreign:
            found.append("look-alike letters from another alphabet")
            text = text.translate(CONFUSABLE_TABLE)
    return text, found
