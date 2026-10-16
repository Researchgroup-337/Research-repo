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

# Common l33t substitutions used to dodge keyword filters.
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
LEET_TOKEN_RE = re.compile(r"\b(?=\w*[a-z])(?=\w*[0-9@$])[\w@$]+\b", re.IGNORECASE)


@dataclass
class CleanMessage:
    original: str
    text: str                      # normalised text used for analysis
    urls: list[str] = field(default_factory=list)


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
    urls = URL_RE.findall(text)
    text = URL_RE.sub(" URL ", text)
    text = EMOJI_RE.sub(" ", text)
    text = text.lower()
    text = LEET_TOKEN_RE.sub(_deleet, text)
    text = REPEAT_RE.sub(r"\1\1", text)
    text = SPACE_RE.sub(" ", text).strip()
    text = text.replace("url", "URL")
    return CleanMessage(original=original, text=text, urls=urls)
