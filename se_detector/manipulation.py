"""Psychological-manipulation detector (Module 3 in the proposal).

Detects the three persuasion tactics the research focuses on:

* **Urgency**   - pressure to act immediately (time limits, scarcity, "now").
* **Authority** - claims to be, or speak for, a trusted institution or role.
* **Fear**      - threatens negative consequences for the reader.

Each tactic is a small, editable list of weighted cues (regular expressions)
derived from Cialdini's influence principles and the phishing-susceptibility
literature (Parsons et al.; time-pressure studies). A cue that only hints at a
tactic (e.g. a brand name on its own) gets a low weight; an explicit claim
("I'm from Twitch support", "your account will be banned") gets a high one.

The score for a tactic is ``1 - exp(-sum(weights))`` so that

* one strong cue  -> ~0.6
* two strong cues -> ~0.85
* weak cue alone  -> ~0.25

which keeps the value in [0, 1] and saturates instead of growing without
bound. Every hit is returned with the matched text so moderators can see *why*
a message was flagged (NFR06 - explainability).

Rules live in plain data (``CUES``) so they can be updated without changing
the rest of the system (NFR07 - maintainability).
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, asdict

# ---------------------------------------------------------------------------
# Cue lexicons: (pattern, weight, short description)
# Patterns run on the *cleaned*, lower-cased text from preprocess.clean().
# ---------------------------------------------------------------------------
_BRANDS = (r"discord|twitch|youtube|steam|paypal|epic(?: games)?|riot(?: games)?|microsoft|apple|"
           r"icloud|amazon|netflix|instagram|facebook|meta|google|adsense|dhl|fedex|bank(?: of [a-z]+)?|"
           r"spotify|roblox|valve|sony|playstation|xbox|binance|coinbase")
_ROLES = (r"mod(?:erator)?s?|admin(?:istrator)?|staff|support|security|trust (?:&|and) safety|"
          r"developer|dev team|partner team|it department|manager|organi[sz]er|officer|recruiter")

CUES: dict[str, list[tuple[str, float, str]]] = {
    "urgency": [
        (r"\b(?:right now|immediately|asap|urgent(?:ly)?|at once|without delay)\b", 0.9, "immediate-action demand"),
        (r"\bnow\b", 0.7, "'now'"),
        (r"\b(?:within|in) (?:the next )?\d+ ?(?:sec(?:ond)?s?|min(?:ute)?s?|hours?|hrs?|h|days?)\b", 0.9, "explicit time limit"),
        (r"\bwithin the hour\b|\bby (?:today|tonight|midnight|tomorrow)\b|\bbefore (?:midnight|tonight|it'?s too late|it runs out|they delete)", 0.9, "deadline"),
        (r"\b(?:expires?|expiring|ends?|closes?|close) (?:in|soon|today|tonight)\b|\bspots? close\b", 0.8, "expiry"),
        (r"\b(?:last|final) (?:chance|notice|warning)\b", 0.9, "last chance / final notice"),
        (r"\b(?:limited|exclusive) (?:time|offer|spots?)\b|\bonly \d+ (?:\w+ ){0,3}(?:spots?|codes?|left|people)\b|\bfirst \d+ (?:people|users)\b", 0.8, "scarcity"),
        (r"\b(?:hurry|act fast|quick(?:ly)?|don'?t (?:wait|miss|ignore))\b", 0.8, "hurry"),
        (r"\b\d+ (?:sec(?:ond)?s?|min(?:ute)?s?|hours?|days?) left\b|\bneed (?:it|this|them|you|the money) (?:today|now|asap|urgently)\b", 0.8, "countdown / immediate need"),
        (r"\btoday\b|\btonight\b", 0.4, "'today'"),
    ],
    "authority": [
        (rf"\b(?:i'?m|i am|this is|we are|we're|here is)(?: \w+)?(?: from| with| of| on behalf of)? (?:the )?(?:{_BRANDS})(?: \w+)? (?:{_ROLES}|team)\b", 1.2, "claims institutional role"),
        (rf"\b(?:i'?m|i am|this is|we are|we're)(?: (?:a|an|the|one of the|your))?(?: \w+)? (?:{_ROLES}|government \w+ officer|streamer'?s \w+)\b", 0.9, "claims trusted role"),
        (rf"\b(?:message|contact|dm|ask) (?:the|an?|our) (?:{_ROLES})\b", 0.8, "redirects to an 'official' contact"),
        (r"\bour (?:tos|terms|policy|policies|guidelines|records|systems?)\b", 0.8, "speaks as the platform"),
        (rf"\b(?:i'?m|i am|this is|hello,? (?:this is )?|hi,? (?:i'?m )?)(?: \w+)? (?:from|with) (?:the )?(?:{_BRANDS}|{_ROLES}|it department|tournament)", 1.0, "claims to be from an organisation"),
        (rf"\b(?:{_BRANDS}) (?:support|security|staff|team|partner|alert|trust)\b", 0.9, "brand + official function"),
        (rf"^\[?(?:{_ROLES}|official|twitch staff|admin)\]|\[(?:mod|admin|staff|official)\]|\badmin here\b|\bsupport here\b", 1.0, "role tag / sign-off"),
        (r"\b(?:police|fbi|cyber division|government|court|irs|tax office|customs)\b", 0.6, "law-enforcement / government"),
        (r"\bofficial\b", 0.4, "'official'"),
        (rf"\b(?:{_BRANDS})\b", 0.25, "brand mention"),
        (r"\bdear (?:customer|user|member|voucher holder)\b", 0.5, "institutional salutation"),
    ],
    "fear": [
        (r"\b(?:your|ur)\s(?:\w+\s){0,3}(?:will|would|is going to|gonna|has been|have been|was|is|are) (?:be )?(?:permanently )?"
         r"(?:banned|suspended|terminated|locked|disabled|deleted|closed|removed|blocked|frozen|blacklisted|flagged|compromised|hacked|leaked|charged|encrypted|stolen)",
         1.2, "threat to the reader's account/asset"),
        (r"\b(?:or|otherwise|unless)\b[^.!?]{0,60}\b(?:banned|suspended|terminated|locked|disabled|deleted|removed|lose|lost|muted|arrest|returned|encrypted|charged|send them)", 1.0, "'or else' consequence"),
        (r"\b(?:you'?ll|you will|you'?re going to) (?:lose|be banned|get banned|be muted|get muted|be arrested)", 1.0, "personal loss threat"),
        (r"\b(?:unauthori[sz]ed|suspicious|unusual) (?:login|access|activity|transaction|sign-?in)\b|\bsomeone tried to access\b", 0.9, "security incident claim"),
        (r"\b(?:infected|virus(?:es)?|malware detected|hacked|breach|compromised|leaked)\b", 0.7, "compromise claim"),
        (r"\b(?:violation|violated|illegal activity|under investigation|money laundering|cybercrime|copyright strikes?)\b", 0.8, "accusation"),
        (r"\b(?:arrest|legal action|fine of|lawsuit|warrant)\b", 0.7, "legal threat"),
        (r"\bwill be (?:permanently )?(?:banned|suspended|terminated|locked|disabled|deleted|closed|removed|blocked|frozen|charged)\b", 0.8, "loss/sanction threat"),
        (r"\bto avoid\b[^.!?]{0,30}\b(?:loss|arrest|ban|suspension|penalt\w*|charges?|termination|deletion)\b", 0.9, "'to avoid' consequence"),
        (r"\b(?:permanently|forever)\b", 0.4, "permanence"),
        (r"\bwarning\b|\balert\b|\bdo not ignore\b", 0.4, "alarm wording"),
    ],
}

_COMPILED = {t: [(re.compile(p, re.IGNORECASE), w, d) for p, w, d in cues] for t, cues in CUES.items()}
TACTICS = tuple(CUES)
TACTIC_THRESHOLD = 0.5   # score >= 0.5 -> tactic reported as present


@dataclass
class Hit:
    tactic: str
    cue: str
    match: str
    weight: float


def _saturate(total: float) -> float:
    return round(1.0 - math.exp(-total), 4)


def detect(text: str) -> dict:
    """Return per-tactic scores in [0,1], the tactics present, and evidence hits."""
    hits: list[Hit] = []
    scores: dict[str, float] = {}
    for tactic, cues in _COMPILED.items():
        total = 0.0
        for rx, weight, desc in cues:
            m = rx.search(text)
            if m:
                total += weight
                hits.append(Hit(tactic, desc, m.group(0).strip(), weight))
        scores[tactic] = _saturate(total)
    present = [t for t in TACTICS if scores[t] >= TACTIC_THRESHOLD]
    return {"scores": scores, "tactics": present, "evidence": [asdict(h) for h in hits]}
