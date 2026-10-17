"""Phishing / social-engineering pattern detector (Module 4 in the proposal).

Where ``manipulation.py`` asks *how* the reader is being pressured, this module
asks *what the attacker wants the reader to do*. The patterns come from the
proposal (account verification, credential request, suspicious call to action,
impersonation, threatening consequences, suspicious links) plus two that are
very common in live-stream chat: reward bait (fake giveaways / free Nitro) and
moving the victim off-platform or into secrecy.

URL analysis here is deliberately *lightweight* (shorteners, risky TLDs,
brand look-alikes). Deep URL verification - blacklists, homographs, sandboxing -
belongs to Gunarathna's component; this module only uses links as one risk
signal and forwards the URLs it found in the result so that component can
check them.
"""
from __future__ import annotations

import math
import re
from urllib.parse import urlparse

PATTERNS: dict[str, list[tuple[str, float]]] = {
    "credential_request": [
        (r"\b(?:password|passcode|login(?: details| credentials| info)?|credentials|2fa|backup codes?|otp|one[- ]time (?:code|password)|"
         r"verification code|\d ?digit code|the code (?:we|i|that was|you just)|seed phrase|recovery phrase|private key|stream key|token|pin)\b", 1.0),
        (r"\b(?:card (?:number|details)|cvv|bank (?:details|login)|banking password|billing info|ssn|id card|upload your id)\b", 1.0),
    ],
    "account_verification": [
        (r"\b(?:verify|confirm|re-?verify|validate|re-?enter|update|secure|unlock|unfreeze|restore)\b[^.!?]{0,30}\b(?:account|identity|login|details|ownership|age|card|password|credentials|info)\b", 0.9),
        (r"\b(?:verify|confirm) (?:it'?s you|yourself)\b|\bverification bot\b|\bverified role\b", 0.7),
    ],
    "reward_bait": [
        (r"\b(?:free|won|winner|prize|giveaway|raffle|reward|selected|chosen|qualif(?:y|ied)|eligible|gift ?card|nitro|robux|v-?bucks|skins?|double your|guaranteed)\b", 0.6),
        (r"\b(?:claim|redeem|collect) (?:your|it|now|here|the)\b|\bclaim\b", 0.6),
    ],
    "payment_request": [
        (r"\b(?:send|pay|transfer|deposit|wire)\b[^.!?]{0,40}\b(?:\$|usd|dollars?|btc|bitcoin|eth|crypto|money|fee|paypal|cashapp|western union|gift ?cards?|wallet)", 1.0),
        (r"\b(?:processing|registration|shipping|delivery|customs) fee\b|\bbuy me a\b[^.!?]{0,20}gift card", 1.0),
    ],
    "call_to_action": [
        (r"\b(?:click|tap|open|visit|go to|log ?in(?: with| here| at)?|sign in|scan (?:the|this) qr|download|install|run the|disable your antivirus|call (?:us|\+?\d))\b", 0.6),
        (r"\b(?:reply|respond|dm me|message me|text \w+ to|call \d)", 0.4),
    ],
           # --- live-stream chat scams (added by D.M.T. Dissanayaka) ---
       "livestream_scam": [
           (r"\b(?:giving away|giveaway|airdrop)\b[^.!?]{0,60}\b(?:btc|bitcoin|eth|ethereum|usdt|usdc|crypto|sol|doge|bnb)\b", 1.0),
           (r"\bsend\b[^.!?]{0,40}\b(?:get|receive)\b[^.!?]{0,25}\bback\b", 1.0),
           (r"\b(?:talk|speak|message|dm|contact|add)\b[^.!?]{0,25}\b(?:support|staff|admin|mod)\w*\b[^.!?]{0,25}\bon (?:discord|telegram|whatsapp)\b", 0.9),
       ],
       "off_platform_or_secrecy": [
        (r"\b(?:add me on|dm me|move to dms?|message me on|telegram|whatsapp|signal|snap(?:chat)?)\b", 0.5),
        (r"\b(?:don'?t tell (?:anyone|the mods|your)|keep (?:this|it) (?:secret|between us|private)|do not tell anyone|secret from)\b", 0.9),
    ],
}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at", "grabify.link"}
RISKY_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "ru", "click", "link", "site", "online", "info", "help", "club", "gift", "free", "app"}
LOOKALIKE_RE = re.compile(r"d[il1]sc[o0]rd|tw[i1]tch|st[e3]amc[o0]mmun|youtub|paypa[l1]|amzn|netf[l1]ix|insta|nitro|steam|riot|epic|apple|microsoft|bank|verify|secure|support|login|account|gift|free|claim|reward|appeal", re.IGNORECASE)
IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

_COMPILED = {k: [(re.compile(p, re.IGNORECASE), w) for p, w in v] for k, v in PATTERNS.items()}
PATTERN_THRESHOLD = 0.4


def _host(url: str) -> str:
    u = url if "://" in url else "http://" + url
    try:
        return (urlparse(u).hostname or "").lower()
    except ValueError:
        return ""


def url_signals(urls: list[str]) -> dict:
    """Cheap, local URL risk heuristics. Returns score in [0,1] and reasons."""
    reasons: list[str] = []
    total = 0.0
    for url in urls:
        host = _host(url)
        if not host:
            continue
        total += 0.3
        reasons.append(f"link present: {host}")
        tld = host.rsplit(".", 1)[-1]
        if host in SHORTENERS:
            total += 0.6
            reasons.append(f"URL shortener hides destination: {host}")
        if tld in RISKY_TLDS:
            total += 0.5
            reasons.append(f"high-abuse TLD .{tld}")
        if IP_HOST_RE.match(host):
            total += 0.8
            reasons.append("raw IP address host")
        if host.startswith("xn--") or ".xn--" in host:
            total += 0.8
            reasons.append("punycode (possible homograph)")
        if LOOKALIKE_RE.search(host) and host.count("-") >= 1:
            total += 0.6
            reasons.append(f"brand/lure word in hyphenated domain: {host}")
        elif LOOKALIKE_RE.search(host.split(".")[0]) and tld not in {"com", "org", "net", "tv", "gg"}:
            total += 0.3
            reasons.append(f"lure word in domain: {host}")
    return {"score": round(1 - math.exp(-total), 4), "reasons": reasons}


def detect(text: str, urls: list[str] | None = None) -> dict:
    """Detect SE patterns. ``R`` (risk) combines pattern and URL evidence in [0,1]."""
    urls = urls or []
    found: dict[str, list[str]] = {}
    total = 0.0
    for name, rules in _COMPILED.items():
        best = 0.0
        for rx, w in rules:
            m = rx.search(text)
            if m:
                found.setdefault(name, []).append(m.group(0).strip())
                best = max(best, w)
        total += best
    link = url_signals(urls)
    if link["score"] >= 0.5:
        found["suspicious_link"] = link["reasons"]
    total += 1.2 * link["score"]
    # A credential/payment request combined with any lure is the classic SE "ask".
    if ("credential_request" in found or "payment_request" in found) and len(found) >= 2:
        total += 0.5
    risk = round(1 - math.exp(-0.6 * total), 4)
    return {"risk": risk, "patterns": sorted(found), "evidence": found, "url_risk": link}


# --- Protective advice (added by D.M.T. Dissanayaka, v0.5.0) -----------------
# Moderators and viewers often WARN others about scams ("PSA: don't click fake
# nitro links", "never share your password"). These mention scam words but are
# not attacks, so they are detected here and their risk is damped.
PROTECTIVE_RE = re.compile(
    r"\b(?:psa|beware|be careful|watch out|scam(?:mer)?s?|fake|"
    r"never (?:share|give|send|click|dm)|"
    r"don'?t (?:click|share|send|give|trust|fall for)|do not (?:click|share|send|give))\b",
    re.IGNORECASE,
)


def is_protective_advice(text: str) -> bool:
    return bool(PROTECTIVE_RE.search(text))