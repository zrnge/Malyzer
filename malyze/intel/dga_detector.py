"""
DGA (Domain Generation Algorithm) domain classifier.

Scores each domain 0–100 for probability of algorithmic generation.
is_dga = True when score >= 60.

Heuristics used:
  1. Shannon entropy of the SLD — random strings have high entropy
  2. Consonant density — DGA SLDs lack vowel patterns
  3. Digit density — numeric injection is common
  4. SLD length in 10–28 char range (typical DGA window)
  5. Suspicious free-hosting TLD membership
  6. No known-legitimate brand substring
"""

import math
import re


_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".online", ".site", ".fun",
    ".pw", ".tk", ".ml", ".ga", ".cf", ".gq", ".cam", ".icu",
    ".rest", ".cyou", ".monster", ".buzz", ".sbs",
}

_KNOWN_BRANDS = {
    "google", "microsoft", "amazon", "apple", "facebook", "twitter",
    "github", "cloudflare", "akamai", "fastly", "azure", "aws",
    "youtube", "instagram", "linkedin", "netflix", "spotify",
    "windows", "office", "adobe", "oracle", "cisco", "intel",
    "update", "download", "cdn", "static", "media", "mail",
    "smtp", "imap", "api", "auth", "login", "secure", "ns1", "ns2",
}


def score_domain(domain: str) -> dict:
    """Return DGA suspicion score (0–100) and per-feature reasoning."""
    domain = domain.lower().strip().rstrip(".")
    sld    = _get_sld(domain)

    if not sld or len(sld) < 5:
        return {"domain": domain, "score": 0, "reasons": [], "is_dga": False}

    score   = 0
    reasons = []

    # 1. Shannon entropy
    ent = _entropy(sld)
    if ent >= 3.8:
        score += 35
        reasons.append(f"very high entropy ({ent:.2f})")
    elif ent >= 3.2:
        score += 18
        reasons.append(f"high entropy ({ent:.2f})")

    # 2. Consonant density
    consonants  = sum(1 for c in sld if c in "bcdfghjklmnpqrstvwxyz")
    cons_ratio  = consonants / max(len(sld), 1)
    if cons_ratio > 0.70:
        score += 25
        reasons.append(f"high consonant density ({cons_ratio:.0%})")
    elif cons_ratio > 0.60:
        score += 12

    # 3. Digit density
    digits = sum(1 for c in sld if c.isdigit())
    if digits >= 4:
        score += 15
        reasons.append(f"many digits ({digits})")
    elif digits >= 2:
        score += 5

    # 4. Length in DGA range
    if 10 <= len(sld) <= 28:
        score += 10

    # 5. Suspicious TLD
    for tld in _SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 15
            reasons.append(f"suspicious TLD ({tld})")
            break

    # 6. Brand penalty
    if _matches_known(sld):
        score = max(0, score - 30)
    else:
        score += 5

    score = min(score, 100)
    return {
        "domain":            domain,
        "sld":               sld,
        "entropy":           round(ent, 2),
        "consonant_density": round(cons_ratio, 2),
        "score":             score,
        "reasons":           reasons,
        "is_dga":            score >= 60,
    }


def batch_score(domains: list) -> list:
    """Score a list of domains; returns results sorted by score descending."""
    return sorted((score_domain(d) for d in domains),
                  key=lambda x: x["score"], reverse=True)


def _get_sld(domain: str) -> str:
    parts = domain.rstrip(".").split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _matches_known(sld: str) -> bool:
    return any(brand in sld for brand in _KNOWN_BRANDS)
