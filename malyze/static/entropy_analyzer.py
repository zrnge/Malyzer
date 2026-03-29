"""Entropy analysis — detects packed/encrypted/obfuscated regions."""

import math
from typing import Optional


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def classify_entropy(entropy: float) -> str:
    if entropy < 1.0:
        return "Very Low (plaintext / sparse)"
    if entropy < 4.0:
        return "Low (text/code)"
    if entropy < 6.0:
        return "Medium (mixed data)"
    if entropy < 7.0:
        return "High (compressed or encrypted candidate)"
    return "Very High (likely packed/encrypted/compressed)"


def analyze_file_entropy(file_path: str) -> dict:
    with open(file_path, "rb") as f:
        data = f.read()

    overall = calculate_entropy(data)

    # Block-based analysis (256 blocks)
    block_size = max(256, len(data) // 256)
    blocks = []
    for i in range(0, len(data), block_size):
        chunk = data[i : i + block_size]
        e = calculate_entropy(chunk)
        blocks.append(round(e, 3))

    high_entropy_blocks = sum(1 for e in blocks if e >= 7.0)

    return {
        "overall_entropy": overall,
        "classification": classify_entropy(overall),
        "total_blocks": len(blocks),
        "high_entropy_blocks": high_entropy_blocks,
        "high_entropy_ratio": round(high_entropy_blocks / max(len(blocks), 1), 3),
        "block_entropies": blocks[:64],  # first 64 for display
        "suspicious": overall >= 7.0 or (high_entropy_blocks / max(len(blocks), 1)) > 0.5,
    }


def analyze_pe_sections_entropy(pe_sections: list) -> list:
    """
    Accepts a list of dicts with 'name' and 'data' (bytes) keys.
    Returns enriched list with entropy added.
    """
    results = []
    for section in pe_sections:
        data = section.get("data", b"")
        entropy = calculate_entropy(data)
        results.append({
            **section,
            "entropy": entropy,
            "entropy_class": classify_entropy(entropy),
            "suspicious": entropy >= 7.0,
        })
    return results
