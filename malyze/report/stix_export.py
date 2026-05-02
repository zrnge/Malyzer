"""
STIX 2.1 bundle export — no third-party stix2 library required.

Objects produced per analysis:
  identity        — Malyze tool (fixed UUID, stable across exports)
  malware         — classified sample
  file            — the sample as a cyber-observable
  attack-pattern  — one per MITRE ATT&CK TTP
  indicator       — one per IP / domain / URL / file-hash IOC
  relationship    — wires every indicator/attack-pattern to the malware object
"""

import datetime
import json
import uuid
from pathlib import Path


# Stable identity ID for Malyze so all bundles share the same creator reference
_MALYZE_IDENTITY_ID = "identity--3532c56d-ea72-48be-a2ad-1a53f4c9c6d4"


def _ts() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _uid(type_: str) -> str:
    return f"{type_}--{uuid.uuid4()}"


def generate_stix_bundle(analysis: dict) -> dict:
    """Return a fully valid STIX 2.1 bundle dict from a Malyze result dict."""
    now  = _ts()
    objs = []

    # ── Identity ──────────────────────────────────────────────────────────────
    objs.append({
        "type":           "identity",
        "spec_version":   "2.1",
        "id":             _MALYZE_IDENTITY_ID,
        "created":        now,
        "modified":       now,
        "name":           "Malyze",
        "identity_class": "tool",
        "description":    "AI-powered malware analysis framework (https://github.com/Zrnge/Malyze)",
    })

    # ── Malware SDO ───────────────────────────────────────────────────────────
    fi      = analysis.get("file_info", {})
    ai_s    = (analysis.get("ai_analysis") or {}).get("structured") or {}
    intel   = analysis.get("intel", {})
    hashes  = fi.get("hashes", {})

    family = (
        ai_s.get("malware_family")
        or (intel.get("_summary") or {}).get("consensus_family")
        or "unknown"
    )
    malware_id  = _uid("malware")
    raw_type    = ai_s.get("malware_type", "unknown")
    threat_lvl  = (ai_s.get("threat_level") or "unknown").lower()

    objs.append({
        "type":            "malware",
        "spec_version":    "2.1",
        "id":              malware_id,
        "created":         now,
        "modified":        now,
        "created_by_ref":  _MALYZE_IDENTITY_ID,
        "name":            family,
        "malware_types":   [raw_type] if raw_type != "unknown" else ["unknown"],
        "is_family":       False,
        "description":     ai_s.get("summary", ""),
        "labels":          [threat_lvl] if threat_lvl else [],
    })

    # ── File SCO ──────────────────────────────────────────────────────────────
    file_id  = _uid("file")
    file_obj: dict = {
        "type":         "file",
        "spec_version": "2.1",
        "id":           file_id,
        "name":         fi.get("name", "unknown"),
        "hashes":       {},
    }
    if hashes.get("md5"):    file_obj["hashes"]["MD5"]     = hashes["md5"]
    if hashes.get("sha1"):   file_obj["hashes"]["SHA-1"]   = hashes["sha1"]
    if hashes.get("sha256"): file_obj["hashes"]["SHA-256"] = hashes["sha256"]
    if hashes.get("size"):   file_obj["size"]              = hashes["size"]
    objs.append(file_obj)

    objs.append({
        "type":              "relationship",
        "spec_version":      "2.1",
        "id":                _uid("relationship"),
        "created":           now,
        "modified":          now,
        "relationship_type": "related-to",
        "source_ref":        file_id,
        "target_ref":        malware_id,
    })

    # ── Attack Patterns (TTPs) ────────────────────────────────────────────────
    for ttp in ai_s.get("ttps", [])[:20]:
        tid   = (ttp.get("id") or "").strip()
        tname = (ttp.get("name") or tid).strip()
        if not tid:
            continue
        ap_id = _uid("attack-pattern")
        url   = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}"
        objs.append({
            "type":         "attack-pattern",
            "spec_version": "2.1",
            "id":           ap_id,
            "created":      now,
            "modified":     now,
            "name":         tname,
            "external_references": [{"source_name": "mitre-attack",
                                     "external_id": tid, "url": url}],
        })
        objs.append({
            "type":              "relationship",
            "spec_version":      "2.1",
            "id":                _uid("relationship"),
            "created":           now,
            "modified":          now,
            "relationship_type": "uses",
            "source_ref":        malware_id,
            "target_ref":        ap_id,
        })

    # ── Indicators ────────────────────────────────────────────────────────────
    iocs = (analysis.get("static") or {}).get("strings", {}).get("iocs", {})

    def _add_indicator(name: str, pattern: str) -> None:
        ind_id = _uid("indicator")
        objs.append({
            "type":            "indicator",
            "spec_version":    "2.1",
            "id":              ind_id,
            "created":         now,
            "modified":        now,
            "created_by_ref":  _MALYZE_IDENTITY_ID,
            "name":            name,
            "indicator_types": ["malicious-activity"],
            "pattern":         pattern,
            "pattern_type":    "stix",
            "valid_from":      now,
        })
        objs.append({
            "type":              "relationship",
            "spec_version":      "2.1",
            "id":                _uid("relationship"),
            "created":           now,
            "modified":          now,
            "relationship_type": "indicates",
            "source_ref":        ind_id,
            "target_ref":        malware_id,
        })

    for ip in iocs.get("ips", [])[:15]:
        _add_indicator(
            f"Malicious IP: {ip}",
            f"[network-traffic:dst_ref.type = 'ipv4-addr' AND "
            f"network-traffic:dst_ref.value = '{ip}']",
        )

    for dom in iocs.get("domains", [])[:15]:
        _add_indicator(f"Malicious Domain: {dom}", f"[domain-name:value = '{dom}']")

    for url in iocs.get("urls", [])[:10]:
        if url.startswith(("http://", "https://", "ftp://")):
            safe = url.replace("'", "\\'")
            _add_indicator(f"Malicious URL: {url[:80]}", f"[url:value = '{safe}']")

    # SHA-256 file hash indicator
    if hashes.get("sha256"):
        _add_indicator(
            f"File SHA-256: {hashes['sha256']}",
            f"[file:hashes.'SHA-256' = '{hashes['sha256']}']",
        )

    return {
        "type":         "bundle",
        "id":           _uid("bundle"),
        "spec_version": "2.1",
        "objects":      objs,
    }


def write_stix_bundle(analysis: dict, output_path: str) -> str:
    """Serialise the STIX bundle to *output_path* (.stix.json).  Returns the path."""
    bundle = generate_stix_bundle(analysis)
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(p)
