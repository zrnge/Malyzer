"""
Threat intel hash lookups — MalwareBazaar (free) and VirusTotal (API key optional).

MalwareBazaar requires no API key.
VirusTotal requires a free API key (set in config: intel.virustotal_api_key).
"""

import requests
from typing import Optional


_MB_API   = "https://mb-api.abuse.ch/api/v1/"
_VT_API   = "https://www.virustotal.com/api/v3/files"
_TIMEOUT  = 15


def lookup_malwarebazaar(sha256: str) -> dict:
    """
    Query MalwareBazaar for a SHA256 hash.
    Returns structured result — no API key needed.
    """
    try:
        resp = requests.post(
            _MB_API,
            data={"query": "get_info", "hash": sha256},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("query_status") != "ok":
            return {"found": False, "source": "malwarebazaar",
                    "status": data.get("query_status", "not_found")}

        info = data.get("data", [{}])[0]
        return {
            "found":          True,
            "source":         "malwarebazaar",
            "sha256":         info.get("sha256_hash"),
            "sha1":           info.get("sha1_hash"),
            "md5":            info.get("md5_hash"),
            "file_name":      info.get("file_name"),
            "file_type":      info.get("file_type"),
            "file_size":      info.get("file_size"),
            "first_seen":     info.get("first_seen"),
            "last_seen":      info.get("last_seen"),
            "malware_family": info.get("signature"),
            "tags":           info.get("tags", []),
            "reporter":       info.get("reporter"),
            "origin_country": info.get("origin_country"),
            "delivery_method":info.get("delivery_method"),
            "intelligence":   info.get("intelligence", {}),
        }
    except requests.Timeout:
        return {"found": False, "source": "malwarebazaar", "error": "timeout"}
    except requests.ConnectionError:
        return {"found": False, "source": "malwarebazaar", "error": "no_connection"}
    except Exception as e:
        return {"found": False, "source": "malwarebazaar", "error": str(e)}


def lookup_virustotal(sha256: str, api_key: str) -> dict:
    """
    Query VirusTotal v3 for a SHA256 hash.
    Returns AV verdicts, detection ratio, malware family if known.
    """
    if not api_key or api_key.startswith("YOUR_"):
        return {"found": False, "source": "virustotal", "error": "no_api_key"}

    try:
        resp = requests.get(
            f"{_VT_API}/{sha256}",
            headers={"x-apikey": api_key},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 404:
            return {"found": False, "source": "virustotal", "status": "not_found"}
        if resp.status_code == 401:
            return {"found": False, "source": "virustotal", "error": "invalid_api_key"}
        if resp.status_code == 429:
            return {"found": False, "source": "virustotal", "error": "rate_limited"}
        resp.raise_for_status()

        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        # Collect family names from AV verdicts
        families = set()
        for av_name, av_result in results.items():
            if av_result.get("category") == "malicious":
                verdict = av_result.get("result") or ""
                if verdict:
                    families.add(verdict)

        detections  = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total_engines = sum(stats.values()) or 1

        return {
            "found":           True,
            "source":          "virustotal",
            "sha256":          sha256,
            "detection_ratio": f"{detections}/{total_engines}",
            "malicious":       stats.get("malicious", 0),
            "suspicious":      stats.get("suspicious", 0),
            "harmless":        stats.get("harmless", 0),
            "undetected":      stats.get("undetected", 0),
            "family_names":    sorted(families)[:10],
            "popular_threat_name": attrs.get("popular_threat_name"),
            "suggested_threat_label": attrs.get("suggested_threat_label"),
            "first_submission": attrs.get("first_submission_date"),
            "last_analysis":    attrs.get("last_analysis_date"),
            "times_submitted":  attrs.get("times_submitted", 0),
            "meaningful_name":  attrs.get("meaningful_name"),
            "tags":             attrs.get("tags", []),
        }
    except requests.Timeout:
        return {"found": False, "source": "virustotal", "error": "timeout"}
    except requests.ConnectionError:
        return {"found": False, "source": "virustotal", "error": "no_connection"}
    except Exception as e:
        return {"found": False, "source": "virustotal", "error": str(e)}


def enrich_sample(hashes: dict, config: dict) -> dict:
    """
    Perform all configured threat intel lookups for a sample.
    Always tries MalwareBazaar (free). Tries VirusTotal if API key is configured.

    Returns combined result dict keyed by source name.
    """
    sha256 = hashes.get("sha256", "")
    if not sha256:
        return {}

    intel_cfg = config.get("intel", {})
    results   = {}

    # MalwareBazaar — always attempt
    if intel_cfg.get("malwarebazaar", True):
        results["malwarebazaar"] = lookup_malwarebazaar(sha256)

    # VirusTotal — only if key is configured
    vt_key = intel_cfg.get("virustotal_api_key", "")
    if vt_key and not vt_key.startswith("YOUR_"):
        results["virustotal"] = lookup_virustotal(sha256, vt_key)

    # Derive a consensus family name from all sources
    families = []
    for src_data in results.values():
        if src_data.get("found"):
            f = src_data.get("malware_family") or src_data.get("popular_threat_name")
            if f:
                families.append(f)
            for fam in src_data.get("family_names", []):
                if fam:
                    families.append(fam)

    results["_summary"] = {
        "known_malware":    any(r.get("found") for r in results.values() if isinstance(r, dict)),
        "consensus_family": families[0] if families else None,
        "all_families":     list(dict.fromkeys(families))[:5],
    }

    return results
