"""
Passive DNS + Certificate Transparency lookups.

APIs (all free, no key required):
  CIRCL PDNS  — https://www.circl.lu/services/passive-dns/
  crt.sh      — https://crt.sh  (SSL cert transparency logs)
"""

import json
import requests

_TIMEOUT = 8


def lookup_pdns(domain: str) -> dict:
    """
    Query CIRCL Passive DNS for historical A / AAAA / NS / MX records.
    Returns list of records with rrtype, rdata, first/last seen timestamps.
    """
    try:
        resp = requests.get(
            f"https://www.circl.lu/pdns/query/{domain}",
            headers={"Accept": "application/json"},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return {"domain": domain, "records": [], "total": 0}

        records = []
        for line in resp.text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                records.append({
                    "rrtype":     r.get("rrtype", ""),
                    "rdata":      r.get("rdata", ""),
                    "time_first": r.get("time_first", ""),
                    "time_last":  r.get("time_last", ""),
                    "count":      r.get("count", 0),
                })
            except Exception:
                pass

        # Unique IP addresses that this domain has resolved to historically
        a_records = sorted({
            r["rdata"] for r in records if r["rrtype"] in ("A", "AAAA")
        })
        return {
            "domain":         domain,
            "records":        records[:50],
            "total":          len(records),
            "resolved_ips":   a_records[:10],
            "source":         "circl_pdns",
        }
    except Exception as e:
        return {"domain": domain, "records": [], "total": 0, "error": str(e)}


def lookup_cert_transparency(domain: str) -> dict:
    """
    Query crt.sh for TLS certificate transparency records.
    Reveals: historical subdomains, issuing CAs, earliest cert date.
    Useful for mapping C2 infrastructure.
    """
    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return {"domain": domain, "total_certs": 0, "subdomains": [], "issuers": []}

        certs      = resp.json()
        subdomains: set = set()
        issuers:    set = set()
        earliest        = None

        for c in certs[:200]:
            for name_field in ("common_name", "name_value"):
                for part in c.get(name_field, "").lower().split("\n"):
                    part = part.strip().lstrip("*.")
                    if part and "." in part:
                        subdomains.add(part)

            issuer = c.get("issuer_name", "")
            if issuer:
                issuers.add(issuer)

            not_before = c.get("not_before", "")
            if not_before and (earliest is None or not_before < earliest):
                earliest = not_before

        subdomains.discard(domain)
        return {
            "domain":        domain,
            "total_certs":   len(certs),
            "subdomains":    sorted(subdomains)[:20],
            "issuers":       sorted(issuers)[:10],
            "earliest_cert": earliest,
            "source":        "crt.sh",
        }
    except Exception as e:
        return {"domain": domain, "total_certs": 0, "subdomains": [],
                "issuers": [], "error": str(e)}
