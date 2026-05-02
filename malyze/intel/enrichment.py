"""
IOC Enrichment Pipeline — geo-IP, URL/domain reputation, threat context.
Free APIs only (no keys required):
  - ip-api.com  (geo-IP + proxy/hosting detection, 45 req/min)
  - URLhaus     (abuse.ch URL/host blacklist)
  - CIRCL PDNS  (passive DNS history)
  - crt.sh      (certificate transparency — subdomain discovery)
  - DGA scoring (pure-Python heuristics)
"""

import socket
import threading
import requests

_TIMEOUT = 6

_PRIV_PREFIXES = (
    "10.", "127.", "0.", "::1", "fe80::", "fc00::", "169.254.",
    "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
)


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIV_PREFIXES)


def enrich_ip(ip: str) -> dict:
    """Geo-IP + proxy/hosting (ip-api.com) + URLhaus host lookup."""
    if _is_private(ip):
        return {"ip": ip, "private": True}

    result: dict = {"ip": ip, "urlhaus_hits": 0}

    # Geo / proxy / hosting
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,city,isp,org,as,proxy,hosting,query"},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            d = resp.json()
            if d.get("status") == "success":
                result.update({
                    "country":    d.get("country", ""),
                    "city":       d.get("city", ""),
                    "isp":        d.get("isp", ""),
                    "org":        d.get("org", ""),
                    "asn":        d.get("as", ""),
                    "is_proxy":   bool(d.get("proxy")),
                    "is_hosting": bool(d.get("hosting")),
                })
    except Exception:
        result["error"] = "geo_lookup_failed"

    # URLhaus host check (also accepts IPs)
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": ip},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            d = resp.json()
            if d.get("query_status") == "is_host":
                urls = d.get("urls", [])
                result["urlhaus_hits"]  = len(urls)
                result["urlhaus_threat"] = urls[0].get("threat", "") if urls else ""
    except Exception:
        pass

    return result


def enrich_domain(domain: str) -> dict:
    """URLhaus + PDNS + cert-transparency + DGA scoring for a domain."""
    result: dict = {"domain": domain, "urlhaus_hits": 0}

    # DNS resolution
    try:
        result["resolved_ip"] = socket.gethostbyname(domain)
    except Exception:
        result["resolved_ip"] = None

    # URLhaus host lookup
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            d = resp.json()
            if d.get("query_status") == "is_host":
                urls = d.get("urls", [])
                result["urlhaus_hits"]   = len(urls)
                result["urlhaus_threat"] = urls[0].get("threat", "") if urls else ""
                result["urlhaus_tags"]   = list({
                    tag for u in urls[:10] for tag in (u.get("tags") or [])
                })[:8]
    except Exception:
        pass

    # DGA scoring (pure Python, instant)
    try:
        from malyze.intel.dga_detector import score_domain
        dga = score_domain(domain)
        result["dga_score"]  = dga["score"]
        result["is_dga"]     = dga["is_dga"]
        result["dga_reasons"] = dga["reasons"]
    except Exception:
        pass

    # Passive DNS (best-effort — skip if slow)
    try:
        from malyze.intel.pdns import lookup_pdns
        pdns = lookup_pdns(domain)
        if pdns.get("total", 0) > 0:
            result["pdns_total"]    = pdns["total"]
            result["pdns_ips"]      = pdns.get("resolved_ips", [])[:5]
    except Exception:
        pass

    # Certificate transparency (best-effort)
    try:
        from malyze.intel.pdns import lookup_cert_transparency
        certs = lookup_cert_transparency(domain)
        if certs.get("total_certs", 0) > 0:
            result["cert_total"]     = certs["total_certs"]
            result["cert_subdomains"] = certs.get("subdomains", [])[:10]
            result["cert_earliest"]  = certs.get("earliest_cert", "")
    except Exception:
        pass

    return result


def enrich_url(url: str) -> dict:
    """URLhaus URL blacklist check."""
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            d = resp.json()
            if d.get("query_status") == "is_available":
                return {
                    "url":            url,
                    "urlhaus_hits":   1,
                    "urlhaus_status": d.get("url_status", ""),
                    "urlhaus_threat": d.get("threat", ""),
                    "urlhaus_tags":   d.get("tags") or [],
                }
    except Exception:
        pass
    return {"url": url, "urlhaus_hits": 0}


def enrich_iocs(
    iocs: dict,
    cfg: dict = None,
    max_ips: int = 15,
    max_domains: int = 15,
    max_urls: int = 10,
) -> dict:
    """
    Enrich extracted IOCs using parallel threads.
    Returns enriched dict with geo/reputation data per indicator.
    """
    enriched: dict = {"ips": [], "domains": [], "urls": [], "_stats": {}}
    lock = threading.Lock()

    raw_ips     = [i for i in iocs.get("ips", [])     if i][:max_ips]
    raw_domains = [d for d in iocs.get("domains", []) if d][:max_domains]
    raw_urls    = [u for u in iocs.get("urls", [])    if u][:max_urls]

    def _run(fn, items, key):
        threads = []
        for item in items:
            def _worker(x=item):
                r = fn(x)
                with lock:
                    enriched[key].append(r)
            t = threading.Thread(target=_worker, daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=_TIMEOUT + 2)

    _run(enrich_ip,     raw_ips,     "ips")
    _run(enrich_domain, raw_domains, "domains")
    _run(enrich_url,    raw_urls,    "urls")

    enriched["_stats"] = {
        "ips_queried":       len(enriched["ips"]),
        "domains_queried":   len(enriched["domains"]),
        "urls_queried":      len(enriched["urls"]),
        "suspicious_ips":    sum(1 for r in enriched["ips"]     if r.get("is_hosting") or r.get("is_proxy") or r.get("urlhaus_hits")),
        "malicious_domains": sum(1 for r in enriched["domains"] if r.get("urlhaus_hits")),
        "malicious_urls":    sum(1 for r in enriched["urls"]    if r.get("urlhaus_hits")),
    }
    return enriched
