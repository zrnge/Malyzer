"""
Deep Threat Intelligence Lookups
Provides functions to query Shodan for IP intel and AlienVault OTX for general IOCs.
"""

import requests
from typing import Dict, Any

_TIMEOUT = 15

def lookup_shodan(ip: str, api_key: str) -> Dict[str, Any]:
    """Query Shodan for an IP address to find open ports, banners, and vulnerabilities."""
    if not api_key or api_key.startswith("YOUR_"):
        return {"error": "shodan_api_key not configured"}
        
    try:
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
            timeout=_TIMEOUT
        )
        if resp.status_code == 404:
            return {"found": False, "ip": ip}
        resp.raise_for_status()
        
        data = resp.json()
        return {
            "found": True,
            "ip": ip,
            "os": data.get("os"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "vulns": data.get("vulns", []),
            "tags": data.get("tags", []),
            "last_update": data.get("last_update")
        }
    except Exception as e:
        return {"error": str(e)}

def lookup_otx(indicator: str, indicator_type: str, api_key: str) -> Dict[str, Any]:
    """
    Query AlienVault OTX for an indicator.
    indicator_type: IPv4, IPv6, domain, hostname, file
    """
    if not api_key or api_key.startswith("YOUR_"):
        return {"error": "otx_api_key not configured"}
        
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general",
            headers={"X-OTX-API-KEY": api_key},
            timeout=_TIMEOUT
        )
        if resp.status_code == 404:
            return {"found": False, "indicator": indicator}
        resp.raise_for_status()
        
        data = resp.json()
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        
        return {
            "found": pulse_info.get("count", 0) > 0,
            "indicator": indicator,
            "type": data.get("type"),
            "pulse_count": pulse_info.get("count", 0),
            "pulses": [
                {
                    "name": p.get("name"),
                    "author": p.get("author_name"),
                    "tags": p.get("tags", []),
                    "malware_families": p.get("malware_families", []),
                    "targeted_countries": p.get("targeted_countries", [])
                }
                for p in pulses[:10]  # Return top 10 pulses to save space
            ]
        }
    except Exception as e:
        return {"error": str(e)}
