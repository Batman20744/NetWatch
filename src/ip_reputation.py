"""AbuseIPDB reputation lookups. API key is read from environment only."""
import ipaddress
import json
import os
import time
from dotenv import load_dotenv

load_dotenv()
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

_CACHE = {}
CACHE_SECONDS = 1800


def check_ip_reputation(value):
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 or IPv6 address.") from exc
    if not address.is_global:
        raise ValueError("Only public IP addresses can be checked with the reputation service.")

    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("AbuseIPDB API key is not configured. Add ABUSEIPDB_API_KEY to your environment.")

    cached = _CACHE.get(str(address))
    if cached and time.time() - cached[0] < CACHE_SECONDS:
        result = dict(cached[1])
        result["cached"] = True
        return result

    query = urlencode({"ipAddress": str(address), "maxAgeInDays": "90"})
    request = Request(
        f"https://api.abuseipdb.com/api/v2/check?{query}",
        headers={"Key": api_key, "Accept": "application/json", "User-Agent": "NetWatch/1.0"},
    )
    try:
        with urlopen(request, timeout=12) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        if exc.code in (401, 403):
            raise RuntimeError("AbuseIPDB rejected the API key or plan permissions.") from exc
        raise RuntimeError(f"AbuseIPDB request failed (HTTP {exc.code}).") from exc
    except (URLError, TimeoutError) as exc:
        raise RuntimeError("Could not reach AbuseIPDB. Check your internet connection.") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("AbuseIPDB returned an unreadable response.") from exc

    data = payload.get("data", {})
    score = int(data.get("abuseConfidenceScore", 0))
    result = {
        "ip": str(address),
        "abuse_confidence_score": score,
        "total_reports": int(data.get("totalReports", 0)),
        "country_code": data.get("countryCode") or "Unknown",
        "isp": data.get("isp") or "Unknown",
        "domain": data.get("domain") or "Unknown",
        "is_tor": bool(data.get("isTor", False)),
        "last_reported_at": data.get("lastReportedAt"),
        "risk": "High" if score >= 70 else "Medium" if score >= 30 else "Low",
        "cached": False,
        "provider": "AbuseIPDB",
    }
    _CACHE[str(address)] = (time.time(), result)
    return result
