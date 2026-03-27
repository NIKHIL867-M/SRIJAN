import requests
import time
import ipaddress
import os
from pathlib import Path
from dotenv import load_dotenv

# ==============================
# LOAD ENV — supports both .env and _env
# ==============================
def _load_env():
    base = Path(__file__).parent
    for name in (".env", "_env"):
        env_file = base / name
        if env_file.exists():
            load_dotenv(dotenv_path=env_file)
            print(f"✅ Loaded env from: {env_file.name}")
            return
    load_dotenv()  # fallback: search default locations

_load_env()

ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
VT_API_KEY    = os.getenv("VT_API_KEY", "").strip()

print("🔑 AbuseIPDB Key Loaded:", bool(ABUSE_API_KEY))
print("🔑 VirusTotal Key Loaded:", bool(VT_API_KEY))

# ==============================
# IN-MEMORY CACHE
# (same IP/domain won't hit the API twice in one run)
# ==============================
_CACHE = {}

def _cache_get(key):
    return _CACHE.get(key)

def _cache_set(key, value):
    _CACHE[key] = value

# ==============================
# RATE LIMITER
# AbuseIPDB free : ~1000 req/day  → 1.1 s gap is safe
# VirusTotal free:    4 req/min   → 15 s gap
# ==============================
_LAST_CALL   = {"abuse": 0, "vt": 0}
_RATE_LIMITS = {"abuse": 1.1, "vt": 15.0}

def _rate_limit(service):
    delay   = _RATE_LIMITS[service]
    elapsed = time.time() - _LAST_CALL[service]
    if elapsed < delay:
        time.sleep(delay - elapsed)
    _LAST_CALL[service] = time.time()

# ==============================
# HELPERS
# ==============================
def _is_valid_public_ip(ip):
    """True only for routable public IPv4. Skips IPv6, private, multicast, etc."""
    try:
        obj = ipaddress.ip_address(ip)
        if isinstance(obj, ipaddress.IPv6Address):
            return False
        return not (
            obj.is_private   or obj.is_loopback  or obj.is_multicast
            or obj.is_link_local or obj.is_reserved or obj.is_unspecified
        )
    except Exception:
        return False

def _safe_get(url, headers=None, params=None, timeout=10, retries=2):
    """HTTP GET with auto-retry on transient errors."""
    for attempt in range(retries + 1):
        try:
            return requests.get(url, headers=headers, params=params, timeout=timeout)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            if attempt < retries:
                time.sleep(3)
            else:
                raise

# ==============================
# ABUSEIPDB
# ==============================
def check_ip_abuseipdb(ip):
    """Check a public IPv4 address against AbuseIPDB."""

    if not _is_valid_public_ip(ip):
        return {
            "source":       "AbuseIPDB",
            "ip":           ip,
            "skipped":      True,
            "reason":       "non-public or IPv6",
            "is_malicious": False,
            "abuse_score":  0
        }

    cached = _cache_get(f"abuse:{ip}")
    if cached:
        return cached

    if not ABUSE_API_KEY:
        return {
            "source":       "AbuseIPDB",
            "ip":           ip,
            "error":        "API key not configured",
            "is_malicious": False,
            "abuse_score":  0
        }

    try:
        _rate_limit("abuse")
        resp = _safe_get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90}
        )

        if resp.status_code == 429:
            return {"source": "AbuseIPDB", "ip": ip, "error": "Rate limit (429)", "is_malicious": False, "abuse_score": 0}
        if resp.status_code != 200:
            return {"source": "AbuseIPDB", "ip": ip, "error": f"HTTP {resp.status_code}", "is_malicious": False, "abuse_score": 0}

        d = resp.json().get("data", {})
        score = d.get("abuseConfidenceScore", 0)

        result = {
            "source":        "AbuseIPDB",
            "ip":            ip,
            "abuse_score":   score,
            "total_reports": d.get("totalReports", 0),
            "country":       d.get("countryCode", "?"),
            "isp":           d.get("isp", "?"),
            "is_malicious":  score > 50
        }

    except Exception as e:
        result = {"source": "AbuseIPDB", "ip": ip, "error": str(e), "is_malicious": False, "abuse_score": 0}

    _cache_set(f"abuse:{ip}", result)
    return result

# ==============================
# VIRUSTOTAL
# ==============================
def check_virustotal(target):
    """Check an IP or domain against VirusTotal."""

    if not target:
        return {"source": "VirusTotal", "target": target, "error": "empty target", "is_malicious": False, "malicious_count": 0}

    cached = _cache_get(f"vt:{target}")
    if cached:
        return cached

    if not VT_API_KEY:
        return {"source": "VirusTotal", "target": target, "error": "API key not configured", "is_malicious": False, "malicious_count": 0}

    # Decide endpoint: IP or domain
    try:
        ipaddress.ip_address(target)
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        kind = "ip"
    except ValueError:
        endpoint = f"https://www.virustotal.com/api/v3/domains/{target}"
        kind = "domain"

    try:
        _rate_limit("vt")
        resp = _safe_get(endpoint, headers={"x-apikey": VT_API_KEY})

        if resp.status_code == 429:
            return {"source": "VirusTotal", "target": target, "error": "Rate limit (429) — free: 4 req/min", "is_malicious": False, "malicious_count": 0}
        if resp.status_code == 404:
            return {"source": "VirusTotal", "target": target, "error": "Not found in VirusTotal", "is_malicious": False, "malicious_count": 0}
        if resp.status_code != 200:
            return {"source": "VirusTotal", "target": target, "error": f"HTTP {resp.status_code}", "is_malicious": False, "malicious_count": 0}

        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal   = stats.get("malicious", 0)
        sus   = stats.get("suspicious", 0)

        result = {
            "source":           "VirusTotal",
            "target":           target,
            "kind":             kind,
            "malicious_count":  mal,
            "suspicious_count": sus,
            "harmless_count":   stats.get("harmless", 0),
            "undetected_count": stats.get("undetected", 0),
            "reputation":       attrs.get("reputation", 0),
            "is_malicious":     mal > 0 or sus > 2
        }

    except Exception as e:
        result = {"source": "VirusTotal", "target": target, "error": str(e), "is_malicious": False, "malicious_count": 0}

    _cache_set(f"vt:{target}", result)
    return result