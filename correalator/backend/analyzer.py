import ipaddress
import logging
from threat_intel import check_ip_abuseipdb, check_virustotal

# ==============================
# LOGGING
# ==============================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)

# ==============================
# IP VALIDATION
# ==============================
def _is_public_ipv4(ip):
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

# ==============================
# SCORING  (0–100)
# AbuseIPDB confidence is already 0-100, weight it at 60%
# VT malicious vendors: +12 each, suspicious: +4 each
# ==============================
def calculate_score(threats):
    score = 0
    for t in threats:
        if t.get("skipped") or t.get("error"):
            continue
        src = t.get("source", "")
        if src == "AbuseIPDB":
            score += t.get("abuse_score", 0) * 0.6
        elif src == "VirusTotal":
            score += t.get("malicious_count", 0) * 12
            score += t.get("suspicious_count", 0) * 4
    return min(round(score), 100)

# ==============================
# SEVERITY LABEL
# ==============================
def severity(score):
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "CLEAN"

# ==============================
# EXTRACT TARGETS FROM ONE EVENT
# ==============================
def _extract_targets(event):
    ip = None
    for key in ("dst_ip", "ip", "src_ip"):
        candidate = event.get(key)
        if candidate and _is_public_ipv4(candidate):
            ip = candidate
            break

    domain  = event.get("domain") or event.get("hostname") or event.get("url")
    process = event.get("process_name") or event.get("process") or event.get("image")
    return ip, domain, process

# ==============================
# MAIN ANALYZE
# ==============================
def analyze(data):
    """
    Accepts any of:
      - {"correlated_groups": [...]}   your Titan format
      - {"events": [...]}              flat list
      - [...]                          raw list
    Returns list of result dicts.
    """
    results      = []
    seen_ips     = set()
    seen_domains = set()

    # ── Flatten to a list of raw events ───────────────────────────────
    raw_events = []

    if isinstance(data, list):
        raw_events = data

    elif isinstance(data, dict):
        if "correlated_groups" in data:
            for group in data["correlated_groups"]:
                cid   = group.get("corr_id")
                ctype = group.get("corr_type")
                for ev in group.get("events", []):
                    ev.setdefault("corr_id",   cid)
                    ev.setdefault("corr_type", ctype)
                    raw_events.append(ev)
        elif "events" in data:
            raw_events = data["events"]
        else:
            raw_events = [data]

    log.info("Total raw events: %d", len(raw_events))

    # ── Process each event ─────────────────────────────────────────────
    for event in raw_events:
        ip, domain, process = _extract_targets(event)

        if not ip and not domain:
            continue  # nothing checkable

        # Deduplicate
        if ip     and ip     in seen_ips     and not domain: continue
        if domain and domain in seen_domains and not ip:     continue

        if ip:     seen_ips.add(ip)
        if domain: seen_domains.add(domain)

        threats = []

        if ip:
            log.info("Checking IP: %s (process: %s)", ip, process or "?")
            threats.append(check_ip_abuseipdb(ip))
            threats.append(check_virustotal(ip))

        if domain:
            log.info("Checking domain: %s", domain)
            threats.append(check_virustotal(domain))

        score = calculate_score(threats)
        sev   = severity(score)

        results.append({
            "event": {
                "ip":          ip,
                "domain":      domain,
                "process":     process,
                "corr_id":     event.get("corr_id"),
                "corr_type":   event.get("corr_type"),
                "record_type": event.get("record_type"),
                "protocol":    event.get("protocol"),
                "dst_port":    event.get("dst_port"),
                "direction":   event.get("direction"),
                "first_ts":    event.get("first_ts"),
            },
            "threats":      threats,
            "risk_score":   score,
            "severity":     sev,
            "is_suspicious": score > 20
        })

    log.info("Analysis complete: %d results", len(results))
    return results