"""
run_analyzer.py — CLI launcher for Threat Intel Analyzer
  1. Opens file picker (or prompts for path in headless mode)
  2. Loads JSON (any format — Titan correlated_groups or flat events)
  3. Extracts & deduplicates checkable targets
  4. Samples up to MAX_SAMPLE to protect API quota
  5. Runs analysis, prints pretty results, saves output JSON
"""

import json
import random
import ipaddress
import os
from analyzer import analyze

# ==============================
# FILE PICKER
# ==============================
try:
    from tkinter import Tk, filedialog
    root = Tk()
    root.withdraw()
    print("📂 Select your JSON file...")
    file_path = filedialog.askopenfilename(
        title="Select JSON File",
        filetypes=[("JSON files", "*.json")]
    )
    if not file_path:
        print("❌ No file selected.")
        exit()
except Exception:
    file_path = input("Enter path to JSON file: ").strip()

print(f"\n✅ Selected: {file_path}")

# ==============================
# LOAD JSON
# ==============================
try:
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    print(f"❌ Cannot read file: {e}")
    exit()

# ==============================
# IP HELPER
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
# UNIVERSAL EVENT EXTRACTOR
# Handles: correlated_groups, flat events, any nested structure
# ==============================
def extract_checkable_targets(data):
    targets = []
    seen    = set()

    def _add(ev, corr_id=None, corr_type=None):
        ip = None
        for key in ("dst_ip", "ip", "src_ip"):
            candidate = ev.get(key)
            if candidate and _is_public_ipv4(candidate):
                ip = candidate
                break

        domain  = ev.get("domain") or ev.get("hostname") or ev.get("url")
        process = ev.get("process_name") or ev.get("process") or "unknown"

        if not ip and not domain:
            return

        key = (ip, domain)
        if key in seen:
            return
        seen.add(key)

        targets.append({
            "ip":          ip,
            "domain":      domain,
            "process":     process,
            "corr_id":     corr_id,
            "corr_type":   corr_type,
            "record_type": ev.get("record_type"),
            "protocol":    ev.get("protocol"),
            "dst_port":    ev.get("dst_port"),
            "direction":   ev.get("direction"),
            "first_ts":    ev.get("first_ts")
        })

    # Titan correlated_groups
    if isinstance(data, dict) and "correlated_groups" in data:
        for group in data["correlated_groups"]:
            cid   = group.get("corr_id")
            ctype = group.get("corr_type")
            for ev in group.get("events", []):
                _add(ev, corr_id=cid, corr_type=ctype)
        return targets

    # Flat events list
    if isinstance(data, dict) and "events" in data:
        for ev in data["events"]:
            _add(ev)
        return targets

    # Recursive fallback for any other nested structure
    def _walk(obj):
        if isinstance(obj, list):
            for item in obj:
                _walk(item)
        elif isinstance(obj, dict):
            _add(obj)
            for v in obj.values():
                _walk(v)

    _walk(data)
    return targets

# ==============================
# EXTRACT
# ==============================
targets = extract_checkable_targets(data)

print(f"\n📊 Unique checkable targets (public IP or domain): {len(targets)}")

if not targets:
    print("\n❌ No usable public IPs or domains found.")
    print("   Your data likely contains only private/multicast/IPv6 addresses.")
    exit()

# ==============================
# SHOW SKIP STATS (so you know what was filtered and why)
# ==============================
all_events_count = 0
if isinstance(data, dict) and "correlated_groups" in data:
    for group in data["correlated_groups"]:
        all_events_count += len(group.get("events", []))
elif isinstance(data, dict) and "events" in data:
    all_events_count = len(data["events"])

skipped = all_events_count - len(targets)
print(f"\n📋 Total raw events in file             : {all_events_count}")
print(f"✅ Usable targets (public IP or domain)  : {len(targets)}")
print(f"⏭  Skipped (private/multicast/IPv6/process-only): {skipped}")

# ==============================
# SAMPLE — protect API quota
# AbuseIPDB free : 1000/day
# VirusTotal free:    4/min → 5 targets ≈ 75s wait max
# ==============================
MAX_SAMPLE = 5
sample = random.sample(targets, min(MAX_SAMPLE, len(targets)))

print(f"\n🎯 Sampling {len(sample)} of {len(targets)} targets (API quota protection)")
print("\n🔍 Selected targets:")
print(json.dumps(sample, indent=2))

# ==============================
# ANALYZE
# ==============================
print("\n⚡ Running Threat Analysis...\n")

try:
    results = analyze({"events": sample})
except Exception as e:
    print(f"❌ Analysis error: {e}")
    exit()

# ==============================
# PRINT RESULTS
# ==============================
ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "CLEAN": "✅"}

for i, res in enumerate(results):
    sev  = res.get("severity", "CLEAN")
    icon = ICONS.get(sev, "❓")

    print(f"\n{'='*52}")
    print(f"  RESULT {i+1}  {icon} {sev}   Score: {res['risk_score']}/100")
    print(f"{'='*52}")

    ev = res["event"]
    print(f"  IP        : {ev.get('ip')        or '—'}")
    print(f"  Domain    : {ev.get('domain')     or '—'}")
    print(f"  Process   : {ev.get('process')    or '—'}")
    print(f"  Protocol  : {ev.get('protocol')   or '—'}   Port: {ev.get('dst_port') or '—'}")
    print(f"  Direction : {ev.get('direction')  or '—'}")
    print(f"  Corr ID   : {ev.get('corr_id')    or '—'}")

    print("\n  🛡 Threat Intel:")
    for t in res["threats"]:
        src = t.get("source", "?")
        if t.get("skipped"):
            print(f"    [{src}] ⏭  Skipped — {t.get('reason','')}")
        elif t.get("error"):
            print(f"    [{src}] ⚠️  Error — {t.get('error','')}")
        elif t.get("is_malicious"):
            if src == "AbuseIPDB":
                print(f"    [{src}] 🚨 Score={t.get('abuse_score')} | Reports={t.get('total_reports')} | ISP={t.get('isp','?')} | {t.get('country','?')}")
            else:
                print(f"    [{src}] 🚨 Malicious={t.get('malicious_count')} | Suspicious={t.get('suspicious_count',0)} | Reputation={t.get('reputation',0)}")
        else:
            if src == "AbuseIPDB":
                print(f"    [{src}] ✅ Clean (score={t.get('abuse_score',0)}, reports={t.get('total_reports',0)})")
            else:
                print(f"    [{src}] ✅ Clean (malicious={t.get('malicious_count',0)}, suspicious={t.get('suspicious_count',0)})")

# ==============================
# SUMMARY
# ==============================
suspicious = [r for r in results if r["is_suspicious"]]
print(f"\n\n📊 SUMMARY")
print(f"  Analyzed  : {len(results)}")
print(f"  Suspicious: {len(suspicious)}")
print(f"  Clean     : {len(results) - len(suspicious)}")

# ==============================
# SAVE OUTPUT
# ==============================
out_path = os.path.join(os.path.dirname(os.path.abspath(file_path)), "threat_analysis_output.json")
try:
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({
            "summary": {
                "analyzed":   len(results),
                "suspicious": len(suspicious),
                "clean":      len(results) - len(suspicious)
            },
            "results": results
        }, f, indent=2)
    print(f"\n💾 Results saved → {out_path}")
except Exception as e:
    print(f"\n⚠️  Could not save output: {e}")

print("\n✅ DONE\n")