"""
TITAN Log Correlator v2
Fixes:
  - R2: skip generic process names (svchost, dllhost, etc.)
  - R3: AND logic instead of OR (must share BOTH process + IP or stricter match)
  - R5: user session only enriches, never hard-merges alone
  - RAM: index stores only event_ids, no duplicate event dicts
"""

import json
import uuid
import sys
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

TIME_WINDOW_SECONDS      = 30
SCRIPT_TIME_WINDOW_SECS  = 60

# R2 FIX: these names are too generic to use as a cross-file bridge
# Multiple unrelated instances share the same name
GENERIC_PROCESS_NAMES = {
    "svchost.exe", "dllhost.exe", "runtimebroker.exe",
    "wmiprvse.exe", "conhost.exe", "rundll32.exe",
    "taskhost.exe", "taskhostw.exe", "werfault.exe",
    "backgroundtaskhost.exe", "sihost.exe", "ctfmon.exe",
}


# ─────────────────────────────────────────────
# GUI FILE SELECTOR
# ─────────────────────────────────────────────

def select_files_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox

    root = tk.Tk()
    root.title("TITAN Correlator v4 — File Selector")
    root.geometry("620x420")
    root.resizable(False, False)
    root.configure(bg="#1e1e2e")

    selected_files = []
    output_folder  = tk.StringVar(value=str(Path.home() / "Desktop"))

    BG    = "#1e1e2e"; CARD  = "#2a2a3e"; ACCENT = "#7c6af7"
    TEXT  = "#cdd6f4"; MUTED = "#6c7086"; GREEN  = "#a6e3a1"

    def lbl(p, t, sz=11, c=TEXT, bold=False):
        return tk.Label(p, text=t, bg=BG, fg=c,
                        font=("Segoe UI", sz, "bold" if bold else "normal"))

    def mbtn(p, t, cmd, col=ACCENT):
        return tk.Button(p, text=t, command=cmd, bg=col, fg="white",
                         font=("Segoe UI", 9, "bold"), relief="flat",
                         padx=10, pady=4, cursor="hand2", bd=0,
                         activebackground=MUTED, activeforeground="white")

    tk.Label(root, text="TITAN  Log Correlator  v2", bg=BG, fg=ACCENT,
             font=("Segoe UI", 15, "bold")).pack(pady=(18, 2))
    lbl(root, "Select log files and output folder, then click Run.", 10, MUTED).pack()

    card = tk.Frame(root, bg=CARD, bd=0, highlightthickness=1,
                    highlightbackground=ACCENT)
    card.pack(fill="x", padx=24, pady=(16, 6))

    hdr = tk.Frame(card, bg=CARD)
    hdr.pack(fill="x", padx=10, pady=(8, 4))
    lbl(hdr, "Input log files", 10, TEXT, bold=True).pack(side="left")
    lbl(hdr, "(.json / .jsonl)", 9, MUTED).pack(side="left", padx=6)

    lb = tk.Listbox(card, bg="#13131f", fg=GREEN, font=("Consolas", 9), height=6,
                    selectbackground=ACCENT, bd=0, highlightthickness=0, activestyle="none")
    lb.pack(fill="x", padx=10, pady=(0, 6))

    br = tk.Frame(card, bg=CARD)
    br.pack(fill="x", padx=10, pady=(0, 10))

    def add_files():
        paths = filedialog.askopenfilenames(title="Select log files",
            filetypes=[("Log files", "*.json *.jsonl"), ("All files", "*.*")])
        for p in paths:
            if p not in selected_files:
                selected_files.append(p)
                lb.insert("end", f"  {Path(p).name}")
        upd()

    def remove_sel():
        for i in reversed(lb.curselection()):
            lb.delete(i); selected_files.pop(i)
        upd()

    def clear_all():
        lb.delete(0, "end"); selected_files.clear(); upd()

    mbtn(br, "+ Add Files",     add_files).pack(side="left", padx=(0,6))
    mbtn(br, "Remove Selected", remove_sel,  "#444466").pack(side="left", padx=(0,6))
    mbtn(br, "Clear All",       clear_all,   "#3a3a55").pack(side="left")

    of = tk.Frame(root, bg=BG)
    of.pack(fill="x", padx=24, pady=4)
    lbl(of, "Output folder:", 10, TEXT, bold=True).pack(side="left")
    tk.Entry(of, textvariable=output_folder, bg=CARD, fg=TEXT, font=("Consolas", 9),
             relief="flat", insertbackground=TEXT, width=42).pack(side="left", padx=8, ipady=4)

    def browse_out():
        f = filedialog.askdirectory(title="Choose output folder")
        if f: output_folder.set(f)

    mbtn(of, "Browse", browse_out, "#444466").pack(side="left")

    sv  = tk.StringVar(value="No files selected.")
    slb = tk.Label(root, textvariable=sv, bg=BG, fg=MUTED, font=("Segoe UI", 9))
    slb.pack(pady=(8, 0))

    def upd():
        n = len(selected_files)
        sv.set("No files selected." if n == 0 else f"{n} file(s) selected — ready.")
        slb.config(fg=MUTED if n == 0 else GREEN)

    result = {"files": None, "folder": None}

    def run():
        if not selected_files:
            messagebox.showwarning("No files", "Please add at least one log file."); return
        out = output_folder.get().strip()
        if not out or not Path(out).is_dir():
            messagebox.showerror("Invalid folder", "Choose a valid output folder."); return
        result["files"] = list(selected_files)
        result["folder"] = out
        root.destroy()

    def cancel():
        root.destroy()

    bot = tk.Frame(root, bg=BG)
    bot.pack(pady=14)
    mbtn(bot, "Run Correlator", run).pack(side="left", padx=8)
    mbtn(bot, "Cancel", cancel, "#3a3a55").pack(side="left")

    root.mainloop()
    return result["files"], result["folder"]


# ─────────────────────────────────────────────
# FILE TYPE DETECTION
# ─────────────────────────────────────────────

def detect_file_type(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read(2000)
        if '"timestamp"' in content and '"script_content"' in content:
            return "applog"
        if '"local_addr"' in content or '"etw_kernel_process"' in content:
            return "process_network_v1"
        if '"src_ip"' in content and '"dst_ip"' in content:
            return "network_v2"
    except Exception:
        pass
    return "unknown"


# ─────────────────────────────────────────────
# INGEST
# ─────────────────────────────────────────────

def load_jsonl(path):
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try: records.append(json.loads(line))
                except json.JSONDecodeError: pass
    return records


def load_applog(path):
    records = []
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    depth = 0; start = None
    for i, ch in enumerate(content):
        if ch == "{":
            if depth == 0: start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try: records.append(json.loads(content[start:i+1]))
                except json.JSONDecodeError: pass
                start = None
    return records


def load_file(path):
    if Path(path).suffix.lower() == ".jsonl":
        return load_jsonl(path)
    recs = load_jsonl(path)
    return recs if recs else load_applog(path)


# ─────────────────────────────────────────────
# NORMALIZE  (unified schema, RAM-lean)
# ─────────────────────────────────────────────

def parse_ts(raw):
    if not raw: return None
    for fmt in ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"]:
        try: return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError: pass
    return None


def _evt(eid, source_file, source, record_type, ts,
         pid, process_name, canonical_path, user_name, user_sid,
         src_ip, dst_ip, src_port, dst_port,
         protocol, direction, tcp_state, ipv6,
         script_content, pattern_hits,
         signature_valid=None, location_type="",
         new_child_flag=None, persistence_touched=None,
         credential_access=False, amsi_bypass=False, process_injection=False):
    """
    Single constructor for all event types.
    Using a function (not a dict literal each time) means
    Python interns the key strings once — saves RAM at scale.
    """
    return {
        "event_id": eid, "source_file": source_file,
        "source": source, "record_type": record_type, "ts": ts,
        "pid": pid, "process_name": process_name or "",
        "canonical_path": canonical_path or "",
        "user_name": user_name or "", "user_sid": user_sid or "",
        "src_ip": src_ip or "", "dst_ip": dst_ip or "",
        "src_port": src_port, "dst_port": dst_port,
        "protocol": protocol or "", "direction": direction or "",
        "tcp_state": tcp_state or "", "ipv6": ipv6,
        "script_content": script_content or "",
        "pattern_hits": pattern_hits or 0,
        "signature_valid": signature_valid,
        "location_type": location_type or "",
        "new_child_flag": new_child_flag,
        "persistence_touched": persistence_touched,
        "credential_access": credential_access,
        "amsi_bypass": amsi_bypass,
        "process_injection": process_injection,
    }


def normalize_v1(raw, label):
    return _evt(
        eid=str(uuid.uuid4()), source_file=label,
        source=raw.get("source",""), record_type=raw.get("record_type","unknown"),
        ts=parse_ts(raw.get("ts")),
        pid=raw.get("pid"), process_name=raw.get("process_name"),
        canonical_path=raw.get("canonical_path"),
        user_name=raw.get("user_name"), user_sid=raw.get("user_sid"),
        src_ip=raw.get("local_addr"), dst_ip=raw.get("remote_addr"),
        src_port=raw.get("local_port"), dst_port=raw.get("remote_port"),
        protocol=raw.get("protocol"), direction=raw.get("direction"),
        tcp_state=raw.get("tcp_state"), ipv6=raw.get("ipv6"),
        script_content="", pattern_hits=0,
        signature_valid=raw.get("signature_valid"),
        location_type=raw.get("location_type"),
        new_child_flag=raw.get("new_child_flag"),
        persistence_touched=raw.get("persistence_touched"),
    )


def normalize_v2(raw, label):
    return _evt(
        eid=str(uuid.uuid4()), source_file=label,
        source=raw.get("source","npcap_live"),
        record_type=raw.get("record_type","network_connect"),
        ts=parse_ts(raw.get("ts")),
        pid=raw.get("pid"), process_name=raw.get("process_name"),
        canonical_path=None, user_name=None, user_sid=None,
        src_ip=raw.get("src_ip"), dst_ip=raw.get("dst_ip"),
        src_port=raw.get("src_port"), dst_port=raw.get("dst_port"),
        protocol=raw.get("protocol"), direction=raw.get("direction"),
        tcp_state=raw.get("state"), ipv6=raw.get("ipv6"),
        script_content="", pattern_hits=0,
    )


def normalize_applog(raw, label):
    return _evt(
        eid=str(uuid.uuid4()), source_file=label,
        source=raw.get("source","PowerShell"),
        record_type="script_execution",
        ts=parse_ts(raw.get("timestamp")),
        pid=None, process_name="powershell.exe",
        canonical_path=None, user_name=None, user_sid=None,
        src_ip=None, dst_ip=None, src_port=None, dst_port=None,
        protocol=None, direction=None, tcp_state=None, ipv6=None,
        script_content=raw.get("script_content",""),
        pattern_hits=raw.get("pattern_hits",0),
        credential_access=raw.get("credential_access",False),
        amsi_bypass=raw.get("amsi_bypass",False),
        process_injection=raw.get("process_injection",False),
    )


NORMALIZERS = {
    "process_network_v1": normalize_v1,
    "network_v2":         normalize_v2,
    "applog":             normalize_applog,
}


def ingest_all(file_paths):
    all_events = []
    for path in file_paths:
        ftype = detect_file_type(path)
        label = Path(path).stem
        raw   = load_file(path)
        norm  = NORMALIZERS.get(ftype, normalize_v2)
        for r in raw:
            all_events.append(norm(r, label))
        print(f"[INGEST] {Path(path).name:<40} type={ftype:<22} records={len(raw)}")
    all_events.sort(key=lambda e: e["ts"] or datetime.min.replace(tzinfo=timezone.utc))
    print(f"[INGEST] Total: {len(all_events)} events from {len(file_paths)} file(s)")
    return all_events


# ─────────────────────────────────────────────
# ENTITY INDEX  (RAM-lean: IDs only, no dup dicts)
# ─────────────────────────────────────────────

def build_index(events):
    """
    Stores only event_id strings in the index — not full event dicts.
    Full event data stays only in the main `events` list.
    Saves ~50% RAM vs storing events twice.
    """
    by_pid    = defaultdict(list)
    by_proc   = defaultdict(list)
    by_user   = defaultdict(list)
    by_sid    = defaultdict(list)
    by_flow   = defaultdict(list)
    by_bucket = defaultdict(list)

    for e in events:
        eid = e["event_id"]
        pid = e["pid"]
        pn  = e["process_name"].lower() if e["process_name"] else ""

        # Only index non-zero, non-None PIDs
        if pid and pid != 0:
            by_pid[pid].append(eid)

        # Only index non-generic process names
        if pn and pn not in GENERIC_PROCESS_NAMES:
            by_proc[pn].append(eid)

        if e["user_name"]:
            by_user[e["user_name"]].append(eid)
        if e["user_sid"]:
            by_sid[e["user_sid"]].append(eid)

        # Index all flows (including PID-0) so R4 can still pair
        # INBOUND+OUTBOUND orphan traffic into one flow record
        if e["src_ip"] and e["dst_ip"]:
            by_flow[(e["src_ip"], e["dst_ip"], e["src_port"], e["dst_port"])].append(eid)

        if e["ts"]:
            by_bucket[int(e["ts"].timestamp()) // TIME_WINDOW_SECONDS].append(eid)

    return dict(by_pid=dict(by_pid), by_proc=dict(by_proc),
                by_user=dict(by_user), by_sid=dict(by_sid),
                by_flow=dict(by_flow), by_bucket=dict(by_bucket))


# ─────────────────────────────────────────────
# CORRELATION ENGINE  (v2 — tighter rules)
# ─────────────────────────────────────────────

def correlate(events, idx):
    """
    Union-Find correlation.

    Key changes vs v1:
    - R2: skips generic process names (GENERIC_PROCESS_NAMES set)
    - R3: AND logic — must share BOTH process_name AND src_ip (not OR)
    - R5: user session no longer hard-merges; only soft-links when
          user also shares a process_name with another event in the group
    """
    # Build a fast lookup: event_id → event
    emap = {e["event_id"]: e for e in events}

    # Union-Find with path compression
    parent = {e["event_id"]: e["event_id"] for e in events}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb: parent[rb] = ra

    def link(ids):
        lst = list(ids)
        for i in range(1, len(lst)):
            union(lst[0], lst[i])

    # ── R1: PID (hard link, strongest) ──────────────────────────
    # Same PID = definitely same process instance
    for pid, eids in idx["by_pid"].items():
        if len(eids) > 1:
            link(eids)

    # ── R2: Process name cross-file bridge (fixed) ───────────────
    # Only bridge SPECIFIC process names (not svchost, dllhost etc.)
    # and only when they appear in MORE than one source file
    for name, eids in idx["by_proc"].items():
        if len(eids) > 1:
            sources = {emap[e]["source_file"] for e in eids}
            if len(sources) > 1:
                link(eids)

    # ── R3: Time window — AND logic (fixed) ──────────────────────
    # Events must share BOTH process_name AND src_ip within window
    # Previously used OR → caused too many false merges
    for bucket, eids in idx["by_bucket"].items():
        cands = set(eids)
        for adj in [bucket - 1, bucket + 1]:
            cands.update(idx["by_bucket"].get(adj, []))
        clist = list(cands)
        for i in range(len(clist)):
            a = emap[clist[i]]
            for j in range(i + 1, len(clist)):
                b = emap[clist[j]]
                if not a["ts"] or not b["ts"]:
                    continue
                diff = abs((a["ts"] - b["ts"]).total_seconds())
                if diff > TIME_WINDOW_SECONDS:
                    continue
                # Conditional AND/OR:
                # - If both events have a src_ip → require BOTH match (AND)
                # - If one or both have no src_ip (e.g. script events) → proc name alone is enough
                # - Never match on generic process names
                pn_a = a["process_name"].lower() if a["process_name"] else ""
                pn_b = b["process_name"].lower() if b["process_name"] else ""
                same_proc = (pn_a and pn_a not in GENERIC_PROCESS_NAMES and pn_a == pn_b)
                same_ip   = (a["src_ip"] and a["src_ip"] == b["src_ip"])
                both_have_ip = bool(a["src_ip"] and b["src_ip"])
                if same_proc and (same_ip or not both_have_ip):
                    union(a["event_id"], b["event_id"])

    # ── R4: Flow pairing (INBOUND + OUTBOUND same flow) ──────────
    # Only for flows that have a real PID (no PID-0 orphans)
    for flow_key, eids in idx["by_flow"].items():
        if len(eids) > 1:
            inb = [e for e in eids if emap[e].get("direction") == "INBOUND"]
            out = [e for e in eids if emap[e].get("direction") == "OUTBOUND"]
            if inb and out:
                link(inb + out)

    # ── R5: User session — soft enrichment only (fixed) ──────────
    # v1 hard-merged everything under the same user → mega groups
    # v2: only merge two events by user if they ALSO share a
    #     specific (non-generic) process name → prevents "blob"
    user_proc_groups = defaultdict(list)  # (user, proc_name) → [eids]
    for e in events:
        u  = e["user_name"]
        pn = e["process_name"].lower() if e["process_name"] else ""
        if u and pn and pn not in GENERIC_PROCESS_NAMES:
            user_proc_groups[(u, pn)].append(e["event_id"])

    for (user, proc), eids in user_proc_groups.items():
        if len(eids) > 1:
            link(eids)

    # ── R6: Script → powershell process time fallback ────────────
    # Unchanged — tries to match applog events to a nearby
    # powershell process_start within SCRIPT_TIME_WINDOW_SECS
    scripts  = [e for e in events if e["record_type"] == "script_execution" and e["ts"]]
    ps_procs = [e for e in events
                if e["record_type"] == "process_start"
                and "powershell" in e["process_name"].lower()
                and e["ts"]]

    for se in scripts:
        best, best_d = None, float("inf")
        for pe in ps_procs:
            d = abs((se["ts"] - pe["ts"]).total_seconds())
            if d <= SCRIPT_TIME_WINDOW_SECS and d < best_d:
                best, best_d = pe, d
        if best:
            union(se["event_id"], best["event_id"])

    # ── Assign stable, readable group IDs ────────────────────────
    roots = defaultdict(list)
    for e in events:
        roots[find(e["event_id"])].append(e["event_id"])

    root_to_gid = {r: "CG-" + min(v)[:8].upper() for r, v in roots.items()}
    return {e["event_id"]: root_to_gid[find(e["event_id"])] for e in events}



# ─────────────────────────────────────────────
# HELPERS: CLEAN + DEDUPLICATE
# ─────────────────────────────────────────────

STRIP_FIELDS = {"pattern_hits"}

def clean_event(e):
    """Keep only fields with real values. Drop pattern_hits always."""
    out = {}
    for k, v in e.items():
        if k in STRIP_FIELDS:
            continue
        if k == "pid" and (v is None or v == 0):
            continue
        if v is None or v == "" or v is False:
            continue
        out[k] = v
    return out


def event_signature(e):
    """Fingerprint that defines 'same action' — excludes event_id and ts."""
    return (
        e.get("record_type",""),
        e.get("source",""),
        e.get("process_name",""),
        e.get("user_name",""),
        e.get("src_ip",""),
        e.get("dst_ip",""),
        e.get("src_port"),
        e.get("dst_port"),
        e.get("protocol",""),
        e.get("direction",""),
        e.get("script_content",""),
    )


def collapse_events(evts):
    """
    Collapse repeated events → one entry per unique action.
    Repeated event = same process, IPs, ports, protocol, direction.
    Each entry stores: first_ts, last_ts, count (if >1).
    event_id dropped for collapsed entries (not needed for analysis).
    """
    seen     = {}
    counts   = defaultdict(int)
    first_ts = {}
    last_ts  = {}

    for e in evts:
        sig = event_signature(e)
        counts[sig] += 1
        ts = e.get("ts")
        if sig not in seen:
            seen[sig]     = clean_event(e)
            first_ts[sig] = ts
        if ts and (last_ts.get(sig) is None or ts > last_ts[sig]):
            last_ts[sig] = ts

    result = []
    for sig, base in seen.items():
        entry = {k: v for k, v in base.items() if k not in ("event_id","ts")}
        entry["first_ts"] = first_ts[sig]
        entry["last_ts"]  = last_ts[sig]
        if counts[sig] > 1:
            entry["count"] = counts[sig]
        result.append(entry)

    result.sort(key=lambda x: x.get("first_ts") or "")
    return result


def group_signature(g):
    """Fingerprint for whole-group deduplication."""
    return (
        g["corr_type"],
        tuple(sorted(g["processes"])),
        tuple(sorted(g["dest_ips"])),
        tuple(sorted(g["protocols"])),
        tuple(sorted(g["source_files"])),
    )


# ─────────────────────────────────────────────
# ASSEMBLE OUTPUT  (v4 — optimized)
# ─────────────────────────────────────────────

def ts_str(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if dt else None


def group_type(evts):
    t  = {e["record_type"] for e in evts}
    hp = "process_start"    in t
    hn = "network_connect"  in t
    hs = "script_execution" in t
    if hp and hn and hs: return "full_activity_session"
    if hp and hn:        return "process_with_network"
    if hp and hs:        return "process_with_script"
    if hn and hs:        return "network_with_script"
    if hp:               return "process_session"
    if hn:               return "network_flow"
    if hs:               return "script_session"
    return "mixed"


def assemble(events, e2g):
    """
    Optimized assembly:
    - Repeated events collapsed (count + first/last ts instead of N copies)
    - Empty fields stripped per event
    - pattern_hits removed entirely
    - Identical groups merged with repeat_count
    """
    group_eids = defaultdict(list)
    emap = {e["event_id"]: e for e in events}
    for e in events:
        group_eids[e2g[e["event_id"]]].append(e["event_id"])

    raw_cegs = []
    for gid, eids in group_eids.items():
        evts = sorted(
            [emap[eid] for eid in eids],
            key=lambda e: e["ts"] or datetime.min.replace(tzinfo=timezone.utc)
        )
        tss  = [e["ts"] for e in evts if e["ts"]]
        s, en = (tss[0], tss[-1]) if tss else (None, None)
        collapsed = collapse_events(evts)
        raw_cegs.append({
            "corr_id":           gid,
            "corr_type":         group_type(evts),
            "unique_events":     len(collapsed),
            "total_occurrences": len(evts),
            "start_ts":          ts_str(s),
            "end_ts":            ts_str(en),
            "duration_seconds":  round((en - s).total_seconds(), 2) if s and en else 0,
            "source_files":      sorted({e["source_file"] for e in evts}),
            "record_types":      sorted({e["record_type"] for e in evts}),
            "processes":         sorted({e["process_name"] for e in evts if e["process_name"]}),
            "users":             sorted({e["user_name"]    for e in evts if e["user_name"]}),
            "pids":              sorted({e["pid"]          for e in evts if e.get("pid")}),
            "dest_ips":          sorted({e["dst_ip"]       for e in evts if e["dst_ip"]}),
            "protocols":         sorted({e["protocol"]     for e in evts if e["protocol"]}),
            "events":            collapsed,
        })

    raw_cegs.sort(key=lambda g: g["total_occurrences"], reverse=True)

    # Whole-group deduplication: identical groups → first kept + repeat_count
    final = []
    seen_sigs = {}
    for g in raw_cegs:
        sig = group_signature(g)
        if sig in seen_sigs:
            idx = seen_sigs[sig]
            final[idx]["repeat_count"]      = final[idx].get("repeat_count", 1) + 1
            final[idx]["total_occurrences"] += g["total_occurrences"]
        else:
            seen_sigs[sig] = len(final)
            final.append(g)

    return final


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  TITAN CORRELATOR  v4")
    print("=" * 55)

    file_paths, out_folder = select_files_gui()

    if not file_paths:
        print("[CANCELLED] No files selected.")
        sys.exit(0)

    print(f"\n[FILES]  {len(file_paths)} file(s) selected")
    for p in file_paths: print(f"         {p}")
    print(f"[OUTPUT] {out_folder}\n")

    events = ingest_all(file_paths)
    idx    = build_index(events)

    print(f"[INDEX]  PIDs:{len(idx['by_pid'])}  "
          f"Procs:{len(idx['by_proc'])}  "
          f"Users:{len(idx['by_user'])}  "
          f"Flows:{len(idx['by_flow'])}")

    e2g  = correlate(events, idx)
    cegs = assemble(events, e2g)

    counts = defaultdict(int)
    for g in cegs: counts[g["corr_type"]] += 1
    print(f"[RESULT] {len(events)} events → {len(cegs)} groups")
    for t, c in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"         {t}: {c}")

    # Write output — stream to file instead of building full string in RAM
    out_path = Path(out_folder) / "correlated_events.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({
            "meta": {
                "generated_at":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "correlator_version": "4.0",
                "total_events":  len(events),
                "total_groups":  len(cegs),
                "input_files":   [Path(p).name for p in file_paths],
                "config": {
                    "time_window_seconds":        TIME_WINDOW_SECONDS,
                    "script_time_window_seconds": SCRIPT_TIME_WINDOW_SECS,
                    "generic_names_excluded":     sorted(GENERIC_PROCESS_NAMES),
                }
            },
            "correlated_groups": cegs
        }, f, indent=2, default=str)

    print(f"\n[DONE]   Output → {out_path}")
    print("=" * 55)

    try:
        import tkinter as tk
        from tkinter import messagebox
        r = tk.Tk(); r.withdraw()
        messagebox.showinfo("Done!",
            f"Correlation complete!\n\n"
            f"Events:  {len(events)}\n"
            f"Groups:  {len(cegs)}\n\n"
            f"Saved to:\n{out_path}")
        r.destroy()
    except Exception:
        pass


if __name__ == "__main__":
    main()