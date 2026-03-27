"""
graph_builder.py
Builds a Cytoscape-compatible node/edge graph from analyzer results.

Node types  : process (blue) | ip (green→red) | domain (purple→red)
Edge data   : protocol, port, direction, corr_id, risk colour
"""

_SEVERITY_COLOR = {
    "CRITICAL": "#e53935",
    "HIGH":     "#ef6c00",
    "MEDIUM":   "#f9a825",
    "LOW":      "#66bb6a",
    "CLEAN":    "#42a5f5",
}

_NODE_DEFAULT_COLOR = {
    "process": "#90caf9",
    "ip":      "#a5d6a7",
    "domain":  "#ce93d8",
}

def _nid(kind, value):
    return f"{kind}::{value}"


def build_graph(results):
    """
    Returns {"nodes": [...], "edges": [...]} ready for Cytoscape.
    Nodes carry colour, severity, risk_score for frontend styling.
    Edges carry protocol, port, direction for tooltips.
    """
    nodes = {}
    edges = []

    for item in results:
        event    = item.get("event", {})
        score    = item.get("risk_score", 0)
        sev      = item.get("severity", "CLEAN")
        sus      = item.get("is_suspicious", False)

        ip      = event.get("ip")
        domain  = event.get("domain")
        process = event.get("process") or "unknown_process"
        proto   = event.get("protocol", "")
        port    = event.get("dst_port", "")
        dirn    = event.get("direction", "")
        corr_id = event.get("corr_id", "")

        # ── Process node ────────────────────────────────────────────
        proc_id = _nid("process", process)
        if proc_id not in nodes:
            nodes[proc_id] = {"data": {
                "id":         proc_id,
                "label":      process,
                "type":       "process",
                "color":      _NODE_DEFAULT_COLOR["process"],
                "risk_score": 0,
                "severity":   "CLEAN"
            }}
        # Escalate process node if this event is worse
        if score > nodes[proc_id]["data"]["risk_score"]:
            nodes[proc_id]["data"]["risk_score"] = score
            nodes[proc_id]["data"]["severity"]   = sev
            nodes[proc_id]["data"]["color"]      = "#ef5350" if sus else _NODE_DEFAULT_COLOR["process"]

        # ── IP node ─────────────────────────────────────────────────
        if ip:
            ip_id = _nid("ip", ip)
            if ip_id not in nodes:
                nodes[ip_id] = {"data": {
                    "id":           ip_id,
                    "label":        ip,
                    "type":         "ip",
                    "color":        _SEVERITY_COLOR.get(sev, _NODE_DEFAULT_COLOR["ip"]),
                    "risk_score":   score,
                    "severity":     sev,
                    "is_suspicious": sus
                }}
            else:
                if score > nodes[ip_id]["data"]["risk_score"]:
                    nodes[ip_id]["data"].update({
                        "risk_score": score,
                        "severity":   sev,
                        "color":      _SEVERITY_COLOR.get(sev, _NODE_DEFAULT_COLOR["ip"])
                    })

            edge_label = f"{proto} :{port}" if port else (proto or "→")
            edges.append({"data": {
                "id":         f"{proc_id}->{ip_id}",
                "source":     proc_id,
                "target":     ip_id,
                "label":      edge_label,
                "direction":  dirn,
                "corr_id":    corr_id,
                "risk_score": score,
                "color":      _SEVERITY_COLOR.get(sev, "#90caf9")
            }})

        # ── Domain node ─────────────────────────────────────────────
        if domain:
            dom_id = _nid("domain", domain)
            if dom_id not in nodes:
                nodes[dom_id] = {"data": {
                    "id":           dom_id,
                    "label":        domain,
                    "type":         "domain",
                    "color":        _SEVERITY_COLOR.get(sev, _NODE_DEFAULT_COLOR["domain"]),
                    "risk_score":   score,
                    "severity":     sev,
                    "is_suspicious": sus
                }}
            edges.append({"data": {
                "id":         f"{proc_id}->{dom_id}",
                "source":     proc_id,
                "target":     dom_id,
                "label":      "DNS/HTTP",
                "corr_id":    corr_id,
                "risk_score": score,
                "color":      _SEVERITY_COLOR.get(sev, "#90caf9")
            }})

    return {
        "nodes": list(nodes.values()),
        "edges": edges
    }