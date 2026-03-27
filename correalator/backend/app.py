"""
app.py — Flask backend for Threat Intel Analyzer

Endpoints:
  GET  /health           — liveness check
  POST /analyze          — JSON body  (application/json)
  POST /analyze/upload   — .json file upload (multipart/form-data, field: "file")
"""

import json
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS

from analyzer     import analyze
from graph_builder import build_graph

# ==============================
# APP SETUP
# ==============================
app = Flask(__name__)
CORS(app)   # allow any frontend origin (React dev server, file://, etc.)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)

# ==============================
# API QUOTA GUARD
# Cap unique targets per request so we don't blow daily limits.
#   AbuseIPDB free : 1 000 req/day
#   VirusTotal free:   240 req/hr  (4/min)
# With caching, only NEW IPs cost an API call.
# ==============================
MAX_UNIQUE_TARGETS = 50


# ==============================
# HEALTH CHECK
# ==============================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


# ==============================
# ANALYZE — JSON BODY
# ==============================
@app.route("/analyze", methods=["POST"])
def analyze_route():
    try:
        data = request.get_json(force=True, silent=True)
        if data is None:
            return jsonify({"error": "Invalid or missing JSON body"}), 400
        return _run_analysis(data)
    except Exception as e:
        log.exception("Error in /analyze")
        return jsonify({"error": str(e)}), 500


# ==============================
# ANALYZE — FILE UPLOAD
# ==============================
@app.route("/analyze/upload", methods=["POST"])
def analyze_upload():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded — use field name 'file'"}), 400

        f = request.files["file"]
        if not f.filename.lower().endswith(".json"):
            return jsonify({"error": "Only .json files are supported"}), 400

        try:
            data = json.loads(f.read())
        except json.JSONDecodeError as e:
            return jsonify({"error": f"Invalid JSON: {e}"}), 400

        return _run_analysis(data)

    except Exception as e:
        log.exception("Error in /analyze/upload")
        return jsonify({"error": str(e)}), 500


# ==============================
# SHARED ANALYSIS LOGIC
# ==============================
def _run_analysis(data):
    log.info("Starting analysis...")

    results = analyze(data)

    if not results:
        return jsonify({
            "summary": {
                "total_analyzed": 0,
                "suspicious": 0,
                "clean": 0,
                "note": "No public IPs or domains found in the uploaded data."
            },
            "results": [],
            "graph": {"nodes": [], "edges": []}
        })

    # Enforce quota cap
    if len(results) > MAX_UNIQUE_TARGETS:
        log.warning("Capping to %d results to protect API quota", MAX_UNIQUE_TARGETS)
        results = results[:MAX_UNIQUE_TARGETS]

    graph = build_graph(results)

    # Build summary
    suspicious = [r for r in results if r["is_suspicious"]]
    sev_counts = {}
    for r in results:
        s = r.get("severity", "CLEAN")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    top_threats = sorted(suspicious, key=lambda x: x["risk_score"], reverse=True)[:5]

    summary = {
        "total_analyzed":     len(results),
        "suspicious":         len(suspicious),
        "clean":              len(results) - len(suspicious),
        "severity_breakdown": sev_counts,
        "top_threats":        top_threats
    }

    log.info("Done — total: %d | suspicious: %d | clean: %d",
             summary["total_analyzed"], summary["suspicious"], summary["clean"])

    return jsonify({
        "summary": summary,
        "results": results,
        "graph":   graph
    })


# ==============================
# ENTRY POINT
# ==============================
if __name__ == "__main__":
    print("\n🚀 Threat Analyzer API → http://localhost:5000")
    print("   POST /analyze          — send JSON body")
    print("   POST /analyze/upload   — upload a .json file")
    print("   GET  /health           — health check\n")
    app.run(debug=True, host="0.0.0.0", port=5000)