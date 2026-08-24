import json
import os
import time
import queue
import threading

from flask import Flask, render_template, request, send_file, Response, session

from header_scan import scan_headers
from port_scan import scan_ports
from report_generator import generate_report
from recommendations import get_recommendations
from vulnerability_scan import scan_vulnerabilities
from owasp_checks import check_basic_owasp
from tor_request import tor_status
from ssl_scan import check_ssl          # ← NEW
from database import (
    init_db,
    save_scan,
    get_last_scans,
    get_dashboard_stats,
    get_recent_scans
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)

init_db()

scan_queues = {}
scan_store  = {}


def sse_message(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


def run_scan(scan_id: str, url: str):
    q = scan_queues[scan_id]

    def push(stage, message, status="running", payload=None):
        q.put(sse_message({
            "stage":   stage,
            "message": message,
            "status":  status,
            "payload": payload or {}
        }))

    try:
        # ── Stage 0: Tor check ──
        push("tor", "Checking Tor connectivity...", "running")
        time.sleep(0.3)
        is_onion = ".onion" in url
        if is_onion:
            status = tor_status()
            if not status["connected"]:
                push("tor", f"⚠ Tor not detected: {status['error']}", "warning")
            else:
                push("tor", f"✓ Tor connected via port {status['port']} — Exit IP: {status['ip']}", "done")
        else:
            push("tor", "✓ Surface web target — direct connection", "done")
        time.sleep(0.2)

        # ── Stage 1: Header scan ──
        push("headers", "Scanning HTTP security headers...", "running")
        time.sleep(0.3)
        results = scan_headers(url)
        if "Error" in results:
            push("headers", f"✗ Header scan failed: {results['Error']}", "error")
        else:
            secure  = results.get("_secure_count", 0)
            total   = results.get("_total_headers", 8)
            missing = results.get("_missing_count", 0)
            push("headers",
                 f"✓ Headers scanned — {secure}/{total} secure, {missing} missing",
                 "done",
                 {"results": {k: v for k, v in results.items()}})
        time.sleep(0.2)

        # ── Stage 2: SSL/TLS analysis ── (NEW)
        hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
        push("ssl", "Analysing SSL/TLS certificate...", "running")
        time.sleep(0.3)
        ssl_data = check_ssl(hostname)

        if not ssl_data.get("supported"):
            reason = ssl_data.get("reason") or ssl_data.get("error", "Not available")
            push("ssl", f"⟳ SSL skipped — {reason}", "skipped", {"ssl": ssl_data})
        elif ssl_data.get("error"):
            push("ssl", f"⚠ SSL issue — {ssl_data['error']}", "warning", {"ssl": ssl_data})
        else:
            grade = ssl_data.get("grade", "?")
            days  = ssl_data.get("days_remaining", 0)
            tls   = ssl_data.get("tls_version", "?")
            push("ssl",
                 f"✓ SSL analysed — Grade: {grade} | {tls} | {days} days remaining",
                 "done",
                 {"ssl": ssl_data})
        time.sleep(0.2)

        # ── Stage 3: Port scan ──
        if is_onion:
            push("ports", "⟳ Port scan skipped for .onion (Nmap cannot reach Tor)", "skipped")
            ports = []
        else:
            push("ports", "Running Nmap port scan...", "running")
            ports = scan_ports(hostname)
            if ports and isinstance(ports[0].get("port"), int):
                push("ports",
                     f"✓ Port scan complete — {len(ports)} open port(s) found",
                     "done", {"ports": ports})
            else:
                push("ports", "✓ Port scan complete — no open ports found", "done")
        time.sleep(0.2)

        # ── Stage 4: Vulnerability scan ──
        push("vulns", "Scanning for vulnerabilities...", "running")
        time.sleep(0.3)
        vulnerabilities = scan_vulnerabilities(url)
        issues = [v for v in vulnerabilities if not v.startswith("✓")]
        push("vulns",
             f"✓ Vulnerability scan done — {len(issues)} issue(s) found",
             "done", {"vulnerabilities": vulnerabilities})
        time.sleep(0.2)

        # ── Stage 5: OWASP checks ──
        push("owasp", "Running OWASP Top 10 checks...", "running")
        time.sleep(0.3)
        owasp_findings = check_basic_owasp(url)
        owasp_issues = [o for o in owasp_findings if not o.startswith("✓")]
        push("owasp",
             f"✓ OWASP checks done — {len(owasp_issues)} finding(s)",
             "done", {"owasp_findings": owasp_findings})
        time.sleep(0.2)

        # ── Stage 6: Recommendations ──
        push("recs", "Generating security recommendations...", "running")
        time.sleep(0.3)
        recommendations = get_recommendations(results, ports)

        # Add SSL-based recommendations
        if ssl_data.get("supported") and ssl_data.get("issues"):
            for issue in ssl_data["issues"]:
                recommendations.append(f"[SSL] {issue}")

        push("recs",
             f"✓ {len(recommendations)} recommendation(s) generated",
             "done", {"recommendations": recommendations})
        time.sleep(0.2)

        # ── Finalise ──
        secure_count  = results.get("_secure_count", 0)
        missing_count = results.get("_missing_count", 0)

        save_scan(url, is_onion, results.get("Risk Level", "Unknown"))

        scan_store[scan_id] = {
            "url":             url,
            "results":         {k: v for k, v in results.items() if not k.startswith("_")},
            "ports":           ports,
            "vulnerabilities": vulnerabilities,
            "owasp_findings":  owasp_findings,
            "recommendations": recommendations,
            "secure_count":    secure_count,
            "missing_count":   missing_count,
            "is_onion":        is_onion,
            "ssl":             ssl_data,         # ← stored for PDF too
        }

        push("complete", "✓ Scan complete!", "complete", {"scan_id": scan_id})

    except Exception as e:
        q.put(sse_message({
            "stage": "error", "message": f"✗ Unexpected error: {str(e)}",
            "status": "error", "payload": {}
        }))
    finally:
        q.put(None)


@app.route("/", methods=["GET"])
def index():
    history = get_last_scans()
    return render_template("index.html", history=history)


@app.route("/start-scan", methods=["POST"])
def start_scan():
    url = request.form.get("url", "").strip()
    if not url:
        return {"error": "No URL provided"}, 400
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    scan_id = f"scan_{int(time.time()*1000)}"
    scan_queues[scan_id] = queue.Queue()
    threading.Thread(target=run_scan, args=(scan_id, url), daemon=True).start()
    return {"scan_id": scan_id}


@app.route("/scan-stream/<scan_id>")
def scan_stream(scan_id):
    if scan_id not in scan_queues:
        return "Scan not found", 404

    def generate():
        q = scan_queues[scan_id]
        while True:
            msg = q.get()
            if msg is None:
                break
            yield msg
        scan_queues.pop(scan_id, None)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/results/<scan_id>")
def results_page(scan_id):
    data = scan_store.get(scan_id)
    if not data:
        return "Scan results not found or expired.", 404
    session["latest_scan_id"] = scan_id
    return render_template("index.html",
        results=data["results"], ports=data["ports"],
        vulnerabilities=data["vulnerabilities"], owasp_findings=data["owasp_findings"],
        recommendations=data["recommendations"], secure_count=data["secure_count"],
        missing_count=data["missing_count"], is_onion=data["is_onion"],
        scanned_url=data["url"], ssl_data=data.get("ssl", {}),
        history=get_last_scans())


@app.route("/download-report")
def download_report():
    scan_id = session.get("latest_scan_id")
    data    = scan_store.get(scan_id) if scan_id else None
    if not data:
        return "No scan available. Please run a scan first.", 400
    filename = generate_report(data["url"], data["results"], data["ports"])
    return send_file(filename, as_attachment=True)


@app.route("/dashboard")
def dashboard():
    stats        = get_dashboard_stats()
    recent_scans = get_recent_scans()
    return render_template("dashboard.html", stats=stats, recent_scans=recent_scans)


if __name__ == "__main__":
    app.run(debug=True)
