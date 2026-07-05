#!/usr/bin/env python3
"""Haltdos WAF Tester UI backend with live Socket.IO streaming."""

import json
import os
import queue
import threading
import sys
from datetime import datetime
from pathlib import Path

import requests
from flask import Flask, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit

sys.path.insert(0, str(Path(__file__).parent))
from engine import WAFEngine

BASE_DIR = Path(__file__).resolve().parent
PROFILES_FILE = BASE_DIR / "profiles.json"
REPORTS_DIR = BASE_DIR / "reports"

app = Flask(__name__)
app.config["SECRET_KEY"] = "haltdos-waf-ui"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


def ensure_storage():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if not PROFILES_FILE.exists():
        PROFILES_FILE.write_text("[]", encoding="utf-8")


def load_profiles():
    ensure_storage()
    try:
        return json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_profiles(profiles):
    ensure_storage()
    PROFILES_FILE.write_text(json.dumps(profiles, indent=2), encoding="utf-8")


def load_report_index():
    ensure_storage()
    reports = []
    for path in sorted(REPORTS_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            reports.append({
                "filename": path.name,
                "profile_id": data.get("profile_id"),
                "generated_at": data.get("generated_at"),
                "health_score": data.get("health_score"),
                "verdict": data.get("verdict"),
                "det_rate": data.get("det_rate"),
            })
        except Exception:
            continue
    return reports


def save_report(profile_id, report_data):
    ensure_storage()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fn = REPORTS_DIR / f"profile_{profile_id}_{ts}.json"
    report_data = dict(report_data)
    report_data["profile_id"] = profile_id
    report_data["filename"] = fn.name
    report_data["completed_at"] = datetime.now().isoformat()
    report_data["det_rate"] = report_data.get("det_rate") or (
        round((sum(1 for a in report_data.get("attack_results", []) if a.get("blocked")) / max(1, len(report_data.get("attack_results", []))) * 100), 1)
        if report_data.get("attack_results") else 0
    )
    fn.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
    return report_data


@app.get("/")
def index():
    return send_from_directory(str(BASE_DIR), "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "version": "5.0", "ts": datetime.now().isoformat()}


@app.get("/api/profiles")
def get_profiles():
    profiles = load_profiles()
    for profile in profiles:
        profile["has_token"] = bool(profile.get("api_token"))
        profile.pop("api_token", None)
    return jsonify(profiles)


@app.post("/api/profiles")
def create_profile():
    payload = request.get_json(silent=True) or {}
    if not payload.get("name") or not payload.get("mgmt_ip") or not payload.get("stack_id") or not payload.get("target_listener"):
        return jsonify({"error": "Fill all required fields"}), 400
    if not payload.get("api_token"):
        return jsonify({"error": "API token is required"}), 400
    profiles = load_profiles()
    profile = {
        "id": len(profiles) + 1,
        "name": payload["name"],
        "setup_type": payload.get("setup_type", "cluster"),
        "mgmt_ip": payload["mgmt_ip"],
        "mgmt_port": int(payload.get("mgmt_port", 443)),
        "miti_ip": payload.get("miti_ip", payload["mgmt_ip"]),
        "api_token": payload["api_token"],
        "stack_id": payload["stack_id"],
        "target_listener": payload["target_listener"],
        "use_https_traffic": bool(payload.get("use_https_traffic", False)),
        "last_run": None,
        "last_score": None,
    }
    profiles.append(profile)
    save_profiles(profiles)
    return jsonify(profile)


@app.put("/api/profiles/<int:profile_id>")
def update_profile(profile_id):
    payload = request.get_json(silent=True) or {}
    profiles = load_profiles()
    profile = next((p for p in profiles if p["id"] == profile_id), None)
    if not profile:
        return jsonify({"error": "Profile not found"}), 404
    for key in ["name", "setup_type", "mgmt_ip", "mgmt_port", "miti_ip", "stack_id", "target_listener", "use_https_traffic"]:
        if key in payload:
            profile[key] = payload[key]
    if payload.get("api_token"):
        profile["api_token"] = payload["api_token"]
    save_profiles(profiles)
    return jsonify(profile)


@app.delete("/api/profiles/<int:profile_id>")
def delete_profile(profile_id):
    profiles = load_profiles()
    profiles = [p for p in profiles if p["id"] != profile_id]
    save_profiles(profiles)
    return jsonify({"ok": True})


@app.post("/api/test-connection")
def test_connection():
    payload = request.get_json(silent=True) or {}
    mgmt_ip = payload.get("mgmt_ip")
    mgmt_port = int(payload.get("mgmt_port", 443))
    miti_ip = payload.get("miti_ip") or mgmt_ip

    management_ok = False
    traffic_ok = False
    try:
        with requests.Session() as session:
            session.verify = False
            session.get(f"https://{mgmt_ip}:{mgmt_port}", timeout=6)
            management_ok = True
    except Exception:
        management_ok = False

    try:
        requests.get(f"http://{miti_ip}", timeout=4, verify=False)
        traffic_ok = True
    except Exception:
        try:
            requests.get(f"https://{miti_ip}", timeout=4, verify=False)
            traffic_ok = True
        except Exception:
            traffic_ok = False

    return jsonify({"management": {"ok": management_ok}, "traffic": {"ok": traffic_ok}})


@app.get("/api/reports/<int:profile_id>")
def list_reports(profile_id):
    reports = []
    for item in load_report_index():
        if item.get("profile_id") == profile_id:
            reports.append(item)
    return jsonify(reports)


@app.get("/api/reports/<int:profile_id>/<path:filename>")
def get_report(profile_id, filename):
    path = REPORTS_DIR / filename
    if not path.exists():
        return jsonify({"error": "Report not found"}), 404
    return jsonify(json.loads(path.read_text(encoding="utf-8")))


@socketio.on("connect")
def on_connect():
    emit("connected", {"status": "ok"})


def build_phase_flags(phases):
    phase_flags = {k: False for k in ["phase1_preflight", "phase2_config", "phase3_rules", "phase4_attacks", "phase5_features", "phase6_incidents", "phase7_report"]}
    selected = set(phases or [])
    if 1 in selected:
        phase_flags["phase1_preflight"] = True
    if 2 in selected:
        phase_flags["phase2_config"] = True
    if 3 in selected:
        phase_flags["phase3_rules"] = True
    if 4 in selected:
        phase_flags["phase4_attacks"] = True
    if 5 in selected:
        phase_flags["phase5_features"] = True
    if 6 in selected:
        phase_flags["phase6_incidents"] = True
    phase_flags["phase7_report"] = True
    return phase_flags


@socketio.on("start_test")
def on_start_test(data):
    sid = request.sid
    profile_id = data.get("profile_id")
    phases = data.get("phases") or [1, 2, 3, 4, 5, 6, 7]
    attack_delay = float(data.get("attack_delay", 0.5))

    profiles = load_profiles()
    profile = next((p for p in profiles if p["id"] == profile_id), None)
    if not profile:
        emit("test_error", {"message": "Profile not found"})
        return

    config = {
        "setup_type": profile.get("setup_type", "cluster"),
        "mgmt_ip": profile.get("mgmt_ip"),
        "mgmt_port": profile.get("mgmt_port", 443),
        "miti_ip": profile.get("miti_ip") or profile.get("mgmt_ip"),
        "api_token": profile.get("api_token", ""),
        "stack_id": profile.get("stack_id"),
        "target_listener": profile.get("target_listener"),
        "use_https_traffic": bool(profile.get("use_https_traffic", False)),
        "profile_name": profile.get("name"),
        "report_name": f"{profile.get('name','profile').replace(' ','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
    }
    print('DEBUG on_start_test received', data)
    sys.stdout.flush()
    phase_flags = build_phase_flags(phases)
    print('DEBUG phase_flags:', phases, phase_flags)
    sys.stdout.flush()
    q = queue.Queue()

    def log_debug(message):
        with open(BASE_DIR / 'server_debug.log', 'a', encoding='utf-8') as dbg:
            dbg.write(f"{datetime.now().isoformat()} {message}\n")
            dbg.flush()

    def run_engine_and_stream():
        try:
            engine = WAFEngine(config, q, phases=phase_flags, attack_delay=attack_delay)
            engine_thread = threading.Thread(target=engine.run, daemon=True)
            engine_thread.start()
            print('DEBUG engine_thread started alive=', engine_thread.is_alive())
            sys.stdout.flush()
            log_debug(f"START engine_thread alive={engine_thread.is_alive()}")

            while engine_thread.is_alive() or not q.empty():
                try:
                    event = q.get(timeout=0.2)
                except queue.Empty:
                    continue
                print('DEBUG queue event:', event)
                sys.stdout.flush()
                log_debug(f"QUEUE_EVENT {event}")
                if event.get("type") == "done":
                    break
                if event.get("type") == "done":
                    break
                event_type = event.get("type")
                if event_type == "log":
                    socketio.emit("log_line", {"ts": event.get("ts"), "level": event.get("level"), "msg": event.get("message"), "phase": event.get("phase")}, to=sid)
                elif event_type == "phase_start":
                    socketio.emit("phase_start", {"phase": event.get("phase"), "name": event.get("name")}, to=sid)
                elif event_type == "phase_done":
                    socketio.emit("phase_done", {"phase": event.get("phase"), "name": event.get("name"), "status": event.get("status"), "passed": event.get("passed"), "failed": event.get("failed"), "skipped": event.get("skipped"), "findings": event.get("findings")}, to=sid)
                elif event_type == "attack_result":
                    socketio.emit("attack_result", {"id": event.get("id"), "category": event.get("category"), "desc": event.get("desc"), "status": event.get("status"), "result": event.get("result"), "progress": event.get("progress"), "index": event.get("index"), "total": event.get("total")}, to=sid)
                elif event_type == "listener_info":
                    socketio.emit("listener_info", {k: event.get(k) for k in ("mode","paranoia","sig_on","ssl_enabled","cipher_suite","backend","hsts","av_mode","bot_bad_rep","has_geo","geo_countries")}, to=sid)
                elif event_type == "incidents_data":
                    socketio.emit("incidents_data", {"incidents": event.get("incidents"), "ioc_count": event.get("ioc_count", 0)}, to=sid)
                elif event_type == "report_ready":
                    socketio.emit("report_ready", {"path": event.get("path"), "health_score": event.get("health_score"), "verdict": event.get("verdict")}, to=sid)
                elif event_type == "error":
                    socketio.emit("test_error", {"message": event.get("message")}, to=sid)
                elif event_type == "test_started":
                    socketio.emit("test_started", {"profile": event.get("profile")}, to=sid)
                elif event_type == "test_complete":
                    socketio.emit("test_complete", event.get("report"), to=sid)

            engine_thread.join(timeout=2)
            if engine_thread.is_alive():
                socketio.emit("test_error", {"message": "The engine did not finish in time"}, to=sid)
        except Exception as exc:
            socketio.emit("test_error", {"message": str(exc)}, to=sid)

    threading.Thread(target=run_engine_and_stream, daemon=True).start()


@socketio.on("stop_test")
def on_stop_test():
    emit("test_stopped", {"status": "stopped"})


if __name__ == "__main__":
    ensure_storage()
    print("\n  🛡️  Haltdos WAF Tester UI")
    print("  ─────────────────────────────")
    print("  Open: http://localhost:8080\n")
    socketio.run(app, host="0.0.0.0", port=8080, debug=False)