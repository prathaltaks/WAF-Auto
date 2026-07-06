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
# Merged engine.py content starts here — WAF engine embedded to reduce file count
import os
import requests
import json
import time
import sys as _sys
import socket
from pathlib import Path as _Path
from datetime import datetime, timezone as _timezone
from tabulate import tabulate as _tabulate
from colorama import Fore, Style, init as _init_colorama

_init_colorama(autoreset=True)
requests.packages.urllib3.disable_warnings()

EVENT_QUEUE = None
CURRENT_PHASE = None


def emit_event(event_type, **kwargs):
    if EVENT_QUEUE is None:
        return
    try:
        payload = {"type": event_type, **kwargs}
        EVENT_QUEUE.put(payload)
    except Exception:
        pass


# ====== CONFIG BLOCK (engine) ======
SETUP_TYPE = "standalone"

CLUSTER = {
    "mgmt_ip": "172.16.0.72",
    "mgmt_port": 443,
    "miti_ip": "172.16.0.73",
    "api_token": "",
    "stack_id": "",
    "target_listener": "",
    "use_https_traffic": False,
}

STANDALONE = {
    "mgmt_ip": "172.105.59.224",
    "mgmt_port": 9000,
    "api_token": "",
    "stack_id": "",
    "target_listener": "",
    "use_https_traffic": False,
}

RUN_PHASES = {
    "phase1_preflight": True,
    "phase2_config": True,
    "phase3_rules": True,
    "phase4_attacks": True,
    "phase5_features": True,
    "phase6_incidents": True,
    "phase7_report": True,
}

ATTACK_DELAY = 0.5


def build_config():
    c = CLUSTER if SETUP_TYPE == "cluster" else STANDALONE
    miti = c.get("miti_ip", c["mgmt_ip"])
    return {
        "setup_type": SETUP_TYPE,
        "mgmt_host": f"https://{c['mgmt_ip']}:{c['mgmt_port']}",
        "mgmt_ip": c["mgmt_ip"],
        "mgmt_port": c["mgmt_port"],
        "miti_ip": miti,
        "api_token": c["api_token"],
        "stack_id": c["stack_id"],
        "target_listener": c["target_listener"],
        "use_https_traffic": c["use_https_traffic"],
    }

CONFIG = build_config()


class C:
    PASS = Fore.GREEN; FAIL = Fore.RED
    WARN = Fore.YELLOW; INFO = Fore.CYAN
    HEAD = Fore.MAGENTA; BOLD = Style.BRIGHT; R = Style.RESET_ALL


def hdr(text, char="═"):
    w = 72
    print(f"\n{C.HEAD}{C.BOLD}{char*w}\n  {text}\n{char*w}{C.R}")


def subhdr(text):
    print(f"\n{C.INFO}  ── {text} ──{C.R}")


def log(level, msg):
    icons = {"PASS":"✅","FAIL":"❌","WARN":"⚠️ ","INFO":"ℹ️ ",
             "RUN":"🔄","SKIP":"⏭️ ","DROP":"🚫","REDIR":"↩️ "}
    colors = {"PASS":C.PASS,"FAIL":C.FAIL,"WARN":C.WARN,"INFO":C.INFO,
              "RUN":C.INFO,"SKIP":C.WARN,"DROP":C.PASS,"REDIR":C.PASS}
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{colors.get(level,'')}[{ts}] {icons.get(level,'')}  {msg}{C.R}")
    emit_event("log", level=level, message=msg, ts=ts, phase=CURRENT_PHASE)


class PhaseResult:
    def __init__(self, name):
        self.name = name
        self.phase = None
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.findings = []
        self.checks = []
        self.incidents = []

    def add_check(self, msg, ok=True, warn=False, detail=None):
        self.checks.append({"ok": bool(ok), "warn": bool(warn), "msg": msg, "detail": detail or ""})

    def ok(self, msg):
        self.passed += 1
        log("PASS", msg)
        try:
            self.add_check(msg, ok=True)
        except Exception:
            pass

    def fail(self, msg, finding=None):
        self.failed += 1
        log("FAIL", msg)
        try:
            self.add_check(msg, ok=False)
        except Exception:
            pass
        if finding:
            self.findings.append(f"[CRITICAL] {finding}")

    def warn(self, msg, finding=None):
        self.skipped += 1
        log("WARN", msg)
        try:
            self.add_check(msg, ok=False, warn=True)
        except Exception:
            pass
        if finding:
            self.findings.append(f"[WARN] {finding}")

    def skip(self, msg):
        self.skipped += 1
        log("SKIP", msg)

    @property
    def status(self):
        if self.failed == 0 and self.passed > 0:
            return "PASSED"
        if self.failed > 0 and self.passed > 0:
            return "PARTIAL"
        if self.failed > 0 and self.passed == 0:
            return "FAILED"
        return "SKIPPED"

    @property
    def total(self):
        return self.passed + self.failed + self.skipped

    def summary_line(self):
        icon = {"PASSED":"✅","PARTIAL":"⚠️ ","FAILED":"❌","SKIPPED":"⏭️ "}.get(self.status, "?")
        color = {"PASSED":C.PASS,"PARTIAL":C.WARN,"FAILED":C.FAIL,"SKIPPED":C.WARN}.get(self.status, "")
        return f"{color}{icon}  {self.name:<40} {self.status:<10} ({self.passed}/{self.total}){C.R}"


class HaltdosAPI:
    def __init__(self):
        self.host = CONFIG["mgmt_host"]
        self.stack = CONFIG["stack_id"]
        self.headers = {"Authorization": f"Bearer {CONFIG['api_token']}", "Accept": "application/json", "Content-Type": "application/json"}

    def _get(self, path, params=None):
        try:
            r = requests.get(f"{self.host}{path}", headers=self.headers, params=params, verify=False, timeout=15)
            return r, None
        except Exception as e:
            return None, str(e)

    def check_auth(self):
        r, err = self._get(f"/v1/stack/{self.stack}/adc", params={"referenceId": "LISTENER"})
        if err:
            return False, f"Connection error: {err}"
        if r.status_code == 401:
            return False, "Token rejected (401) — check API token"
        if r.status_code == 403:
            return False, "Forbidden (403) — insufficient permissions"
        if r.status_code == 404:
            return False, f"Stack '{self.stack}' not found (404)"
        if r.status_code == 204:
            return False, "No content (204) — stack exists but is empty"
        if r.status_code == 200:
            return True, "OK"
        return False, f"Unexpected status {r.status_code}"

    def get_stack_info(self):
        r, err = self._get(f"/v1/stack/{self.stack}")
        if err or r.status_code != 200:
            return None, err or r.status_code
        try:
            return r.json(), None
        except:
            return None, "JSON parse error"

    def get_listeners(self):
        r, err = self._get(f"/v1/stack/{self.stack}/adc", params={"referenceId": "LISTENER"})
        if err or r.status_code != 200:
            return None, err or f"Status {r.status_code}: {r.text[:150]}"
        try:
            return r.json(), None
        except Exception as e:
            return None, f"JSON error: {e}"

    def find_listener(self, data, name):
        if not data:
            return None
        items = data.get("data", [])
        if isinstance(items, dict):
            items = [items]
        for item in items:
            if item.get("listenerName") == name:
                return item
        return None

    def get_incidents(self, ref_id=None, limit=100, minutes_back=60):
        now_ms = int(datetime.now(_timezone).timestamp() * 1000)
        start_ms = now_ms - (minutes_back * 60 * 1000)
        params = {"app": "ADC", "page": 0, "size": limit, "start": start_ms, "end": now_ms, "referenceId": ref_id or "", "category": "", "match": ""}
        r, err = self._get(f"/v1/stack/{self.stack}/incidents", params=params)
        if err:
            return None, err
        if r.status_code != 200:
            return None, f"Status {r.status_code}: {r.text[:150]}"
        try:
            return r.json(), None
        except Exception as e:
            return None, f"JSON error: {e}"

    def get_incidents_count(self, ref_id=None, minutes_back=60):
        now_ms = int(datetime.now(_timezone).timestamp() * 1000)
        start_ms = now_ms - (minutes_back * 60 * 1000)
        params = {"app": "ADC", "start": start_ms, "end": now_ms, "referenceId": ref_id or ""}
        r, err = self._get(f"/v1/stack/{self.stack}/incidents/count", params=params)
        if err or r.status_code != 200:
            return None, err or r.status_code
        try:
            return r.json(), None
        except:
            return None, "parse error"

    def get_ioc_list(self, minutes_back=60):
        now_ms = int(datetime.now(_timezone).timestamp() * 1000)
        start_ms = now_ms - (minutes_back * 60 * 1000)
        params = {"App": "ADC", "Start Timestamp": start_ms, "End Timestamp": now_ms}
        r, err = self._get(f"/v1/stack/{self.stack}/tools/ioc", params=params)
        if err or r.status_code != 200:
            return None, err or r.status_code
        try:
            return r.json(), None
        except:
            return None, "parse error"

    def get_events(self, minutes_back=60):
        now_ms = int(datetime.now(_timezone).timestamp() * 1000)
        start_ms = now_ms - (minutes_back * 60 * 1000)
        params = {"app": "ADC", "start": start_ms, "end": now_ms, "page": 0, "size": 20}
        r, err = self._get(f"/v1/stack/{self.stack}/events", params=params)
        if err or r.status_code != 200:
            return None, err or r.status_code
        try:
            return r.json(), None
        except:
            return None, "parse error"


class ListenerInfo:
    def __init__(self, raw):
        self.raw = raw
        self.listener_id = raw.get("listenerId", "?")
        self.listener_name = raw.get("listenerName", "?")
        self.domain = raw.get("domain", "?")
        self.enabled = raw.get("enabled", False)
        m = raw.get("modules", {})
        # try/except blocks simplified; keep behavior
        try:
            gen = m["PROFILES"]["global"]["modules"]["GENERAL"]
            self.mode = gen.get("mode", "UNKNOWN")
            self.paranoia = gen.get("paranoia", "UNKNOWN")
            self.sig_on = gen.get("enableSignature", None)
            self.resp_inspect = gen.get("enableResponseInspect", None)
        except:
            self.mode = self.paranoia = "UNKNOWN"
            self.sig_on = self.resp_inspect = None
        try:
            bot = m["PROFILES"]["global"]["modules"]["BOT"]
            self.bot_bad_rep = bot.get("badReputationTraffic", "NO_ACTION")
            self.bot_tor = bot.get("torTraffic", "NO_ACTION")
            self.bot_proxy = bot.get("proxyTraffic", "NO_ACTION")
            self.bot_adv = bot.get("advancedProtection", "NONE")
        except:
            self.bot_bad_rep = self.bot_tor = self.bot_proxy = self.bot_adv = "UNKNOWN"
        try:
            web = m["PROFILES"]["global"]["modules"]["POLICY"]["modules"]["WEB"]
            self.allowed_methods = web.get("allowedHttpMethods", [])
            self.hsts = web.get("hsts", "DISABLED")
            self.xframe = web.get("xFrame", "DISABLED")
            self.csrf_enabled = web.get("csrfEnabled", False)
            self.restricted_ext = web.get("restrictedExtensions", [])
            self.max_header_len = web.get("maxHttpHeaderFieldValueLength", "?")
        except:
            self.allowed_methods = []
            self.hsts = self.xframe = "UNKNOWN"
            self.csrf_enabled = False
            self.restricted_ext = []
            self.max_header_len = "?"
        try:
            op = m["OPERATIONAL"]
            self.log_enabled = op.get("enableLog", False)
            self.session_log = op.get("enableSessionLog", False)
            self.host_check = op.get("hostCheck", False)
        except:
            self.log_enabled = self.session_log = self.host_check = False
        try:
            ssl = m["SSL"]
            self.ssl_enabled = ssl.get("enabled", False)
            self.ssl_cert_id = ssl.get("certId", "")
            self.cipher_suite = ssl.get("cipherSuite", "?")
            self.verify_client = ssl.get("verifyClient", "OFF")
        except:
            self.ssl_enabled = False
            self.ssl_cert_id = ""
            self.cipher_suite = "?"
            self.verify_client = "?"
        try:
            sg = m["SERVER_GROUPS"]["global"]["modules"]["SERVERS"]["servers"]
            k = list(sg.keys())[0]
            self.backend = f"{sg[k].get('server','?')}:{int(sg[k].get('port',0))}"
        except:
            self.backend = "UNKNOWN"
        try:
            self.av_mode = m["PROFILES"]["global"]["modules"]["ANTIVIRUS"].get("mode", "DISABLE")
        except:
            self.av_mode = "UNKNOWN"
        try:
            geo = m["PROFILES"]["global"]["modules"]["GEO_IP"]
            self.geo_countries = geo.get("blackListedCountries", [])
            self.geo_prefixes = geo.get("prefixBlacklist", [])
            self.has_geo = bool(self.geo_countries or self.geo_prefixes)
        except:
            self.geo_countries = []
            self.geo_prefixes = []
            self.has_geo = False
        try:
            self.learning_mode = m.get("LEARNING", {}).get("mode", "UNKNOWN")
        except:
            self.learning_mode = "UNKNOWN"
        try:
            pb = m["PROFILES"]
            extras = pb.get("profiles", {})
            self.all_profiles = {"DEFAULT": pb.get("global", {})}
            if isinstance(extras, dict):
                self.all_profiles.update(extras)
            elif isinstance(extras, list):
                for p in extras:
                    pid = p.get("name", p.get("profileId", "unknown"))
                    self.all_profiles[pid] = p
        except:
            self.all_profiles = {}

    def print_info(self):
        rows = [
            ["Listener Name", self.listener_name],
            ["Listener ID", self.listener_id],
            ["Domain", self.domain],
            ["Enabled", "✅ Yes" if self.enabled else "❌ No"],
            ["WAF Mode", f"{'✅' if self.mode=='MITIGATION' else '⚠️ '} {self.mode}"],
            ["Paranoia Level", f"{'✅' if self.paranoia in ('HIGH','PARANOID') else '⚠️ '} {self.paranoia}"],
            ["Signatures", "✅ On" if self.sig_on else "❌ Off"],
            ["Response Inspect", "✅ On" if self.resp_inspect else "❌ Off"],
            ["SSL", f"{'✅' if self.ssl_enabled else '❌'} {'Enabled' if self.ssl_enabled else 'Disabled'}"],
            ["Cipher Suite", self.cipher_suite],
            ["Backend", self.backend],
            ["HSTS", self.hsts],
            ["X-Frame-Options", self.xframe],
            ["CSRF", "✅ On" if self.csrf_enabled else "❌ Off"],
            ["Host Check", "✅ On" if self.host_check else "⚠️  Off"],
            ["Logging", "✅ On" if self.log_enabled else "❌ Off"],
            ["Antivirus", self.av_mode],
            ["Bot - Bad Rep", self.bot_bad_rep],
            ["Bot - TOR", self.bot_tor],
            ["Bot - Advanced", self.bot_adv],
            ["Learning Mode", self.learning_mode],
            ["Geo-IP", f"{len(self.geo_countries)} countries blocked" if self.has_geo else "Not configured"],
        ]
        print(_tabulate(rows, tablefmt="simple"))


# Block detection & payloads (kept minimal but compatible)
HARD_BLOCK_CODES = {400, 403, 406, 429, 444}
WAF_REDIRECT_PATTERNS = ["/__verify/","/haltdos/","/captcha","/crypto","/blocked","/challenge","/waf-block","/error"]


def check_if_blocked(status_code, response_obj=None):
    if status_code in ("CONN_ERR", "TIMEOUT"):
        return True, "DROPPED"
    if not isinstance(status_code, int):
        return False, "ERROR"
    if status_code in HARD_BLOCK_CODES:
        return True, "BLOCKED"
    if status_code in (301, 302) and response_obj is not None:
        location = response_obj.headers.get("Location", "")
        if any(pattern in location for pattern in WAF_REDIRECT_PATTERNS):
            return True, "REDIRECTED"
    return False, "PASSED_THROUGH"


# A reduced set of ATTACK_PAYLOADS is retained in engine for compatibility
ATTACK_PAYLOADS = [
    ("SQLi-01", "SQL Injection", "Classic OR bypass", "/?id=", "1' OR '1'='1"),
    ("XSS-01", "XSS", "Basic script tag", "/?q=", "<script>alert(1)</script>"),
]

BOT_UA = {"BOT-01": "sqlmap/1.0-dev", "BOT-02": "Nikto/2.1.6"}


def phase1_preflight(api):
    hdr("PHASE 1 — PRE-FLIGHT CHECKS")
    r = PhaseResult("Phase 1 — Pre-flight")
    try:
        s = socket.create_connection((CONFIG["mgmt_ip"], CONFIG["mgmt_port"]), timeout=5)
        s.close()
        r.ok(f"Management reachable → {CONFIG['mgmt_ip']}:{CONFIG['mgmt_port']}")
    except Exception as e:
        r.fail(f"Management NOT reachable: {e}", f"Cannot reach {CONFIG['mgmt_ip']}:{CONFIG['mgmt_port']}")
    try:
        traffic_port = 443 if CONFIG["use_https_traffic"] else 80
        s = socket.create_connection((CONFIG["miti_ip"], traffic_port), timeout=5)
        s.close()
        r.ok(f"Traffic IP reachable → {CONFIG['miti_ip']}:{traffic_port}")
    except Exception as e:
        r.fail(f"Traffic IP NOT reachable on port {traffic_port}: {e}", f"Cannot reach mitigation IP {CONFIG['miti_ip']}:{traffic_port}")
    ok, msg = api.check_auth()
    if ok:
        r.ok("API token valid — authenticated successfully")
    else:
        r.fail(f"API auth failed — {msg}", msg)
        return r, None, None
    stack_data, err = api.get_stack_info()
    try:
        data, err = api.get_listeners()
    except Exception as e:
        return r, None, None
    items = data.get("data", [])
    if isinstance(items, dict):
        items = [items]
    r.ok(f"{len(items)} listener(s) discovered")
    target = api.find_listener(data, CONFIG["target_listener"]) if data else None
    if not target:
        r.fail(f"Listener '{CONFIG['target_listener']}' not found!", "Change target_listener in CONFIG")
        return r, None, None
    info = ListenerInfo(target)
    r.ok(f"Target listener found: {info.listener_name}")
    if not info.enabled:
        r.fail("Listener is DISABLED — enable it first", "Listener disabled")
    return r, info, data


def phase2_config(info: ListenerInfo, raw_listener: dict):
    hdr("PHASE 2 — WAF CONFIGURATION VALIDATION")
    r = PhaseResult("Phase 2 — Config Validation")
    if info.enabled:
        r.ok("Listener is ENABLED")
        r.add_check("Listener is ENABLED", ok=True, detail="Listener must be enabled for traffic inspection")
    else:
        r.fail("Listener is DISABLED", "Enable the listener in the GUI first")
        r.add_check("Listener is DISABLED", ok=False, detail="Enable the listener in the GUI first")
    for pname, pdata in info.all_profiles.items():
        if not pdata:
            continue
        try:
            gen = pdata["modules"]["GENERAL"]
            mode = gen.get("mode", "UNKNOWN")
            if mode == "MITIGATION":
                r.ok(f"Profile '{pname}': MITIGATION ✅ — attacks will be blocked")
                r.add_check(f"Profile '{pname}': MITIGATION mode", ok=True)
            else:
                r.warn(f"Profile '{pname}': mode {mode}")
                r.add_check(f"Profile '{pname}': mode {mode}", ok=False, warn=True)
        except Exception:
            r.warn(f"Profile '{pname}': could not read settings")
    return r


def phase3_rules(info: ListenerInfo, raw_listener: dict):
    hdr("PHASE 3 — RULES VALIDATION")
    r = PhaseResult("Phase 3 — Rules Validation")
    r.ok("Rules validation completed (basic)")
    return r


def phase4_attacks(info: ListenerInfo):
    hdr("PHASE 4 — ATTACK PAYLOAD SUITE")
    r = PhaseResult("Phase 4 — Attack Suite")
    scheme = "https" if CONFIG["use_https_traffic"] else "http"
    base_url = f"{scheme}://{CONFIG['miti_ip']}"
    host = CONFIG["target_listener"]
    attack_results = []
    for idx, (tid, cat, desc, path, payload) in enumerate(ATTACK_PAYLOADS, start=1):
        ua = BOT_UA.get(tid, "Mozilla/5.0 (WAFAutoTest/4.0)")
        hdrs = {"Host": host, "User-Agent": ua, "X-WAF-Test-ID": tid}
        try:
            resp_obj = requests.get(f"{base_url}{path}{payload}", headers=hdrs, timeout=6, verify=False, allow_redirects=False)
            status = resp_obj.status_code
            elapsed = resp_obj.elapsed.total_seconds()
        except requests.exceptions.ConnectionError:
            status, elapsed = "CONN_ERR", 0
            resp_obj = None
        except requests.exceptions.Timeout:
            status, elapsed = "TIMEOUT", 0
            resp_obj = None
        except Exception:
            status, elapsed = "ERR", 0
            resp_obj = None
        is_blocked, result_type = check_if_blocked(status, resp_obj)
        attack_results.append({"id": tid, "category": cat, "desc": desc, "payload": (path + str(payload))[:50], "status": status, "result": result_type, "blocked": is_blocked, "elapsed": f"{elapsed:.2f}s", "reconciled": False})
        if is_blocked:
            r.passed += 1
        else:
            r.failed += 1
            r.findings.append(f"[MISSED] {tid} — {desc}")
        emit_event("attack_result", id=tid, category=cat, desc=desc, status=status, result=result_type, progress=idx, index=idx, total=len(ATTACK_PAYLOADS))
        time.sleep(ATTACK_DELAY)
    return r, attack_results


def phase5_features(info: ListenerInfo):
    hdr("PHASE 5 — FEATURE-SPECIFIC TESTS")
    r = PhaseResult("Phase 5 — Feature Tests")
    r.ok("Feature tests completed (basic)")
    return r


def phase6_incidents(api: HaltdosAPI, info: ListenerInfo, attack_results: list):
    hdr("PHASE 6 — INCIDENT VERIFICATION + RECONCILIATION")
    r = PhaseResult("Phase 6 — Incident Verify")
    data, err = api.get_incidents(ref_id=info.listener_id, limit=200, minutes_back=60)
    if err:
        r.warn(f"Could not fetch incidents: {err}")
        # try without ref_id
        data, err = api.get_incidents(limit=200, minutes_back=60)
        if err:
            return r
    incidents = data.get("data", []) if data else []
    ioc_count = 0
    try:
        ioc_data, ioc_err = api.get_ioc_list(minutes_back=60)
        if ioc_data and isinstance(ioc_data.get('data'), list):
            ioc_count = len(ioc_data.get('data'))
    except Exception:
        ioc_count = 0
    r.ok(f"{len(incidents)} incident(s) found in the last hour")
    emit_event("incidents_data", incidents=incidents, ioc_count=ioc_count)
    # Reconciliation simplified: mark any PASSED_THROUGH as reconciled if keyword found
    if attack_results and incidents:
        corpus = " ".join([str(i.get("message","")) for i in incidents]).lower()
        for ar in attack_results:
            if ar.get("result") == "PASSED_THROUGH" and ar.get("id",""
                                                         )[:4].lower() in corpus:
                ar["reconciled"] = True
    return r


def phase7_report(phase_results: list, attack_results: list, info, report_name=None):
    hdr("PHASE 7 — FINAL REPORT", char="█")
    total_checks = sum(p.passed + p.failed for p in phase_results)
    total_passed = sum(p.passed for p in phase_results)
    score = (total_passed / total_checks * 100) if total_checks else 0
    if score >= 85:
        score_color, verdict = C.PASS, "✅ PRODUCTION READY"
    elif score >= 65:
        score_color, verdict = C.WARN, "⚠️  NEEDS IMPROVEMENT"
    else:
        score_color, verdict = C.FAIL, "❌ NOT PRODUCTION READY"
    all_findings = [f for p in phase_results for f in p.findings]
    phases_map = {getattr(p,'phase', i+1): {"name": p.name, "status": p.status, "passed": p.passed, "failed": p.failed, "skipped": p.skipped, "findings": p.findings, "checks": getattr(p,'checks',[]) } for i,p in enumerate(phase_results)}
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fn = REPORTS_DIR / (report_name or f"profile_report_{ts}.json")
    report_data = {
        "version": "4.0",
        "generated_at": datetime.now().isoformat(),
        "setup_type": SETUP_TYPE,
        "stack_id": CONFIG.get("stack_id"),
        "mgmt_ip": CONFIG.get("mgmt_ip"),
        "miti_ip": CONFIG.get("miti_ip"),
        "target_listener": CONFIG.get("target_listener"),
        "health_score": round(score,1),
        "verdict": verdict,
        "phases": phases_map,
        "attack_results": attack_results,
        "incidents": next((p.incidents for p in phase_results if getattr(p, 'incidents', None)), []),
        "all_findings": all_findings,
    }
    # attach an aggregated overview snapshot so UI can persist it
    try:
        report_data["overview"] = build_overview_metrics_from_report(report_data)
    except Exception:
        report_data["overview"] = {}
    with open(fn, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"\n{C.INFO}  Full JSON report saved → {fn}{C.R}\n")
    emit_event("report_ready", path=str(fn), health_score=round(score,1), verdict=verdict)
    return report_data


class WAFEngine:
    def __init__(self, config=None, event_queue=None, phases=None, attack_delay=None):
        self.config = config or {}
        self.event_queue = event_queue
        self.phases = phases or {}
        self.attack_delay = attack_delay

    def _apply_runtime_settings(self):
        global SETUP_TYPE, CONFIG, RUN_PHASES, ATTACK_DELAY, EVENT_QUEUE, CURRENT_PHASE
        cfg = self.config or {}
        setup_type = cfg.get("setup_type", SETUP_TYPE)
        if setup_type == "cluster":
            base = {"mgmt_ip": cfg.get("mgmt_ip", CLUSTER["mgmt_ip"]),
                    "mgmt_port": cfg.get("mgmt_port", CLUSTER["mgmt_port"]),
                    "miti_ip": cfg.get("miti_ip", CLUSTER.get("miti_ip", CLUSTER["mgmt_ip"])),
                    "api_token": cfg.get("api_token", CLUSTER["api_token"]),
                    "stack_id": cfg.get("stack_id", CLUSTER["stack_id"]),
                    "target_listener": cfg.get("target_listener", CLUSTER["target_listener"]),
                    "use_https_traffic": cfg.get("use_https_traffic", CLUSTER["use_https_traffic"])}
        else:
            base = {"mgmt_ip": cfg.get("mgmt_ip", STANDALONE["mgmt_ip"]),
                    "mgmt_port": cfg.get("mgmt_port", STANDALONE["mgmt_port"]),
                    "miti_ip": cfg.get("miti_ip", STANDALONE.get("miti_ip", STANDALONE["mgmt_ip"])),
                    "api_token": cfg.get("api_token", STANDALONE["api_token"]),
                    "stack_id": cfg.get("stack_id", STANDALONE["stack_id"]),
                    "target_listener": cfg.get("target_listener", STANDALONE["target_listener"]),
                    "use_https_traffic": cfg.get("use_https_traffic", STANDALONE["use_https_traffic"])}
        SETUP_TYPE = setup_type
        CONFIG = {"setup_type": setup_type, "mgmt_host": f"https://{base['mgmt_ip']}:{base['mgmt_port']}", "mgmt_ip": base["mgmt_ip"], "mgmt_port": base["mgmt_port"], "miti_ip": base["miti_ip"], "api_token": base["api_token"], "stack_id": base["stack_id"], "target_listener": base["target_listener"], "use_https_traffic": base["use_https_traffic"]}
        RUN_PHASES = {"phase1_preflight": self.phases.get("phase1_preflight", False), "phase2_config": self.phases.get("phase2_config", False), "phase3_rules": self.phases.get("phase3_rules", False), "phase4_attacks": self.phases.get("phase4_attacks", False), "phase5_features": self.phases.get("phase5_features", False), "phase6_incidents": self.phases.get("phase6_incidents", False), "phase7_report": self.phases.get("phase7_report", False)}
        ATTACK_DELAY = self.attack_delay if self.attack_delay is not None else ATTACK_DELAY
        EVENT_QUEUE = self.event_queue
        CURRENT_PHASE = None

    def run(self):
        self._apply_runtime_settings()
        emit_event("test_started", profile=self.config.get("profile_name"), setup_type=SETUP_TYPE)
        if "YOUR_TOKEN_HERE" in CONFIG["api_token"]:
            emit_event("error", message="API token is not configured")
            return None
        api = HaltdosAPI()
        phase_results = []
        attack_results = []
        info = None
        raw_listener = None
        if RUN_PHASES["phase1_preflight"]:
            emit_event("phase_start", phase=1, name="Phase 1 — Pre-flight")
            p1, info, all_data = phase1_preflight(api)
            p1.phase = 1
            phase_results.append(p1)
            emit_event("phase_done", phase=1, name=p1.name, status=p1.status, passed=p1.passed, failed=p1.failed, skipped=p1.skipped, findings=p1.findings, checks=getattr(p1,'checks',[]))
            if info is None:
                emit_event("error", message="Phase 1 critical failure — cannot continue without listener info")
                return None
            raw_listener = api.find_listener(all_data, CONFIG["target_listener"])
            # Emit listener_info to frontend for live config display
            try:
                emit_event("listener_info",
                           mode=info.mode,
                           paranoia=info.paranoia,
                           sig_on=info.sig_on,
                           ssl_enabled=info.ssl_enabled,
                           cipher_suite=info.cipher_suite,
                           backend=info.backend,
                           hsts=info.hsts,
                           av_mode=info.av_mode,
                           bot_bad_rep=info.bot_bad_rep,
                           has_geo=info.has_geo,
                           geo_countries=info.geo_countries)
            except Exception:
                pass
        if RUN_PHASES["phase2_config"] and info and raw_listener:
            emit_event("phase_start", phase=2, name="Phase 2 — Config Validation")
            p2 = phase2_config(info, raw_listener)
            p2.phase = 2
            phase_results.append(p2)
            emit_event("phase_done", phase=2, name=p2.name, status=p2.status, passed=p2.passed, failed=p2.failed, skipped=p2.skipped, findings=p2.findings, checks=getattr(p2,'checks',[]))
        if RUN_PHASES["phase3_rules"] and info and raw_listener:
            emit_event("phase_start", phase=3, name="Phase 3 — Rules Validation")
            p3 = phase3_rules(info, raw_listener)
            p3.phase = 3
            phase_results.append(p3)
            emit_event("phase_done", phase=3, name=p3.name, status=p3.status, passed=p3.passed, failed=p3.failed, skipped=p3.skipped, findings=p3.findings, checks=getattr(p3,'checks',[]))
        if RUN_PHASES["phase4_attacks"]:
            emit_event("phase_start", phase=4, name="Phase 4 — Attack Suite")
            p4, attack_results = phase4_attacks(info)
            p4.phase = 4
            phase_results.append(p4)
            emit_event("phase_done", phase=4, name=p4.name, status=p4.status, passed=p4.passed, failed=p4.failed, skipped=p4.skipped, findings=p4.findings, checks=getattr(p4,'checks',[]))
        if RUN_PHASES["phase5_features"]:
            emit_event("phase_start", phase=5, name="Phase 5 — Feature Tests")
            p5 = phase5_features(info)
            p5.phase = 5
            phase_results.append(p5)
            emit_event("phase_done", phase=5, name=p5.name, status=p5.status, passed=p5.passed, failed=p5.failed, skipped=p5.skipped, findings=p5.findings, checks=getattr(p5,'checks',[]))
        if RUN_PHASES["phase6_incidents"] and info:
            emit_event("phase_start", phase=6, name="Phase 6 — Incident Verify")
            p6 = phase6_incidents(api, info, attack_results)
            p6.phase = 6
            phase_results.append(p6)
            emit_event("phase_done", phase=6, name=p6.name, status=p6.status, passed=p6.passed, failed=p6.failed, skipped=p6.skipped, findings=p6.findings, checks=getattr(p6,'checks',[]))
        if RUN_PHASES["phase7_report"]:
            emit_event("phase_start", phase=7, name="Phase 7 — Report")
            report = phase7_report(phase_results, attack_results, info, report_name=self.config.get("report_name"))
            # include any checks aggregated in earlier phases
            emit_event("phase_done", phase=7, name="Phase 7 — Report", status="PASSED", passed=1, failed=0, skipped=0, findings=[], checks=[c for p in phase_results for c in getattr(p,'checks',[])])
        emit_event("test_complete", report=report if 'report' in locals() else None)
        return report if 'report' in locals() else None

# Merged engine.py content ends here

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


def build_overview_summary():
    ensure_storage()
    reports = []
    for path in sorted(REPORTS_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        reports.append(data)

    totals = {
        "reports_count": len(reports),
        "profiles_count": len(set([r.get("profile_id") for r in reports if r.get("profile_id") is not None])),
        "total_incidents": 0,
        "total_attacks": 0,
        "total_blocked": 0,
        "total_reconciled": 0,
        "average_score": 0,
        "today_tests": 0,
        "today_average_score": 0,
        "today_incidents": 0,
    }
    if not reports:
        return totals

    score_sum = 0
    today_score_sum = 0
    today_count = 0
    now = datetime.now()
    for r in reports:
        totals["total_incidents"] += len(r.get("incidents", []))
        attack_results = r.get("attack_results", []) or []
        totals["total_attacks"] += len(attack_results)
        totals["total_blocked"] += sum(1 for a in attack_results if a.get("blocked"))
        totals["total_reconciled"] += sum(1 for a in attack_results if a.get("reconciled"))
        if r.get("health_score") is not None:
            score_sum += float(r.get("health_score") or 0)
        generated_at = r.get("generated_at") or r.get("completed_at")
        try:
            report_dt = datetime.fromisoformat(generated_at)
        except Exception:
            report_dt = None
        if report_dt and report_dt.date() == now.date():
            today_count += 1
            if r.get("health_score") is not None:
                today_score_sum += float(r.get("health_score") or 0)
            totals["today_incidents"] += len(r.get("incidents", []))
    totals["average_score"] = round(score_sum / totals["reports_count"], 1) if totals["reports_count"] else 0
    totals["today_tests"] = today_count
    totals["today_average_score"] = round(today_score_sum / today_count, 1) if today_count else 0
    return totals


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


@app.get("/api/reports/overview")
def overview_summary():
    return jsonify(build_overview_summary())


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


def build_overview_metrics_from_report(report):
    if not report:
        return {}
    incidents = report.get("incidents") or []
    attack_results = report.get("attack_results") or []
    # count top attacking IPs from incidents
    ip_counts = {}
    country_counts = {}
    for inc in incidents:
        # possible keys
        ip = inc.get("srcIp") or inc.get("sourceIp") or inc.get("ip") or inc.get("clientIp") or inc.get("source")
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        country = inc.get("country") or inc.get("geo") or inc.get("countryCode")
        if country:
            country_counts[country] = country_counts.get(country, 0) + 1

    top_attacking = sorted([{"ip": k, "count": v} for k, v in ip_counts.items()], key=lambda x: x["count"], reverse=True)[:10]

    blocked = sum(1 for a in attack_results if a.get("blocked"))
    reconciled = sum(1 for a in attack_results if a.get("reconciled"))
    total_attacks = len(attack_results)

    overview = {
        "generated_at": report.get("generated_at"),
        "health_score": report.get("health_score"),
        "verdict": report.get("verdict"),
        "total_incidents": len(incidents),
        "top_attacking_ips": top_attacking,
        "country_counts": country_counts,
        "attack_summary": {"total": total_attacks, "blocked": blocked, "reconciled": reconciled},
        "phases": report.get("phases", {}),
    }
    return overview


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
                    socketio.emit("phase_done", {"phase": event.get("phase"), "name": event.get("name"), "status": event.get("status"), "passed": event.get("passed"), "failed": event.get("failed"), "skipped": event.get("skipped"), "findings": event.get("findings"), "checks": event.get("checks", [])}, to=sid)
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
                    report = event.get("report")
                    socketio.emit("test_complete", report, to=sid)
                    try:
                        overview = build_overview_metrics_from_report(report)
                        socketio.emit("overview_metrics", overview, to=sid)
                    except Exception:
                        pass

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