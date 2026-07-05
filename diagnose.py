#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   HALTDOS WAF TESTER — SETUP DIAGNOSTIC TOOL               ║
║   Run this FIRST when a new setup isn't working             ║
║   It tests every layer independently and tells you exactly  ║
║   what is different between two setups                      ║
╚══════════════════════════════════════════════════════════════╝

USAGE:
  python3 diagnose.py

Fill in both setups below. The script will compare them side by side.
"""

import requests
import socket
import json
import sys
from datetime import datetime, timezone

requests.packages.urllib3.disable_warnings()

# ════════════════════════════════════════════════════════════════
#  CONFIGURE BOTH SETUPS HERE
# ════════════════════════════════════════════════════════════════

SETUP_A = {
    "name":            "Setup A (72/73) — WORKING",
    "mgmt_ip":         "172.16.0.72",
    "mgmt_port":       443,
    "miti_ip":         "172.16.0.73",
    "api_token":       "YOUR_TOKEN_FOR_72",
    "stack_id":        "PAHDIWCFPM",
    "target_listener": "roti.com",
}

SETUP_B = {
    "name":            "Setup B (27/28) — NOT WORKING",
    "mgmt_ip":         "172.16.0.27",
    "mgmt_port":       443,
    "miti_ip":         "172.16.0.28",
    "api_token":       "YOUR_TOKEN_FOR_27",   # ← CHANGE THIS
    "stack_id":        "YOUR_STACK_ID_27",    # ← CHANGE THIS
    "target_listener": "your_listener",       # ← CHANGE THIS
}

# ════════════════════════════════════════════════════════════════

RED   = "\033[91m"
GREEN = "\033[92m"
YEL   = "\033[93m"
CYAN  = "\033[96m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
RST   = "\033[0m"

def ok(msg):  print(f"  {GREEN}✅ {msg}{RST}")
def fail(msg):print(f"  {RED}❌ {msg}{RST}")
def warn(msg):print(f"  {YEL}⚠️  {msg}{RST}")
def info(msg):print(f"  {CYAN}ℹ️  {msg}{RST}")
def hdr(msg): print(f"\n{BOLD}{CYAN}{'─'*60}\n  {msg}\n{'─'*60}{RST}")
def sep():    print(f"  {DIM}{'·'*56}{RST}")

def diagnose_setup(s):
    results = {}
    name    = s["name"]

    print(f"\n{BOLD}{'═'*60}")
    print(f"  {name}")
    print(f"{'═'*60}{RST}")

    # ── 1. TCP connectivity: management ──────────────────────────
    hdr("1. Management Console Connectivity")
    try:
        sock = socket.create_connection((s["mgmt_ip"], s["mgmt_port"]), timeout=5)
        sock.close()
        ok(f"TCP connection to {s['mgmt_ip']}:{s['mgmt_port']} — SUCCESS")
        results["mgmt_tcp"] = True
    except Exception as e:
        fail(f"TCP connection to {s['mgmt_ip']}:{s['mgmt_port']} FAILED: {e}")
        results["mgmt_tcp"] = False
        warn("Cannot reach management — check IP, port, firewall")
        return results

    # ── 2. TCP connectivity: mitigation ──────────────────────────
    hdr("2. Traffic / Mitigation IP Connectivity")
    for port in [80, 443]:
        try:
            sock = socket.create_connection((s["miti_ip"], port), timeout=3)
            sock.close()
            ok(f"Mitigation {s['miti_ip']}:{port} — reachable")
            results[f"miti_tcp_{port}"] = True
        except Exception as e:
            warn(f"Mitigation {s['miti_ip']}:{port} — not reachable: {e}")
            results[f"miti_tcp_{port}"] = False

    # ── 3. HTTPS check (certificate, TLS) ────────────────────────
    hdr("3. HTTPS / TLS Check")
    base = f"https://{s['mgmt_ip']}:{s['mgmt_port']}"
    try:
        r = requests.get(base, verify=False, timeout=8, allow_redirects=True)
        ok(f"HTTPS responds — status {r.status_code}")
        results["https"] = True
        # Check if it looks like Haltdos
        if "haltdos" in r.text.lower() or "haltdos" in str(r.headers).lower():
            ok("Response looks like a Haltdos UI ✓")
            results["looks_like_haltdos"] = True
        else:
            warn("Response doesn't look like Haltdos — might be a different service on this IP")
            results["looks_like_haltdos"] = False
            info(f"Response preview: {r.text[:200]!r}")
    except Exception as e:
        fail(f"HTTPS failed: {e}")
        results["https"] = False

    # ── 4. API token check ────────────────────────────────────────
    hdr("4. API Token Authentication")
    hdrs = {
        "Authorization": f"Bearer {s['api_token']}",
        "Accept":        "application/json",
    }

    # Try /v1/stack list first (no stack_id needed)
    try:
        r = requests.get(f"{base}/v1/stack", headers=hdrs, verify=False, timeout=10)
        info(f"GET /v1/stack → {r.status_code}")
        if r.status_code == 200:
            ok("Token valid — /v1/stack works")
            results["token_valid"] = True
            try:
                data = r.json()
                stacks = data.get("data", [])
                if isinstance(stacks, dict): stacks = [stacks]
                if stacks:
                    ok(f"Found {len(stacks)} stack(s):")
                    for st in stacks:
                        sid = st.get("stackId", st.get("id", "?"))
                        sname = st.get("stackName", st.get("name", "?"))
                        info(f"  Stack ID: {sid}  Name: {sname}")
                    results["stack_ids"] = [st.get("stackId", st.get("id","?")) for st in stacks]
                else:
                    warn("No stacks returned")
                    results["stack_ids"] = []
            except Exception as e:
                warn(f"Could not parse stack list: {e}")
                info(f"Raw response: {r.text[:400]}")
        elif r.status_code == 401:
            fail("Token rejected (401) — wrong or expired token")
            results["token_valid"] = False
        elif r.status_code == 403:
            fail("Forbidden (403) — token valid but insufficient permissions")
            results["token_valid"] = False
        elif r.status_code == 404:
            warn("/v1/stack returned 404 — endpoint might differ on this version")
            results["token_valid"] = None
        else:
            warn(f"Unexpected status {r.status_code}: {r.text[:200]}")
            results["token_valid"] = None
    except Exception as e:
        fail(f"API call failed: {e}")
        results["token_valid"] = False

    # ── 5. Stack ID specific check ────────────────────────────────
    hdr(f"5. Stack ID Check: {s['stack_id']}")
    try:
        r = requests.get(f"{base}/v1/stack/{s['stack_id']}/adc",
                         headers=hdrs,
                         params={"referenceId": "LISTENER"},
                         verify=False, timeout=10)
        info(f"GET /v1/stack/{s['stack_id']}/adc?referenceId=LISTENER → {r.status_code}")

        if r.status_code == 200:
            ok(f"Stack '{s['stack_id']}' found and returned listener data")
            results["stack_found"] = True
            try:
                data = r.json()
                items = data.get("data", [])
                if isinstance(items, dict): items = [items]
                ok(f"Got {len(items)} listener(s)")
                for item in items:
                    lname = item.get("listenerName", "?")
                    try:    mode = item["modules"]["PROFILES"]["global"]["modules"]["GENERAL"]["mode"]
                    except: mode = "?"
                    enabled = item.get("enabled", False)
                    info(f"  → '{lname}' | mode: {mode} | enabled: {enabled}")
                results["listeners"] = [i.get("listenerName","?") for i in items]
            except Exception as e:
                warn(f"Could not parse listeners: {e}")
                info(f"Raw response preview: {r.text[:400]}")

        elif r.status_code == 204:
            warn("204 No Content — stack exists but has no listeners, OR API token has no access to this stack")
            results["stack_found"] = False
            results["likely_cause"] = "204 — token may not have access to this stack"

        elif r.status_code == 404:
            fail(f"Stack '{s['stack_id']}' NOT FOUND (404)")
            results["stack_found"] = False
            results["likely_cause"] = f"Stack ID '{s['stack_id']}' doesn't exist on this server"

        elif r.status_code == 401:
            fail("401 — token rejected for this specific endpoint")
            results["stack_found"] = False

        else:
            warn(f"Unexpected: {r.status_code}")
            info(f"Body: {r.text[:300]}")
            results["stack_found"] = False

    except Exception as e:
        fail(f"Stack check failed: {e}")
        results["stack_found"] = False

    # ── 6. API response structure check ──────────────────────────
    hdr("6. API Response Structure Analysis")
    if results.get("stack_found"):
        try:
            r = requests.get(f"{base}/v1/stack/{s['stack_id']}/adc",
                             headers=hdrs,
                             params={"referenceId": "LISTENER"},
                             verify=False, timeout=10)
            data = r.json()
            items = data.get("data", [])
            if isinstance(items, dict): items = [items]

            if items:
                sample = items[0]
                ok("Checking JSON structure of first listener...")

                # Check all the paths our engine uses
                paths_to_check = [
                    ("PROFILES.global.modules.GENERAL.mode",
                     lambda d: d["modules"]["PROFILES"]["global"]["modules"]["GENERAL"]["mode"]),
                    ("PROFILES.global.modules.BOT.badReputationTraffic",
                     lambda d: d["modules"]["PROFILES"]["global"]["modules"]["BOT"]["badReputationTraffic"]),
                    ("PROFILES.global.modules.POLICY.modules.WEB.allowedHttpMethods",
                     lambda d: d["modules"]["PROFILES"]["global"]["modules"]["POLICY"]["modules"]["WEB"]["allowedHttpMethods"]),
                    ("OPERATIONAL.enableLog",
                     lambda d: d["modules"]["OPERATIONAL"]["enableLog"]),
                    ("SSL.enabled",
                     lambda d: d["modules"]["SSL"]["enabled"]),
                    ("SERVER_GROUPS.global.modules.SERVERS.servers",
                     lambda d: d["modules"]["SERVER_GROUPS"]["global"]["modules"]["SERVERS"]["servers"]),
                    ("RULES.modules (listener-level)",
                     lambda d: d["modules"]["RULES"]["modules"]),
                    ("PROFILES.global.modules.RULES.modules (profile-level)",
                     lambda d: d["modules"]["PROFILES"]["global"]["modules"]["RULES"]["modules"]),
                ]

                path_results = {}
                for path_name, accessor in paths_to_check:
                    try:
                        val = accessor(sample)
                        ok(f"  ✓ {path_name}")
                        if isinstance(val, (str, bool, int, float)):
                            info(f"    Value: {val}")
                        path_results[path_name] = True
                    except (KeyError, TypeError) as e:
                        fail(f"  ✗ {path_name} — MISSING: {e}")
                        path_results[path_name] = False

                results["path_checks"] = path_results
                missing = [k for k,v in path_results.items() if not v]
                if missing:
                    warn(f"\n  {len(missing)} path(s) missing — these will cause the engine to use fallback values")
                    warn("  This usually means a different Haltdos version or different API structure")
                else:
                    ok("All JSON paths match expected structure ✓")

        except Exception as e:
            warn(f"Structure check failed: {e}")

    # ── 7. Mitigation IP traffic test ────────────────────────────
    hdr("7. Traffic IP — Actual HTTP Request Test")
    target_host = s.get("target_listener", "")
    if target_host and results.get(f"miti_tcp_80"):
        try:
            r = requests.get(f"http://{s['miti_ip']}/",
                             headers={"Host": target_host, "User-Agent": "WAF-Diagnostic/1.0"},
                             timeout=6, verify=False, allow_redirects=False)
            ok(f"HTTP request to mitigation IP → {r.status_code}")
            info(f"Location header: {r.headers.get('Location','(none)')}")
            info(f"Server header: {r.headers.get('Server','(none)')}")
            results["miti_http"] = r.status_code
        except requests.exceptions.ConnectionError as e:
            warn(f"Connection refused/reset to mitigation IP: {e}")
            info("This could mean: wrong IP, WAF not running, or firewall blocking")
            results["miti_http"] = "CONN_ERR"
        except Exception as e:
            warn(f"Traffic test failed: {e}")
            results["miti_http"] = "ERR"
    else:
        warn("Skipping traffic test — mitigation IP not reachable on port 80")

    # ── 8. Summary ────────────────────────────────────────────────
    hdr("SUMMARY")
    all_good = all([
        results.get("mgmt_tcp"),
        results.get("token_valid"),
        results.get("stack_found"),
    ])
    if all_good:
        ok(f"Setup '{name}' should work with the engine")
    else:
        fail(f"Setup '{name}' has issues — see details above")
        if not results.get("mgmt_tcp"):
            fail("ROOT CAUSE: Management IP not reachable")
        elif not results.get("token_valid"):
            fail("ROOT CAUSE: API token is wrong/expired/insufficient permissions")
        elif not results.get("stack_found"):
            fail(f"ROOT CAUSE: {results.get('likely_cause', 'Stack ID not found')}")
        elif results.get("path_checks"):
            missing = [k for k,v in results.get("path_checks",{}).items() if not v]
            if missing:
                fail(f"ROOT CAUSE: API response structure mismatch ({len(missing)} paths missing)")
                warn("FIX: The engine's JSON path traversal needs to be updated for this Haltdos version")

    return results


def compare_setups(r_a, r_b):
    print(f"\n\n{BOLD}{'═'*60}")
    print(f"  SIDE-BY-SIDE COMPARISON")
    print(f"{'═'*60}{RST}")

    checks = [
        ("mgmt_tcp",          "Management TCP reachable"),
        ("https",             "HTTPS works"),
        ("looks_like_haltdos","Looks like Haltdos"),
        ("token_valid",       "API token valid"),
        ("stack_found",       "Stack ID found"),
        ("miti_tcp_80",       "Mitigation port 80"),
        ("miti_tcp_443",      "Mitigation port 443"),
    ]

    print(f"\n  {'Check':<35} {'Setup A (72/73)':<18} {'Setup B (27/28)'}")
    print(f"  {'─'*35} {'─'*18} {'─'*16}")
    for key, label in checks:
        va = r_a.get(key)
        vb = r_b.get(key)
        ca = GREEN + "PASS" + RST if va is True else (RED + "FAIL" + RST if va is False else YEL + "N/A " + RST)
        cb = GREEN + "PASS" + RST if vb is True else (RED + "FAIL" + RST if vb is False else YEL + "N/A " + RST)
        print(f"  {label:<35} {ca:<25} {cb}")

    # Path checks comparison
    pa = r_a.get("path_checks", {})
    pb = r_b.get("path_checks", {})
    if pa or pb:
        print(f"\n  {'JSON Path':<35} {'Setup A':<18} {'Setup B'}")
        print(f"  {'─'*35} {'─'*18} {'─'*16}")
        all_paths = set(list(pa.keys()) + list(pb.keys()))
        for path in sorted(all_paths):
            va = pa.get(path)
            vb = pb.get(path)
            ca = GREEN + "✓" + RST if va else (RED + "✗" + RST if va is False else DIM + "-" + RST)
            cb = GREEN + "✓" + RST if vb else (RED + "✗" + RST if vb is False else DIM + "-" + RST)
            short = path[:33] + ".." if len(path) > 35 else path
            print(f"  {short:<35} {ca:<25} {cb}")

    # Diagnosis
    print(f"\n{BOLD}  DIAGNOSIS:{RST}")
    a_works = r_a.get("stack_found") and r_a.get("token_valid")
    b_works = r_b.get("stack_found") and r_b.get("token_valid")

    if a_works and not b_works:
        print(f"\n  {YEL}Setup A works, Setup B doesn't. Most likely causes:{RST}")
        if not r_b.get("mgmt_tcp"):
            print(f"  {RED}  1. Network — 27/28 not reachable from this machine. Check routing.{RST}")
        if not r_b.get("token_valid"):
            print(f"  {RED}  2. Auth — Wrong API token for the 27/28 cluster. Tokens are per-cluster.{RST}")
        if not r_b.get("stack_found") and r_b.get("token_valid"):
            print(f"  {RED}  3. Stack ID — The stack ID for 27/28 is different. Check the URL when logged into 27.{RST}")
        pb_fail = [k for k,v in pb.items() if not v]
        pa_fail = [k for k,v in pa.items() if not v]
        new_fails = set(pb_fail) - set(pa_fail)
        if new_fails:
            print(f"  {YEL}  4. API structure differs on 27/28:{RST}")
            for f in new_fails:
                print(f"     {RED}  → {f}{RST}")
            print(f"  {YEL}     This means a different Haltdos version or different config structure.{RST}")
            print(f"  {YEL}     The engine needs fallbacks added for these paths.{RST}")
    elif a_works and b_works:
        print(f"  {GREEN}  Both setups look compatible. If the engine still fails on 27/28,{RST}")
        print(f"  {GREEN}  run the engine with DEBUG=True to see the exact error.{RST}")


def main():
    print(f"\n{BOLD}{'█'*60}")
    print(f"  HALTDOS WAF TESTER — DIAGNOSTIC TOOL")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'█'*60}{RST}")

    print(f"\n{YEL}NOTE: This tool does NOT fire any attack payloads.")
    print(f"      It only makes read-only API calls and TCP checks.{RST}")

    results_a = diagnose_setup(SETUP_A)
    results_b = diagnose_setup(SETUP_B)
    compare_setups(results_a, results_b)

    print(f"\n{DIM}Tip: If Stack ID is wrong for 27, log into https://172.16.0.27 in your browser,")
    print(f"     navigate to the stack, and copy the ID from the URL:{RST}")
    print(f"     https://172.16.0.27/stack/{{STACK_ID}}/apps\n")


if __name__ == "__main__":
    main()