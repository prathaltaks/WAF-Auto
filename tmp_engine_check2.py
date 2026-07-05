import json, queue, threading, time
from engine import WAFEngine
from pathlib import Path

profiles = json.loads(Path('profiles.json').read_text(encoding='utf-8'))
profile = profiles[0]
q = queue.Queue()
engine = WAFEngine({
    'setup_type': profile.get('setup_type', 'cluster'),
    'mgmt_ip': profile.get('mgmt_ip'),
    'mgmt_port': profile.get('mgmt_port', 443),
    'miti_ip': profile.get('miti_ip') or profile.get('mgmt_ip'),
    'api_token': profile.get('api_token', ''),
    'stack_id': profile.get('stack_id'),
    'target_listener': profile.get('target_listener'),
    'use_https_traffic': bool(profile.get('use_https_traffic', False)),
    'profile_name': profile.get('name'),
    'report_name': 'tmp_report.json',
}, q, phases={'phase4_attacks': True, 'phase7_report': True}, attack_delay=0.0)

threading.Thread(target=engine.run, daemon=True).start()
finished = False
while not finished:
    try:
        e = q.get(timeout=5)
    except Exception:
        print('TIMEOUT waiting for event')
        break
    print('EVENT', e)
    if e.get('type') == 'test_complete':
        finished = True
