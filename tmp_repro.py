import queue
from engine import WAFEngine
cfg = {
    'setup_type': 'standalone',
    'mgmt_ip': '172.105.59.224',
    'mgmt_port': 9000,
    'miti_ip': '172.105.59.224',
    'api_token': 'eyJhbGciOiJIUzI1NiJ9.eyJhdXRob3JpdHkiOiJUT0tFTl9VU0VSIiwic3ViIjoicXRnc2J5bnBpZmY5a202cyIsImlhdCI6MTc4MzE4NTgzMX0.pbg0nC0Dziu8zyFJyrtmgjV6SAU-EU6TLaghAQ7ocCE',
    'stack_id': 'PZF87FTTHC',
    'target_listener': 'roti.com',
    'use_https_traffic': False,
    'profile_name': 'Pratyush',
    'report_name': 'test.json',
}
q = queue.Queue()
engine = WAFEngine(cfg, q, phases={
    'phase1_preflight': True,
    'phase2_config': True,
    'phase3_rules': True,
    'phase4_attacks': True,
    'phase5_features': True,
    'phase6_incidents': True,
    'phase7_report': True,
}, attack_delay=0.1)
report = engine.run()
print('REPORT_NONE', report is None)
print('REPORT_KEYS', list(report.keys()) if report else None)
print('VERDICT', report.get('verdict') if report else None)
print('ATTACK_COUNT', len(report.get('attack_results', [])) if report else None)
