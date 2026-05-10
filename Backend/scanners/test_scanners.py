import sys, json
sys.path.insert(0, '/app/scanners')

from nmap_scanner import run_nmap
from sqlmap_scanner import run_sqlmap
from nikto_scanner import run_nikto
from wfuzz_scanner import run_wfuzz

DVWA = 'dvwa'
DVWA_HTTP = 'http://dvwa'

tests = [
    ('nmap',   lambda: run_nmap(DVWA, 'standard')),
    ('nikto',  lambda: run_nikto(DVWA_HTTP)),
    ('wfuzz',  lambda: run_wfuzz(DVWA_HTTP)),
    ('sqlmap', lambda: run_sqlmap(DVWA_HTTP + '/login.php')),
]

results = {}
for name, fn in tests:
    print(f'\nTesting {name}...')
    try:
        r = fn()
        results[name] = r
        count = len(r.get('findings') or r.get('found_paths') or r.get('ports') or [])
        print(f'  OK — {count} findings')
    except Exception as e:
        results[name] = {'error': str(e)}
        print(f'  ERROR: {e}')

with open('/tmp/test_results.json', 'w') as f:
    json.dump(results, f, indent=2)
print('\nSaved to /tmp/test_results.json')
