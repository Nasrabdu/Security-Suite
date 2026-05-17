import requests
import os

s = requests.Session()
s.post('http://localhost:5000/api/auth/login', json={
    'email': os.environ.get('ADMIN_EMAIL', 'admin@security.com'),
    'password': os.environ['ADMIN_PASSWORD']
})
res = s.post('http://localhost:5000/api/scan', json={'target':'google.com', 'scan_type':'normal', 'consent':True})
print("Scan:", res.status_code, res.text)
