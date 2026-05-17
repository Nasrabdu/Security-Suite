import requests
import os

s = requests.Session()
res = s.post('http://localhost:5000/api/auth/login', json={
    'email': os.environ.get('ADMIN_EMAIL', 'admin@security.com'),
    'password': os.environ['ADMIN_PASSWORD']
})
print("Login:", res.status_code, res.text)

res = s.post('http://localhost:5000/api/ping', json={'target':'google.com'})
print("Ping:", res.status_code, res.text)
