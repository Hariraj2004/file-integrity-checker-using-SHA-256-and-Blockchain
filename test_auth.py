import requests

s = requests.Session()

# 1. Unauthenticated request to /api/files should fail
res1 = s.get("http://localhost:5000/api/files")
print("1. /api/files (no auth):", res1.status_code, res1.text)

# 2. Login with bad password
res2 = s.post("http://localhost:5000/api/auth/login", json={"password": "wrong"})
print("2. /api/auth/login (bad):", res2.status_code, res2.text)

# 3. Login with good password
res3 = s.post("http://localhost:5000/api/auth/login", json={"password": "admin123"})
print("3. /api/auth/login (good):", res3.status_code, res3.text)

# 4. Authenticated request to /api/files should succeed
res4 = s.get("http://localhost:5000/api/files")
print("4. /api/files (auth):", res4.status_code, len(res4.json()), "files returned")

# 5. Logout
res5 = s.post("http://localhost:5000/api/auth/logout")
print("5. /api/auth/logout:", res5.status_code, res5.text)

# 6. Unauthenticated request to /api/files should fail again
res6 = s.get("http://localhost:5000/api/files")
print("6. /api/files (no auth):", res6.status_code, res6.text)

