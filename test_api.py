import requests

url = "http://localhost:5000/api/health"
print("Health:", requests.get(url).json())

files = {"file": ("test.txt", "hello world")}
res = requests.post("http://localhost:5000/api/files/register", files=files)
print("Register:", res.status_code, res.text)

res2 = requests.post("http://localhost:5000/api/files/register", files={"file": ("test.txt", "hello world")})
print("Register again:", res2.status_code, res2.text)

res3 = requests.post("http://localhost:5000/api/files/register", files={"file": ("test.txt", "tampered text")})
print("Register tampered:", res3.status_code, res3.text)

print("Files:", requests.get("http://localhost:5000/api/files").json())
