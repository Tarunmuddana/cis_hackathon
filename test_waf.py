import urllib.request
import urllib.parse
import json

def test_request(path, params):
    query_string = urllib.parse.urlencode(params)
    url = f"http://localhost:5000{path}?{query_string}"
    
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as response:
            status = response.getcode()
            body = response.read().decode('utf-8')
            print(f"[{status}] OK: {url}\n{body}")
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8')
        print(f"[{e.code}] BLOCKED: {url}\n{body}")
    except Exception as e:
        print(f"ERROR: {e}")

print("Testing Normal Request:")
test_request('/search', {'q': 'normal query'})

print("\nTesting SQL Injection:")
test_request('/search', {'q': "' OR 1=1"})

print("\nTesting XSS:")
test_request('/search', {'q': "<script>alert(1)</script>"})

print("\nTesting Repeated Attacks (Triggering Ban Limit):")
for i in range(5):
    test_request('/search', {'q': f"../../etc/passwd step {i}"})

print("\nTesting Normal Request After Ban:")
test_request('/search', {'q': 'normal query'})
