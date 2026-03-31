# WAF EC2 Deployment Guide

These instructions describe how to deploy this Python Flask Web Application Firewall to an AWS EC2 instance running Ubuntu and how to run simulated attacks to prove its functionality.

## 1. AWS EC2 Setup

1. Launch a **Ubuntu 22.04 LTS** (or similar) EC2 Instance in your AWS Console.
2. In the Security Group attached to the instance, ensure you allow incoming traffic on:
   - **Port 22** (SSH)
   - **Port 80** (HTTP)
   - **Port 5000** (Flask - if you want to access the app directly without Nginx)
3. SSH into your instance:
   ```bash
   ssh -i your-key.pem ubuntu@<EC2-PUBLIC-IP>
   ```

## 2. Environment Setup

Update the package lists and install required tools:
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip python3-venv nginx -y
```

Clone your project (or copy it over via `scp`):
```bash
# Example if using git
git clone <your-repo-url> /home/ubuntu/waf-project
cd /home/ubuntu/waf-project
```

Create an isolated virtual environment and install the dependencies (Flask, Gunicorn):
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 3. Running the Server

### Option A: Development Mode (Testing)
Run the Flask server directly. It runs on `0.0.0.0:5000`.
```bash
python3 app.py
```
*Access your Web App at: `http://<EC2-PUBLIC-IP>:5000/`*
*Access your WAF dashboard at: `http://<EC2-PUBLIC-IP>:5000/dashboard_ui`*

### Option B: Production Mode (Gunicorn + Nginx)
To run the WAF reliably, you should bind app via Gunicorn.

1. Start Gunicorn in the background:
   ```bash
   # Runs with 3 workers, binds to local port 5000
   gunicorn -w 3 -b 127.0.0.1:5000 app:app --daemon
   ```
2. Configure Nginx to proxy traffic to Gunicorn. Open the default site config:
   ```bash
   sudo nano /etc/nginx/sites-available/default
   ```
   Replace the `location /` block with:
   ```nginx
   server {
       listen 80;
       server_name _;

       location / {
           proxy_pass http://127.0.0.1:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       }
   }
   ```
3. Restart Nginx:
   ```bash
   sudo systemctl restart nginx
   ```
*Access your Web App directly at: `http://<EC2-PUBLIC-IP>/`*
*Access your WAF dashboard directly at: `http://<EC2-PUBLIC-IP>/dashboard_ui`*

---

## 4. Testing the WAF (SQLi, XSS, Path Traversal)

Our WAF acts as an interceptor. If you hit a valid route with a malicious payload, it will block you and log the attempt to the Dashboard.

### Valid Request
Run a valid search command (Expect a **200 OK** JSON success message):
```bash
curl "http://localhost:5000/search?q=cybersecurity"
```

### SQL Injection Testing
To test the SQL Injection rule functionality, we trigger our `<rule_id: R001>` and `<rule_id: R002>` regex triggers.

**Test 1: Classic OR 1=1 bypass**
```bash
curl -v "http://localhost:5000/search?q=' OR 1=1"
```
Expect an HTTP **403 Forbidden** with block message: *"Malicious payload detected"*

**Test 2: Union Select Injection**
```bash
curl -v "http://localhost:5000/search?q=1 UNION SELECT uname, password FROM users"
```
Expect an HTTP **403 Forbidden**.

### XSS Testing
Test Cross-Site Scripting filtering.

```bash
curl -v "http://localhost:5000/search?q=<script>alert('hacked')</script>"
```
Expect an HTTP **403 Forbidden**.

*(You can also use your web browser to test all these payloads simply by pasting the URL!)*

### IP Banning System Proof
To demonstrate the "Repeat Offender" automated blockage mechanism:
1. Fire 5 malicious payloads rapidly using `curl`.
2. Open the dashboard manually via a browser—you should see your attack count mapped in Chart.js.
3. Once your attacks reach the `BLOCK_THRESHOLD` limit (5), fire a completely benign request (like `http://localhost:5000/search?q=normal`).
4. Result: Your benign request is **refused** (403 Forbidden) because your IP identity is now globally restricted due to the previous attacks.
