from flask import Flask, jsonify, request, render_template, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix
from waf.request_analyzer import analyze_request
from waf.logger import get_logs
from waf.attack_tracker import get_banned_ips

app = Flask(__name__, template_folder='dashboard')

# Trust 1 proxy hop (Nginx). This makes request.remote_addr return
# the real client IP from the X-Forwarded-For header instead of 127.0.0.1.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# -------------------------------------------------------------
# WAF Middleware
# -------------------------------------------------------------
@app.before_request
def waf_middleware():
    """
    This function runs before every single request to intercept and analyze payloads.
    """
    return analyze_request()

# -------------------------------------------------------------
# Dummy Application Routes (To test the WAF against)
# -------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Simulated authentication
        return jsonify({"message": "Login attempt processed (WAF allowed it)."})
    return jsonify({"message": "Login page GET request successful."})

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    return jsonify({
        "message": f"Search executed for: {query}",
        "status": "success - WAF allowed the request"
    })

@app.route('/upload', methods=['POST'])
def upload():
    return jsonify({"message": "File upload simulated (WAF allowed it)."})

# -------------------------------------------------------------
# Dashboard & Analytics Routes
# -------------------------------------------------------------
@app.route('/')
def home():
    """Serve the interactive dummy website."""
    return render_template('site.html')

@app.route('/dashboard_ui')
def dashboard():
    """Serve the WAF dashboard HTML."""
    return render_template('index.html')

@app.route('/dashboard/<path:filename>')
def dashboard_static(filename):
    """Serve the static files (JS/CSS) for the dashboard."""
    return send_from_directory('dashboard', filename)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """
    Compute analytics from the logs JSON file for the dashboard Chart.js UI.
    """
    logs = get_logs()
    
    # 1. Total attacks
    total_attacks = len(logs)
    
    # 2. Attacks by Type
    attack_types = {}
    for log in logs:
        # Check if the WAF intercepted a raw Regex match or if it was blocked by the generic IP ban
        atype = log.get("attack_type", "Unknown")
        attack_types[atype] = attack_types.get(atype, 0) + 1
        
    # 3. Attacks per IP
    ip_distribution = {}
    for log in logs:
        ip = log.get("ip_address", "Unknown")
        ip_distribution[ip] = ip_distribution.get(ip, 0) + 1
        
    # Sort top 5 attacking IPs
    top_ips = sorted(ip_distribution.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # 4. Severity breakdown
    severity_breakdown = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for log in logs:
        sev = log.get("severity", "LOW")
        if sev in severity_breakdown:
            severity_breakdown[sev] += 1
            
    # 5. Attack Timeline (Grouping by Hour/Minute)
    # For a minimal view, we just group the last 10-20 attacks
    timeline = []
    for log in reversed(logs[-20:]): # Last 20 recent attacks
        timeline.append({
            "time": log.get("timestamp")[11:19], # Extract HH:MM:SS
            "type": log.get("attack_type")
        })

    return jsonify({
        "total_attacks": total_attacks,
        "attack_types": attack_types,
        "top_ips": top_ips,
        "severity": severity_breakdown,
        "timeline": timeline,
        "banned_ips_count": len(get_banned_ips())
    })

@app.route('/api/logs', methods=['GET'])
def get_raw_logs():
    """Return raw log entries."""
    logs = get_logs()
    # Return last 50 logs reversed
    return jsonify(list(reversed(logs[-50:])))

if __name__ == '__main__':
    # Run the Flask app on all interfaces (0.0.0.0) so it's accessible externally on EC2
    app.run(host='0.0.0.0', port=5000, debug=True)
