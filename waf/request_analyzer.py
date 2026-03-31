from flask import request, abort, jsonify
import urllib.parse
from .rule_engine import check_payload
from .logger import log_attack
from .attack_tracker import track_attack, is_ip_blocked

def analyze_request():
    """
    Middleware function designed to be used with Flask's before_request.
    Inspects headers, query params, body and path.
    Blocks the request if malicious payloads are detected or if IP is banned.
    """
    ip_address = request.remote_addr
    
    # 1. Check if IP is already blocked due to previous attacks
    if is_ip_blocked(ip_address):
        # We can immediately reject to save processing power
        return jsonify({"error": "Forbidden. Your IP has been banned due to repeated malicious requests."}), 403

    # 2. Extract potential payloads for analysis
    path = request.path
    
    # Don't inspect static files or pure dashboard API calls to be safe
    if path.startswith('/api/') or path.startswith('/static/'):
        return None
        
    payloads = []
    
    # Extract query parameters
    for key, value in request.args.items():
        payloads.append(f"{key}={value}")
        
    # Extract form data
    if request.form:
        for key, value in request.form.items():
            payloads.append(f"{key}={value}")
    
    # Extract JSON body
    if request.is_json:
        try:
            json_data = request.get_json(silent=True)
            if json_data:
                # Convert dict to string for simplistic regex checking
                payloads.append(str(json_data))
        except Exception:
            pass
            
    # Extract headers (specifically looking at User-Agent and Referer)
    headers_to_check = ['User-Agent', 'Referer']
    for header in headers_to_check:
        val = request.headers.get(header)
        if val:
            payloads.append(f"{header}: {val}")
            
    # Include the path itself
    payloads.append(path)

    # Decode payloads once to catch URL-encoded attacks
    decoded_payloads = [urllib.parse.unquote(p) for p in payloads]
    combined_payloads = payloads + decoded_payloads
    
    # 3. Analyze all extracted data
    for payload in combined_payloads:
        matched_rule = check_payload(payload)
        
        if matched_rule:
            # Attack detected!
            track_attack(ip_address)
            log_attack(
                ip_address=ip_address,
                path=path,
                payload=payload,
                rule_id=matched_rule["rule_id"],
                rule_name=matched_rule["rule_name"],
                severity=matched_rule["severity"],
                attack_type=matched_rule["attack_type"]
            )
            
            # Issue HTTP 403 Forbidden
            return jsonify({
                "error": "Forbidden", 
                "message": "Malicious payload detected and blocked by WAF.",
                "rule_triggered": matched_rule["attack_type"]
            }), 403
            
    # Return None allows the request to proceed to the Flask route
    return None
