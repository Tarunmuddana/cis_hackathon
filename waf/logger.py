import os
import json
from datetime import datetime
import threading

# Use a threading lock to avoid file corruption on concurrent writes
lock = threading.Lock()

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'attacks.json')

def setup_logger():
    """Ensure the log directory and file exist."""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w') as f:
            json.dump([], f)

def log_attack(ip_address, path, payload, rule_id, rule_name, severity, attack_type):
    """
    Log an attack to the json file.
    """
    setup_logger()
    
    attack_data = {
        "timestamp": datetime.now().isoformat(),
        "ip_address": ip_address,
        "path": path,
        "payload": payload,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "attack_type": attack_type
    }
    
    with lock:
        try:
            with open(LOG_FILE, 'r') as f:
                logs = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            logs = []
            
        logs.append(attack_data)
        
        with open(LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=4)

def get_logs():
    """Retrieve all logs for the dashboard analytics."""
    setup_logger()
    with lock:
        try:
            with open(LOG_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
