from collections import defaultdict

# A simple in-memory dictionary to track attacks per IP
ATTACK_COUNTS = defaultdict(int)
BLOCK_THRESHOLD = 5

def track_attack(ip_address):
    """
    Increment the attack count for a given IP.
    """
    ATTACK_COUNTS[ip_address] += 1

def is_ip_blocked(ip_address):
    """
    Check if an IP has exceeded the allowed number of malicious requests.
    Returns True if blocked, False otherwise.
    """
    return ATTACK_COUNTS.get(ip_address, 0) >= BLOCK_THRESHOLD

def get_banned_ips():
    """
    Return a list of all currently blocked IP addresses.
    """
    return [ip for ip, count in ATTACK_COUNTS.items() if count >= BLOCK_THRESHOLD]

def unban_ip(ip_address):
    """
    Remove an IP from the banned list by resetting its attack count.
    """
    if ip_address in ATTACK_COUNTS:
        del ATTACK_COUNTS[ip_address]
