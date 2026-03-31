import re

# Severity Levels
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"

# Attack Types
SQLI = "SQLi"
XSS = "XSS"
CMD_INJ = "Command Injection"
PATH_TRAV = "Path Traversal"

# WAF Rules
RULES = [
    {
        "rule_id": "R001",
        "rule_name": "Basic SQLi (OR 1=1)",
        "regex_pattern": re.compile(r"(\%27|')\s*(OR|AND)\s*(1=1|\d=\d|'.*?'='.*?')", re.IGNORECASE),
        "severity": HIGH,
        "attack_type": SQLI
    },
    {
        "rule_id": "R002",
        "rule_name": "SQLi UNION SELECT",
        "regex_pattern": re.compile(r"UNION\s+(ALL\s+)?SELECT", re.IGNORECASE),
        "severity": HIGH,
        "attack_type": SQLI
    },
    {
        "rule_id": "R003",
        "rule_name": "SQLi DROP Statement",
        "regex_pattern": re.compile(r";\s*DROP\s+TABLE", re.IGNORECASE),
        "severity": HIGH,
        "attack_type": SQLI
    },
    {
        "rule_id": "R004",
        "rule_name": "Basic XSS Tags",
        "regex_pattern": re.compile(r"<\s*script.*?>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL),
        "severity": HIGH,
        "attack_type": XSS
    },
    {
        "rule_id": "R005",
        "rule_name": "XSS JavaScript URI",
        "regex_pattern": re.compile(r"javascript:\s*", re.IGNORECASE),
        "severity": MEDIUM,
        "attack_type": XSS
    },
    {
        "rule_id": "R006",
        "rule_name": "XSS OnError Event",
        "regex_pattern": re.compile(r"onerror\s*=", re.IGNORECASE),
        "severity": MEDIUM,
        "attack_type": XSS
    },
    {
        "rule_id": "R007",
        "rule_name": "Command Injection (; or &&)",
        "regex_pattern": re.compile(r"(;|&&)\s*(ls|cat|ping|wget|curl|nc\s+)", re.IGNORECASE),
        "severity": HIGH,
        "attack_type": CMD_INJ
    },
    {
        "rule_id": "R008",
        "rule_name": "Path Traversal (../)",
        "regex_pattern": re.compile(r"(\.\./|\.\.\\)+"),
        "severity": HIGH,
        "attack_type": PATH_TRAV
    }
]

def check_payload(payload):
    """
    Search payload against all detection rules.
    Returns the first matching rule or None.
    """
    if not payload:
        return None
        
    for rule in RULES:
        if rule['regex_pattern'].search(str(payload)):
            return rule
            
    return None
