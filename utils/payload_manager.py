"""
payload_manager.py
------------------
Handles the loading and management of payloads for SQL Injection and XSS attacks.
Ethical Note: Only use these payloads on authorized, intentionally vulnerable targets!
"""

import os

PAYLOADS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'payloads')

def load_payloads(filename):
    """Load payloads from a file, one per line, skipping blanks and comments."""
    path = os.path.join(PAYLOADS_DIR, filename)
    payloads = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    payloads.append(line)
    except Exception as e:
        print(f"[!] Could not load payloads from {filename}: {e}")
    return payloads

# Load SQL injection payloads
def get_sqli_payloads():
    """Get a list of SQL Injection payloads."""
    return load_payloads('sqli_payloads.txt')

def get_xss_payloads():
    """Get a list of XSS payloads."""
    return load_payloads('xss_payloads.txt') 
# Payload validation and filtering
# Remove duplicate payloads for efficiency
# Payload rotation for WAF evasion
# Smart payload prioritization
# payload cleanup
