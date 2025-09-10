"""
config.py
---------
Centralized project configuration settings and tunable constants.
"""

import os

# -------------------------------------------------------------
# Paths
# -------------------------------------------------------------
BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR: str = os.path.join(BASE_DIR, 'utils')
MODULES_DIR: str = os.path.join(BASE_DIR, 'vulnerability_modules')
REPORTS_DIR: str = os.path.join(BASE_DIR, 'reporting')
PAYLOADS_DIR: str = os.path.join(BASE_DIR, 'payloads')

# -------------------------------------------------------------
# HTTP Connection Constants
# -------------------------------------------------------------
# Base timeout for all HTTP requests to prevent hangs
DEFAULT_TIMEOUT: int = 10

# Defines the retry mechanism logic for resilience
# Essential when scanning Docker containers on Windows which frequently drop TCP connections
HTTP_MAX_RETRIES: int = 3
HTTP_BACKOFF_FACTOR: float = 0.5

# HTTP status codes that trigger an automatic retry
HTTP_RETRY_STATUS: list = [500, 502, 503, 504]

# -------------------------------------------------------------
# Crawler Configuration
# -------------------------------------------------------------
# The crawler will IGNORE any URL containing these terms (case-insensitive).
CRAWLER_DENY_LIST: list = [
    # Session-destroying actions
    'logout', 'signout', 'logoff',
    # OS command execution — shell payloads cause worker pool starvation
    'vulnerabilities/exec',
    # File uploads write real files to the server
    'vulnerabilities/upload',
    # reCAPTCHA — cannot be solved by a scanner
    'vulnerabilities/captcha',
]

# The crawler will IGNORE any URL ending in these extensions.
CRAWLER_SKIP_EXTENSIONS: tuple = (
    '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.pdf', '.zip', '.rar'
)

# -------------------------------------------------------------
# Scanner Rules
# -------------------------------------------------------------
# These paths belong to features that, if injected with random characters,
# cause legitimate server side-effects (creating files, exhausting shell pools)
# and corrupt the web server environment for all subsequent payloads.
SKIP_SCAN_PATTERNS: list = [
    'vulnerabilities/exec',
    'vulnerabilities/upload',
    'vulnerabilities/captcha',
    'vulnerabilities/weak_id',
]

# HTML input types considered safe to inject into.
# Hidden inputs, file inputs, etc. are excluded deliberately.
TESTABLE_INPUT_TYPES: tuple = (
    'text', 'password', 'search', 'number', 'email', 'tel', 'url', ''
)
