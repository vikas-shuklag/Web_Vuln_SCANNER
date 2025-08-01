"""
http_client.py
--------------
A friendly HTTP client wrapper for GET and POST requests, with support for headers, cookies, and basic error handling.
Ethical Note: Only use this client on authorized targets!
"""

import requests

class HTTPClient:
    def __init__(self, base_url, cookies=None, headers=None, auth=None, timeout=10):
        self.base_url = base_url
        self.session = requests.Session()  # Persistent HTTP session()
        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)
        self.auth = auth
        self.timeout = timeout

    def get(self, url, params=None):
        try:
            resp = self.session.get(url, params=params, auth=self.auth, timeout=self.timeout)
            return resp
        except Exception as e:  # Enhanced error handling
            print(f"[!] GET request failed: {e}")
            return None

    def post(self, url, data=None):
        try:
            resp = self.session.post(url, data=data, auth=self.auth, timeout=self.timeout)
            return resp
        except Exception as e:  # Enhanced error handling
            print(f"[!] POST request failed: {e}")
            return None 
# Authentication support for protected targets
# Connection pooling for performance
# SSL/TLS certificate verification
