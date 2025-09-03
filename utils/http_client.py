"""
http_client.py
--------------
Authenticated HTTP client with automatic retry on stale connections.
Provides a resilient session wrapper extending `requests` to handle
transient networking and Docker socket drops.
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import DEFAULT_TIMEOUT, HTTP_MAX_RETRIES, HTTP_BACKOFF_FACTOR, HTTP_RETRY_STATUS


class HTTPClient:
    """Wrapper around requests.Session providing resilient connection pooling."""

    def __init__(self, base_url: str, cookies: dict = None, headers: dict = None, auth: tuple = None, timeout: int = DEFAULT_TIMEOUT):
        self.base_url = base_url
        self.auth = auth
        self.timeout = timeout
        self.cookies = cookies or {}
        self.headers = headers or {}
        self._build_session()

    def _build_session(self) -> None:
        """Create a fresh requests.Session with retry strategy."""
        self.session = requests.Session()
        
        # Automatically retry on connection errors, read errors, and configured HTTP error statuses
        retry = Retry(
            total=HTTP_MAX_RETRIES,
            backoff_factor=HTTP_BACKOFF_FACTOR,
            status_forcelist=HTTP_RETRY_STATUS,
            allowed_methods=['GET', 'POST'],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        if self.cookies:
            self.session.cookies.update(self.cookies)
        if self.headers:
            self.session.headers.update(self.headers)

    def _reset(self) -> None:
        """Rebuild the session to clear any stale connection pool state."""
        old_cookies = dict(self.session.cookies)
        self.session.close()
        self._build_session()
        # Re-apply any cookies that were set during the active session
        self.session.cookies.update(old_cookies)

    def get(self, url: str, params: dict = None) -> requests.Response | None:
        """Issue an HTTP GET request with transient failure recovery."""
        try:
            return self.session.get(url, params=params, auth=self.auth, timeout=self.timeout)
        except requests.exceptions.ConnectionError:
            # Stale connection — reset session and retry once
            self._reset()
            try:
                return self.session.get(url, params=params, auth=self.auth, timeout=self.timeout)
            except Exception as e:
                print(f"[!] GET failed after retry: {e}")
                return None
        except Exception as e:
            print(f"[!] GET request failed: {e}")
            return None

    def post(self, url: str, data: dict = None) -> requests.Response | None:
        """Issue an HTTP POST request with transient failure recovery."""
        try:
            return self.session.post(url, data=data, auth=self.auth, timeout=self.timeout)
        except requests.exceptions.ConnectionError:
            self._reset()
            try:
                return self.session.post(url, data=data, auth=self.auth, timeout=self.timeout)
            except Exception as e:
                print(f"[!] POST failed after retry: {e}")
                return None
        except Exception as e:
            print(f"[!] POST request failed: {e}")
            return None
