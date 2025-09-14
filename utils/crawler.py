"""
crawler.py
----------
Spider module mapping the target domain surface.
Discovers and yields newly found distinct URLs for vulnerability scanning.
Respects authentication cookies via http_client session.
"""

from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

from config import CRAWLER_DENY_LIST, CRAWLER_SKIP_EXTENSIONS


def crawl(http_client, start_url: str, max_depth: int = 1, verbose: bool = False) -> list[str]:
    """
    Crawls from start_url up to max_depth levels deep.
    Returns a list of discovered unique URLs on the same domain, ordered breadth-first.

    Args:
        http_client: Authenticated HTTPClient instance
        start_url (str): The initial entry point URL
        max_depth (int): Maximum link jumps allowed from start_url
        verbose (bool): Print debug spidering progress

    Returns:
        list[str]: Discovered URLs ready for scanning
    """
    visited = set()
    to_visit = [(start_url, 0)]
    discovered_ordered = [start_url]
    discovered_set = set([start_url])

    base_netloc = urlparse(start_url).netloc

    while to_visit:
        current_url, depth = to_visit.pop(0)

        if current_url in visited:
            continue

        visited.add(current_url)

        if depth > max_depth:
            continue

        if verbose:
            print(f"  [Spider] Fetching depth={depth}: {current_url}")

        resp = http_client.get(current_url)
        if not resp or not resp.text:
            continue

        # If we were redirected to login page (session expired), warn and skip
        if 'login.php' in resp.url and current_url != resp.url:
            if verbose:
                print(f"  [Spider] Session expired! Redirected to login. Stopping crawl.")
            break

        soup = BeautifulSoup(resp.text, 'html.parser')

        for link in soup.find_all('a', href=True):
            href = link['href'].strip()

            if not href:
                continue
            if href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:'):
                continue

            # Skip dangerous state-changing URLs
            if any(term in href.lower() for term in CRAWLER_DENY_LIST):
                continue

            full_url = urljoin(current_url, href)
            parsed = urlparse(full_url)

            # Only follow links on the same domain, skip file downloads
            if parsed.netloc != base_netloc:
                continue
            if parsed.path.endswith(CRAWLER_SKIP_EXTENSIONS):
                continue

            # Normalize: strip fragment
            normalized = parsed._replace(fragment='').geturl()

            if normalized not in discovered_set:
                discovered_set.add(normalized)
                discovered_ordered.append(normalized)
                to_visit.append((normalized, depth + 1))

    return discovered_ordered
