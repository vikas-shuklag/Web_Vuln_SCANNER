"""
html_parser.py
--------------
Parses HTML DOM elements to extract forms, input fields, and URL parameters
for payload injection testing.
"""

from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urldefrag, urljoin


def hunt_forms(html: str, base_url: str = '') -> list[dict]:
    """
    Find all relevant HTML injection forms and their input parameters from a raw body.
    Correctly handles `<form action="#">` logic by defragging and normalizing based on page URL.

    Args:
        html (str): Raw string HTML document text
        base_url (str): The URL where this HTML was hosted, used for resolving relative form actions

    Returns:
        list[dict]: A structural blueprint of forms and their inputs:
            [
              {
                'action': 'http://localhost/login.php',
                'method': 'post',
                'inputs': [{'type': 'text', 'name': 'user', 'value': ''}, ...]
              }
            ]
    """
    soup = BeautifulSoup(html, 'html.parser')
    forms = []
    
    for form in soup.find_all('form'):
        raw_action = form.get('action', '') or ''

        # Resolve the action against the base URL, then strip any fragment (#...)
        # e.g. action="#" on http://localhost/sqli/ -> http://localhost/sqli/
        if base_url:
            resolved = urljoin(base_url, raw_action)
        else:
            resolved = raw_action
            
        clean_action, _ = urldefrag(resolved)  # drop the fragment

        method = form.get('method', 'get').lower()
        inputs = []

        for tag in form.find_all(['input', 'textarea', 'select']):
            name = tag.get('name')
            if not name:
                continue
            inputs.append({
                'type': tag.get('type', 'text').lower(),
                'name': name,
                'value': tag.get('value', '')
            })

        forms.append({
            'action': clean_action,
            'method': method,
            'inputs': inputs
        })
        
    return forms


def sniff_url_params(url: str) -> dict[str, str]:
    """
    Extract URL query parameters as a mutable flattened dict.
    
    Args:
        url (str): HTTP URL to parse (e.g. `http://exam.com/?user=1`)
        
    Returns:
        dict[str, str]: Parameter keys mapped to string values (e.g. `{'user': '1'}`)
    """
    parsed = urlparse(url)
    return {k: v[0] for k, v in parse_qs(parsed.query).items()}
