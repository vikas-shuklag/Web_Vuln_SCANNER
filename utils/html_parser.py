"""
html_parser.py
--------------
Parses HTML to extract forms, input fields, and URL parameters.
Ethical Note: Only use this parser on authorized targets!
"""

from bs4 import BeautifulSoup  # Robust HTML parsing
from urllib.parse import urlparse, parse_qs

# Enhanced form detection
def hunt_forms(html):
    """Find all forms and their input fields in the HTML."""
    soup = BeautifulSoup(html, 'html.parser')
    forms = []
    for form in soup.find_all('form'):
        form_details = {
            'action': form.get('action'),
            'method': form.get('method', 'get').lower(),
            'inputs': []
        }
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_type = input_tag.get('type', 'text')
            name = input_tag.get('name')
            if name:
                form_details['inputs'].append({
                    'type': input_type,
                    'name': name,
                    'value': input_tag.get('value', '')
                })
        forms.append(form_details)
    return forms

def sniff_url_params(url):
    """Extract URL parameters as a dict."""
    parsed = urlparse(url)
    return {k: v[0] for k, v in parse_qs(parsed.query).items()} 
# Complex form field parsing
# Advanced parameter discovery techniques
# Dynamic form attribute analysis
# type hints pass 1
