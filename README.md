# Web_Vuln_SCANNER

Educational web vulnerability scanner for authorized security testing.

This project crawls a target web app, discovers forms and URL parameters, and checks for:
- Error-based SQL Injection (SQLi)
- Reflected Cross-Site Scripting (XSS)

It is designed for intentionally vulnerable environments such as DVWA and similar labs.

## Ethical Use

Use this scanner only on systems you own or have explicit written permission to test.
Unauthorized scanning may be illegal and unethical.

## Features

- Cookie-based authenticated scanning session
- Breadth-first crawler with depth control
- Deny-list based crawl and scan safety controls
- SQLi scanner with high-confidence DB error signatures
- XSS scanner with canary marker reflection detection
- Colored terminal report and optional text report export

## Project Structure

main_scanner.py: CLI entry point and scan orchestration
config.py: central configuration (timeouts, crawler rules, scan rules)
utils/crawler.py: authenticated spidering and URL discovery
utils/html_parser.py: form and URL parameter extraction helpers
utils/http_client.py: HTTP session, retries, and request wrappers
utils/payload_manager.py: payload loading from payload files
vulnerability_modules/sql_injection_scanner.py: SQLi checks
vulnerability_modules/xss_scanner.py: reflected XSS checks
reporting/report_generator.py: terminal and file report output
payloads/: SQLi and XSS payload wordlists

## Requirements

- Python 3.10+
- pip

Python dependencies are listed in requirements.txt:
- requests
- beautifulsoup4
- colorama

## Installation

### Windows (PowerShell)

```powershell
python -m venv venv3
.\venv3\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

Run a basic scan:

```bash
python main_scanner.py -u "http://127.0.0.1:8080/" -d 1
```

Run with authenticated cookies and save report:

```bash
python main_scanner.py -u "http://127.0.0.1:8080/" -d 2 -c "PHPSESSID=abc123; security=low" -o report.txt
```

Verbose spider and scanner output:

```bash
python main_scanner.py -u "http://127.0.0.1:8080/" -d 2 -v
```

## CLI Options

-u, --url: target URL (required)
-d, --depth: crawl depth (default 1, use 0 to disable crawling)
-c, --cookie: session cookies string (for authenticated targets)
-o, --output: save report to text file
-v, --verbose: verbose spidering and payload test output

## How Detection Works

### SQL Injection

- Tries priority SQLi payloads first, then payload file entries
- Tests both URL parameters and form inputs
- Confirms finding only when high-confidence DB error signatures are reflected

### Reflected XSS

- Uses a unique canary token in payloads
- Tests URL parameters and form inputs
- Flags a vulnerability when the canary or payload is reflected in response content

## Safety Controls in This Codebase

- Session validation before scan starts
- Stops scan when redirected to login page (session expiry)
- Skip-list for high-risk endpoints that can trigger real side effects
- Input-type whitelisting to avoid unsafe or irrelevant form fields

## Output Format

Each finding includes:
- Vulnerability type
- URL
- Parameter name
- Payload used
- Evidence snippet
- Remediation guidance

If no vulnerabilities are found, an informational report entry is generated.

## Troubleshooting

Session invalid or expired:
- Re-login in browser and copy fresh session cookie
- Re-run with updated -c cookie string

No URLs discovered:
- Increase crawl depth
- Confirm target has crawlable links and valid session

Too many false negatives:
- Ensure target is intentionally vulnerable and set to low security mode (for labs like DVWA)
- Expand payload files in payloads/

## Final Notes

This scanner is for learning and controlled lab validation.
For real-world assessments, combine this with manual testing and dedicated tools, and always follow legal authorization boundaries.
