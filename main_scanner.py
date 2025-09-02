"""
main_scanner.py
---------------
Orchestrates the scanning process: setup -> crawl -> parse forms -> inject -> report.
Ethical Note: Only scan authorized, intentionally vulnerable targets!
"""

import argparse
from colorama import Fore, Style, init

from config import SKIP_SCAN_PATTERNS
from utils.http_client import HTTPClient
from utils.html_parser import hunt_forms
from utils.crawler import crawl
from vulnerability_modules import sql_injection_scanner, xss_scanner
from reporting.report_generator import print_report

init(autoreset=True)


def parse_cookies(cookie_str: str) -> dict[str, str]:
    """Parse a cookie string like 'key=val; key2=val2' into a dict."""
    cookie_dict = {}
    for item in cookie_str.split(';'):
        item = item.strip()
        if '=' in item:
            k, v = item.split('=', 1)
            cookie_dict[k.strip()] = v.strip()
    return cookie_dict


def check_session(http_client: HTTPClient, url: str) -> bool:
    """
    Check if the session is alive by requesting the target URL and verifying
    we are NOT redirected to the login page.
    Returns True if the session is valid, False otherwise.
    """
    resp = http_client.get(url)
    if not resp:
        return False
    # DVWA redirects to login.php when session is expired
    if 'login.php' in resp.url:
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Web Application Vulnerability Scanner (Educational Use Only!)"
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-d', '--depth', type=int, default=1, help='Crawl depth (default: 1). Use 0 to skip crawling.')
    parser.add_argument('-c', '--cookie', help='Session cookies: "key1=val1; key2=val2"')
    parser.add_argument('-o', '--output', help='Output file for the report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show verbose spider output')
    args = parser.parse_args()

    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*55}")
    print(f"  Web Application Vulnerability Scanner")
    print(f"{'='*55}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  Target : {args.url}")
    print(f"  Depth  : {args.depth}")

    # Parse and attach cookies
    cookie_dict = {}
    if args.cookie:
        cookie_dict = parse_cookies(args.cookie)
        keys = list(cookie_dict.keys())
        print(f"  Cookies: {keys}")
    print(f"{Fore.CYAN}{'='*55}{Style.RESET_ALL}\n")

    # Build the HTTP client (all requests go through this single authenticated session)
    http_client = HTTPClient(args.url, cookies=cookie_dict if cookie_dict else None)

    # --- Session Validation ---
    print(f"{Fore.BLUE}[*] Validating session...")
    if not check_session(http_client, args.url):
        print(f"{Fore.RED}[!] SESSION EXPIRED or INVALID!")
        print(f"{Fore.RED}    Your PHPSESSID cookie is no longer valid.")
        print(f"{Fore.YELLOW}    -> Log in to DVWA in your browser, copy your new PHPSESSID from")
        print(f"{Fore.YELLOW}       DevTools (F12 -> Application -> Cookies) and re-run the scanner.")
        return
    print(f"{Fore.GREEN}[+] Session is valid! Proceeding...\n")

    # --- Crawling Phase ---
    if args.depth > 0:
        print(f"{Fore.BLUE}[*] Spidering target up to depth {args.depth}...")
        urls_to_scan = crawl(http_client, args.url, max_depth=args.depth, verbose=args.verbose)
        print(f"{Fore.GREEN}[+] Discovered {len(urls_to_scan)} unique URL(s) to test.\n")
    else:
        urls_to_scan = [args.url]
        print(f"{Fore.YELLOW}[*] Crawling disabled (-d 0). Scanning single URL only.\n")

    # --- Scanning Phase ---
    all_results = []

    for idx, current_url in enumerate(urls_to_scan, 1):
        print(f"{Style.BRIGHT}{Fore.MAGENTA}[{idx}/{len(urls_to_scan)}] Scanning: {current_url}{Style.RESET_ALL}")

        resp = http_client.get(current_url)
        if not resp:
            print(f"{Fore.RED}  [!] Failed to fetch URL.")
            continue
        if resp.status_code != 200:
            print(f"{Fore.YELLOW}  [!] Non-200 response ({resp.status_code}), skipping.")
            continue
        if 'login.php' in resp.url:
            print(f"{Fore.RED}  [!] Session expired mid-scan. Stopping.")
            break

        # Skip pages that cause real server-side effects when injected
        if any(p in current_url for p in SKIP_SCAN_PATTERNS):
            print(f"{Fore.YELLOW}  [~] Skipping form testing (command-exec / file-upload page — would cause real server side effects)")
            print()
            continue

        # Parse forms from the page
        forms = hunt_forms(resp.text, base_url=current_url)
        print(f"{Fore.BLUE}  [*] Found {len(forms)} form(s). Testing inputs...")

        # Scan for SQL Injection
        sqli_results = sql_injection_scanner.sniff_vuln(http_client, current_url, forms, debug=args.verbose)
        if sqli_results:
            print(f"{Fore.RED}  [!] SQL Injection FOUND!")
            all_results.extend(sqli_results)
        else:
            print(f"{Fore.GREEN}  [+] No SQL Injection found.")

        # Scan for XSS
        xss_results = xss_scanner.sniff_vuln(http_client, current_url, forms, debug=args.verbose)
        if xss_results:
            print(f"{Fore.RED}  [!] Reflected XSS FOUND!")
            all_results.extend(xss_results)
        else:
            print(f"{Fore.GREEN}  [+] No Reflected XSS found.")

        print()

    # --- Report Phase ---
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*55}")
    print(f"  FINAL REPORT")
    print(f"{'='*55}{Style.RESET_ALL}")

    if not all_results:
        all_results = [{
            'type': 'Info',
            'url': args.url,
            'parameter': '-',
            'payload': '-',
            'evidence': 'No vulnerabilities found on any discovered pages.',
            'found': False
        }]

    print_report(all_results, output_file=args.output)


if __name__ == '__main__':
    main()
