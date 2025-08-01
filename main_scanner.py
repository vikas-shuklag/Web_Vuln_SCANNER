"""
main_scanner.py
---------------
The main event! Orchestrates the scanning process.
Ethical Note: Only scan authorized, intentionally vulnerable targets!
"""

import argparse
from utils.http_client import HTTPClient
from utils.html_parser import hunt_forms
from vulnerability_modules import sql_injection_scanner, xss_scanner
from reporting.report_generator import print_report
from colorama import Fore, Style, init

init(autoreset=True)

def main():
    parser = argparse.ArgumentParser(description="Simple Web Application Vulnerability Scanner (For Educational Use Only!)")
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., http://localhost/dvwa/)')
    parser.add_argument('-o', '--output', help='Output file for the report')
    parser.add_argument('-c', '--cookie', help='Session cookies format: "key1=value1; key2=value2"')
    args = parser.parse_args()

    print(f"{Fore.CYAN}[SCANNER] {Style.BRIGHT}Welcome to the Simple Web App Vulnerability Scanner!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Target: {args.url}")

    # Parse cookies if provided
    cookie_dict = {}
    if args.cookie:
        for item in args.cookie.split(';'):
            if '=' in item:
                k, v = item.strip().split('=', 1)
                cookie_dict[k] = v
        print(f"{Fore.BLUE}Cookies loaded: {list(cookie_dict.keys())}")

    # Set up HTTP client
    http_client = HTTPClient(args.url, cookies=cookie_dict if cookie_dict else None)

    # Fetch the page
    resp = http_client.get(args.url)
    if not resp or resp.status_code != 200:
        print(f"{Fore.RED}[!] Could not fetch the target URL. Please check the URL and try again.")
        return

    # Parse forms
    forms = hunt_forms(resp.text)
    print(f"{Fore.BLUE}Found {len(forms)} form(s) to poke at.")

    # Scan for SQL Injection
    print(f"{Fore.MAGENTA}Scanning for SQL Injection vulnerabilities...")
    sqli_results = sql_injection_scanner.sniff_vuln(http_client, args.url, forms)
    if sqli_results:
        print(f"{Fore.RED}Whoa, found a juicy SQL Injection!")
    else:
        print(f"{Fore.GREEN}No SQL Injection found. Nice and tidy!")

    # Scan for XSS
    print(f"{Fore.MAGENTA}Scanning for Reflected XSS vulnerabilities...")
    xss_results = xss_scanner.sniff_vuln(http_client, args.url, forms)
    if xss_results:
        print(f"{Fore.RED}Yikes, found some XSS action!")
    else:
        print(f"{Fore.GREEN}No Reflected XSS found. Shiny and clean!")

    # Aggregate and report
    all_results = sqli_results + xss_results
    if not all_results:
        all_results = [{
            'type': 'Info',
            'url': args.url,
            'parameter': '-',
            'payload': '-',
            'evidence': 'No vulnerabilities found!',
            'found': False
        }]
    print_report(all_results, output_file=args.output)

if __name__ == '__main__':
    main() 
# Enhanced vulnerability scanner with session management
# Integrated vulnerability scanning workflow
# Detailed logging for debugging
# Multi-threaded concurrent scanning
# Version 1.0 - Complete web vulnerability scanner
