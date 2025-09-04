"""
report_generator.py
-------------------
Formats and outputs scan results with style!
"""

import re
from colorama import Fore, Style, init

init(autoreset=True)


def print_report(results: list[dict], output_file: str = None) -> None:
    """Prints a vibrant report to the console and optionally saves to a file."""
    lines = []
    banner = f"{Fore.CYAN}{Style.BRIGHT}=== Web Vulnerability Scanner Report ==={Style.RESET_ALL}"
    lines.append(banner)
    
    for vuln in results:
        color = Fore.RED if vuln['found'] else Fore.GREEN
        status = "VULNERABLE! [X]" if vuln['found'] else "Safe [Ok]"
        lines.append(f"\n{color}{vuln['type']} on {vuln['url']} [{vuln['parameter']}]")
        lines.append(f"  Status: {status}")
        
        if vuln['found']:
            lines.append(f"  Payload: {vuln['payload']}")
            lines.append(f"  Evidence: {vuln['evidence']}")
            lines.append(f"  Remediation: {remediation_advice(vuln['type'])}")
            
        lines.append('-' * 60)
        
    report = '\n'.join(lines)
    print(report)
    
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(strip_ansi(report))
        print(f"{Fore.YELLOW}Report saved to {output_file}")


def remediation_advice(vuln_type: str) -> str:
    """Fetch actionable feedback given a discovered application footprint flaw."""
    if vuln_type == "SQL Injection":
        return "Use parameterized queries (prepared statements) and input validation."
    elif vuln_type == "Reflected XSS":
        return "Sanitize and encode user input before reflecting it in responses."
    else:
        return "See OWASP guidelines for remediation."


def strip_ansi(text: str) -> str:
    """Remove ANSI color codes for file output formatting readiness."""
    ansi_escape = re.compile(r'\x1b\[([0-9]+)(;[0-9]+)*m')
    return ansi_escape.sub('', text)
