import json
import csv
import os
from datetime import datetime

# Terminal colors 
RED    = '\033[91m'
YELLOW = '\033[93m'
GREEN  = '\033[92m'
CYAN   = '\033[96m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

RISK_COLOR = {
    'HIGH':   RED,
    'MEDIUM': YELLOW,
    'LOW':    CYAN,
    'SAFE':   GREEN,
}

SEVERITY_COLOR = {
    'HIGH':   RED,
    'MEDIUM': YELLOW,
    'LOW':    CYAN,
}


def print_report(info, findings, risk):
    
    color = RISK_COLOR.get(risk, RESET)
    line  = '─' * 52

    print(f"\n{line}")
    print(f"  {BOLD}Certificate Report — {info['domain']}{RESET}")
    print(f"{line}")
    print(f"  Common Name   : {info['common_name']}")
    print(f"  Organisation  : {info['org'] or 'N/A'}")
    print(f"  Issuer        : {info['issuer_org']}")
    print(f"  Issued        : {info['issued_on'].strftime('%Y-%m-%d')}")
    print(f"  Expires       : {info['expires_on'].strftime('%Y-%m-%d')} ({info['days_left']} days)")
    print(f"  TLS Version   : {info['tls_version']}")
    print(f"  Cipher        : {info['cipher_name']} ({info['cipher_bits']} bits)")
    print(f"  SANs ({len(info['san_domains'])} total): {', '.join(info['san_domains'][:4])}")

    print(f"\n  {BOLD}Risk Level    : {color}{risk}{RESET}")

    if findings:
        print(f"\n  {BOLD}Issues Found:{RESET}")
        for (issue_type, severity, detail) in findings:
            sc = SEVERITY_COLOR.get(severity, RESET)
            print(f"   {sc}[{severity}]{RESET} {issue_type}")
            print(f"          {detail}")
    else:
        print(f"\n  {GREEN}✓ All security checks passed{RESET}")

    print(f"{line}\n")


def save_json(results, filename=None):
    "Save all results to a JSON file."
    os.makedirs('reports', exist_ok=True)
    if not filename:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'reports/ssl_report_{ts}.json'

    # Convert datetime objects to strings for JSON serialisation
    def serialise(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Cannot serialise {type(obj)}")

    with open(filename, 'w') as f:
        json.dump(results, f, indent=2, default=serialise)

    print(f"  JSON report saved: {filename}")
    return filename


def save_csv(results, filename=None):
    """Save a summary CSV — one row per domain."""
    os.makedirs('reports', exist_ok=True)
    if not filename:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'reports/ssl_report_{ts}.csv'

    fieldnames = ['domain', 'issuer', 'expires_on', 'days_left',
                  'tls_version', 'cipher_name', 'risk', 'issues_count']

    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                'domain':       r['info']['domain'],
                'issuer':       r['info']['issuer_org'],
                'expires_on':   r['info']['expires_on'].strftime('%Y-%m-%d'),
                'days_left':    r['info']['days_left'],
                'tls_version':  r['info']['tls_version'],
                'cipher_name':  r['info']['cipher_name'],
                'risk':         r['risk'],
                'issues_count': len(r['findings']),
            })

    print(f"  CSV report saved: {filename}")
    return filename