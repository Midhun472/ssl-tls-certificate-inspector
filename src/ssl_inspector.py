import ssl
import socket
import sys
import argparse
from datetime import datetime

from checker import run_all_checks
from reporter import print_report, save_json, save_csv


def get_certificate(domain, port=443, timeout=10):
    # Create SSL context
    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()
                tls_version = tls_sock.version()

        return cert, cipher, tls_version

    except ssl.SSLCertVerificationError as e:
        return None, None, f"SSL_ERROR: {e}"

    except socket.timeout:
        return None, None, "TIMEOUT"

    except socket.gaierror:
        return None, None, "DNS_FAILED"

    except ConnectionRefusedError:
        return None, None, "CONNECTION_REFUSED"

    except Exception as e:
        return None, None, f"ERROR: {e}"


def parse_certificate(cert, cipher, tls_version, domain):
    if not cert:
        return None

    subject = dict(item[0] for item in cert.get("subject", []))
    issuer = dict(item[0] for item in cert.get("issuer", []))

    expiry = datetime.strptime(
        cert["notAfter"],
        "%b %d %H:%M:%S %Y %Z"
    )

    issued = datetime.strptime(
        cert["notBefore"],
        "%b %d %H:%M:%S %Y %Z"
    )

    # Collect SAN domains
    san = []

    for cert_type, value in cert.get("subjectAltName", []):
        if cert_type == "DNS":
            san.append(value)

    # Days remaining before expiretion
    days_left = (expiry - datetime.utcnow()).days

    wildcard = ""
    if "." in domain:
        wildcard = "*." + ".".join(domain.split(".")[1:])

    return {
        "domain": domain,
        "common_name": subject.get("commonName", "N/A"),
        "org": subject.get("organizationName", "N/A"),
        "issuer_org": issuer.get("organizationName", "N/A"),
        "issuer_cn": issuer.get("commonName", "N/A"),
        "issued_on": issued,
        "expires_on": expiry,
        "days_left": days_left,
        "tls_version": tls_version,
        "cipher_name": cipher[0] if cipher else "N/A",
        "cipher_bits": cipher[2] if cipher else 0,
        "san_domains": san,
        "san_covers": domain in san or wildcard in san
    }


def scan_domain(domain):
    print(f"Scanning {domain}...", end=" ", flush=True)

    cert, cipher, tls_version = get_certificate(domain)

    if cert is None:
        print("Failed")

        return {
            "domain": domain,
            "error": tls_version,
            "risk": "ERROR",
            "findings": []
        }

    info = parse_certificate(cert, cipher, tls_version, domain)

    findings, risk = run_all_checks(info)

    print(f"Completed ({risk})")

    return {
        "domain": domain,
        "info": info,
        "findings": findings,
        "risk": risk
    }


def main():
    parser = argparse.ArgumentParser(
        description="SSL/TLS Certificate Inspector"
    )

    parser.add_argument(
        "domains",
        nargs="*",
        help="Domains to scan"
    )

    parser.add_argument(
        "-f",
        "--file",
        help="Read domains from a file"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Export JSON report"
    )

    parser.add_argument(
        "--csv",
        action="store_true",
        help="Export CSV report"
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Hide detailed output"
    )

    args = parser.parse_args()

    domains = list(args.domains)

    if args.file:
        with open(args.file, "r") as file:
            for line in file:
                line = line.strip()

                if line and not line.startswith("#"):
                    domains.append(line)

    if not domains:
        parser.print_help()
        sys.exit(1)

    # Remove duplicates
    domains = list(dict.fromkeys(domains))

    print("\n" + "=" * 60)
    print(f"SSL Inspector - Scanning {len(domains)} domain(s)")
    print("=" * 60)

    results = []

    for domain in domains:
        results.append(scan_domain(domain))

    if not args.quiet:
        for result in results:

            if "info" in result:
                print_report(
                    result["info"],
                    result["findings"],
                    result["risk"]
                )
            else:
                print(
                    f"\nERROR: {result['domain']} "
                    f"({result['error']})\n"
                )

    print("\n" + "=" * 60)
    print(f"{'Domain':<30} {'Risk':<10} {'Days Left'}")
    print("-" * 60)

    for result in results:
        if "info" in result:
            print(
                f"{result['domain']:<30} "
                f"{result['risk']:<10} "
                f"{result['info']['days_left']}"
            )
        else:
            print(f"{result['domain']:<30} ERROR")

    print("=" * 60)

    if args.json:
        save_json(results)

    if args.csv:
        save_csv(results)


if __name__ == "__main__":
    main()