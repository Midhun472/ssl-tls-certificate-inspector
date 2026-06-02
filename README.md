# SSL/TLS Certificate Inspector

A Python command-line tool that connects to websites, retrieves their
SSL/TLS certificates, and checks for security misconfigurations.

---

## Features

- Retrieves full certificate metadata (issuer, expiry, cipher, TLS version)
- Detects expired and near-expiring certificates
- Flags weak TLS versions (TLS 1.0, TLS 1.1)
- Flags weak ciphers (RC4, DES, MD5)
- Checks Subject Alternative Name (SAN) coverage
- Multi-domain scanning from a file
- Exports reports to JSON and CSV
- Colour-coded terminal output with risk levels

---

## Project Structure

ssl-tls-inspector/
├── ssl_inspector.py   # Main entry point — connection & parsing
├── checker.py         # Security validation checks
├── reporter.py        # Output formatting & file export
├── domains.txt        # Sample domain list
└── reports/           # Generated reports saved here