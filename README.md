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
│
├── ssl_inspector.py
│   └── Main application responsible for SSL/TLS connections,
│       certificate retrieval, and certificate parsing.
│
├── checker.py
│   └── Performs security validation checks including certificate
│       expiry, TLS version analysis, cipher strength validation,
│       and SAN verification.
│
├── reporter.py
│   └── Generates terminal output and exports scan results
│       in JSON and CSV formats.
│
├── domains.txt
│   └── Sample list of domains used for bulk scanning.
│
└── reports/
    └── Stores generated JSON and CSV security reports.
