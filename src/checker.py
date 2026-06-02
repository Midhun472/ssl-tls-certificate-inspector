from datetime import datetime

# Old TLS versions that are no longer considered secure
WEAK_TLS_VERSIONS = {
    "SSLv2",
    "SSLv3",
    "TLSv1",
    "TLSv1.1"
}

# Weak or outdated encryption algorithms
WEAK_CIPHER_KEYWORDS = [
    "RC4",
    "DES",
    "MD5",
    "NULL",
    "EXPORT",
    "ANON",
    "ADH",
    "AECDH"
]

# Cipher suites that do not support forward secrecy
NO_PFS_KEYWORDS = [
    "RSA_WITH",
    "DH_",
    "ECDH_RSA",
    "ECDH_ECDSA"
]


def check_expiry(info):
    # Check certificate expiration date
    findings = []
    days = info["days_left"]

    if days < 0:
        findings.append((
            "EXPIRED",
            "HIGH",
            f'Certificate expired {abs(days)} days ago'
        ))

    elif days <= 7:
        findings.append((
            "CRITICAL_EXPIRY",
            "HIGH",
            f'Certificate expires in {days} days'
        ))

    elif days <= 30:
        findings.append((
            "NEAR_EXPIRY",
            "MEDIUM",
            f'Certificate expires in {days} days'
        ))

    elif days <= 90:
        findings.append((
            "EXPIRY_WARNING",
            "LOW",
            f'Certificate expires in {days} days'
        ))

    return findings


def check_tls_version(info):
    # Check TLS version being used
    findings = []
    version = info["tls_version"]

    if version in WEAK_TLS_VERSIONS:
        findings.append((
            "WEAK_TLS",
            "HIGH",
            f"{version} is outdated and should not be used"
        ))

    elif version == "TLSv1.2":
        findings.append((
            "LEGACY_TLS",
            "LOW",
            "TLS 1.2 is supported, but TLS 1.3 is preferred"
        ))

    return findings


def check_cipher(info):
    # Check cipher strength
    findings = []

    cipher = info["cipher_name"].upper()
    bits = info["cipher_bits"]

    for weak in WEAK_CIPHER_KEYWORDS:
        if weak in cipher:
            findings.append((
                "WEAK_CIPHER",
                "HIGH",
                f'Weak cipher detected: {info["cipher_name"]}'
            ))
            break

    if bits and bits < 128:
        findings.append((
            "SHORT_KEY",
            "HIGH",
            f"Key length ({bits} bits) is considered weak"
        ))

    return findings


def check_forward_secrecy(info):
    # Check for forward secrecy support
    findings = []

    cipher = info["cipher_name"].upper()

    for keyword in NO_PFS_KEYWORDS:
        if keyword in cipher:
            findings.append((
                "NO_FORWARD_SECRECY",
                "MEDIUM",
                "Cipher suite does not support forward secrecy"
            ))
            break

    return findings


def check_san_coverage(info):
    # Verify the domain exists in SAN entries
    findings = []

    if not info["san_covers"]:
        findings.append((
            "SAN_MISMATCH",
            "HIGH",
            f'{info["domain"]} is not covered by the certificate'
        ))

    return findings


def check_cert_age(info):
    # Flag certificates issued very recently
    findings = []

    age_hours = (
        datetime.utcnow() - info["issued_on"]
    ).total_seconds() / 3600

    if age_hours < 1:
        findings.append((
            "VERY_NEW_CERT",
            "LOW",
            "Certificate was issued very recently"
        ))

    return findings


def run_all_checks(info):
    # Run every security check
    findings = []

    findings.extend(check_expiry(info))
    findings.extend(check_tls_version(info))
    findings.extend(check_cipher(info))
    findings.extend(check_forward_secrecy(info))
    findings.extend(check_san_coverage(info))
    findings.extend(check_cert_age(info))

    severities = [item[1] for item in findings]

    if "HIGH" in severities:
        risk = "HIGH"

    elif "MEDIUM" in severities:
        risk = "MEDIUM"

    elif "LOW" in severities:
        risk = "LOW"

    else:
        risk = "SAFE"

    return findings, risk