import ssl
import socket
from datetime import datetime, timezone


def check_ssl(hostname):
    """
    Full SSL/TLS certificate analysis for a hostname.
    Returns a structured dict with all certificate details.
    Skips gracefully for .onion sites (no SSL via Tor).
    """

    # .onion sites don't have standard SSL certs
    if ".onion" in hostname:
        return {
            "supported": False,
            "reason": "SSL/TLS analysis not applicable for .onion hidden services",
            "error": None
        }

    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=10),
            server_hostname=hostname
        )
        cert = conn.getpeercert()
        cipher = conn.cipher()       # (name, protocol, bits)
        tls_version = conn.version() # e.g. "TLSv1.3"
        conn.close()

        # ── Parse subject ──
        subject_dict = {}
        for field in cert.get("subject", []):
            for key, val in field:
                subject_dict[key] = val

        # ── Parse issuer ──
        issuer_dict = {}
        for field in cert.get("issuer", []):
            for key, val in field:
                issuer_dict[key] = val

        # ── Parse dates ──
        fmt = "%b %d %H:%M:%S %Y %Z"
        not_before_str = cert.get("notBefore", "")
        not_after_str  = cert.get("notAfter",  "")

        not_before = datetime.strptime(not_before_str, fmt).replace(tzinfo=timezone.utc)
        not_after  = datetime.strptime(not_after_str,  fmt).replace(tzinfo=timezone.utc)
        now        = datetime.now(timezone.utc)

        days_remaining = (not_after - now).days
        is_expired     = days_remaining < 0
        is_expiring_soon = 0 <= days_remaining <= 30

        # ── SAN (Subject Alternative Names) ──
        san_list = []
        for field_type, value in cert.get("subjectAltName", []):
            if field_type == "DNS":
                san_list.append(value)

        # ── Self-signed check ──
        is_self_signed = (
            subject_dict.get("commonName") == issuer_dict.get("commonName")
            and subject_dict.get("organizationName") == issuer_dict.get("organizationName")
        )

        # ── Cipher strength rating ──
        bits = cipher[2] if cipher else 0
        if bits >= 256:
            cipher_rating = "Strong"
        elif bits >= 128:
            cipher_rating = "Adequate"
        else:
            cipher_rating = "Weak"

        # ── Overall SSL grade ──
        issues = []
        if is_expired:
            issues.append("Certificate is expired")
        if is_expiring_soon:
            issues.append(f"Certificate expires in {days_remaining} day(s)")
        if is_self_signed:
            issues.append("Self-signed certificate (not trusted by browsers)")
        if cipher_rating == "Weak":
            issues.append(f"Weak cipher ({bits} bits)")
        if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
            issues.append(f"Outdated protocol: {tls_version}")

        if not issues:
            grade = "A"
        elif len(issues) == 1 and is_expiring_soon:
            grade = "B"
        elif is_expired or is_self_signed:
            grade = "F"
        else:
            grade = "C"

        return {
            "supported":        True,
            "error":            None,

            # Subject
            "common_name":      subject_dict.get("commonName",       "Unknown"),
            "organization":     subject_dict.get("organizationName", "Unknown"),
            "country":          subject_dict.get("countryName",      "Unknown"),

            # Issuer
            "issuer_cn":        issuer_dict.get("commonName",        "Unknown"),
            "issuer_org":       issuer_dict.get("organizationName",  "Unknown"),
            "is_self_signed":   is_self_signed,

            # Validity
            "valid_from":       not_before.strftime("%Y-%m-%d"),
            "valid_until":      not_after.strftime("%Y-%m-%d"),
            "days_remaining":   days_remaining,
            "is_expired":       is_expired,
            "is_expiring_soon": is_expiring_soon,

            # Protocol & cipher
            "tls_version":      tls_version,
            "cipher_name":      cipher[0] if cipher else "Unknown",
            "cipher_bits":      bits,
            "cipher_rating":    cipher_rating,

            # SANs
            "san_domains":      san_list,
            "san_count":        len(san_list),

            # Summary
            "grade":            grade,
            "issues":           issues,
        }

    except ssl.SSLCertVerificationError as e:
        return {
            "supported": True,
            "error": f"SSL verification failed: {str(e)}",
            "grade": "F",
            "issues": ["Certificate verification failed — possibly self-signed or expired"]
        }
    except ssl.SSLError as e:
        return {
            "supported": True,
            "error": f"SSL error: {str(e)}",
            "grade": "F",
            "issues": [str(e)]
        }
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {
            "supported": False,
            "error": f"Could not connect to port 443: {str(e)}",
            "grade": None,
            "issues": []
        }
    except Exception as e:
        return {
            "supported": False,
            "error": f"SSL scan error: {str(e)}",
            "grade": None,
            "issues": []
        }
