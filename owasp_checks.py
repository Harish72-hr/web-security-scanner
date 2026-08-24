from tor_request import get_response


def check_basic_owasp(url):
    findings = []

    try:
        response = get_response(url)
        headers  = response.headers
        body     = response.text.lower()

        # A01 – Broken Access Control
        sensitive_paths = ["/admin", "/phpmyadmin", "/.env", "/config", "/backup"]
        for path in sensitive_paths:
            if path in body:
                findings.append(
                    f"A01: Broken Access Control — sensitive path reference found: {path}"
                )

        # A02 – Cryptographic Failures
        if "Strict-Transport-Security" not in headers:
            findings.append("A02: Cryptographic Failures — Missing HSTS header")
        if url.startswith("http://") and not url.startswith("https://"):
            findings.append("A02: Cryptographic Failures — Site served over HTTP, not HTTPS")

        # A03 – Injection
        sql_errors = ["sql syntax", "mysql_fetch", "sqlite error", "database error", "ora-", "pg::"]
        for err in sql_errors:
            if err in body:
                findings.append(f"A03: Injection — SQL error pattern found: '{err}'")
                break

        # A04 – Insecure Design
        if "Content-Security-Policy" not in headers:
            findings.append("A04: Insecure Design — No Content-Security-Policy defined")

        # A05 – Security Misconfiguration
        if "X-Frame-Options" not in headers:
            findings.append("A05: Security Misconfiguration — Missing X-Frame-Options (clickjacking risk)")
        if "X-Content-Type-Options" not in headers:
            findings.append("A05: Security Misconfiguration — Missing X-Content-Type-Options")
        if "server" in headers:
            findings.append(
                f"A05: Security Misconfiguration — Server version disclosed: {headers['server']}"
            )
        if "X-Powered-By" in headers:
            findings.append(
                f"A05: Security Misconfiguration — Technology disclosed via X-Powered-By: {headers['X-Powered-By']}"
            )

        # A06 – Vulnerable and Outdated Components
        tech_headers = ["X-Powered-By", "X-Generator", "X-Drupal-Cache", "X-WordPress"]
        for h in tech_headers:
            if h in headers:
                findings.append(
                    f"A06: Outdated Components — Framework header detected: {h}: {headers[h]}"
                )

        # A07 – Auth failures
        cookies = response.cookies
        for cookie in cookies:
            if not cookie.has_nonstandard_attr("HttpOnly"):
                findings.append(
                    f"A07: Auth Failure — Cookie '{cookie.name}' missing HttpOnly flag"
                )
            if not cookie.secure:
                findings.append(
                    f"A07: Auth Failure — Cookie '{cookie.name}' missing Secure flag"
                )

        # A09 – Security Logging
        if "Referrer-Policy" not in headers:
            findings.append("A09: Security Logging Failure — Missing Referrer-Policy")

        if not findings:
            findings.append("✓ No OWASP Top 10 issues detected")

        return findings

    except Exception as e:
        return [f"OWASP Check Error: {str(e)}"]
