from tor_request import get_response


# ── Header definitions ────────────────────────────────────────────────────────
# Each entry: (header_name, weight, modern_alternative_check_fn | None)
# Weight = how much this missing header contributes to risk score (total = 100)

SECURITY_HEADERS = [
    "Content-Security-Policy",        # weight 20 — most important
    "X-Frame-Options",                # weight 15 — has modern CSP equivalent
    "Strict-Transport-Security",      # weight 20 — critical for HTTPS
    "X-Content-Type-Options",         # weight 10
    "Referrer-Policy",                # weight 10
    "Permissions-Policy",             # weight 10
    "X-XSS-Protection",              # weight 5  — deprecated but still checked
    "Cross-Origin-Opener-Policy",     # weight 10
]

HEADER_WEIGHTS = {
    "Content-Security-Policy":     20,
    "X-Frame-Options":             15,
    "Strict-Transport-Security":   20,
    "X-Content-Type-Options":      10,
    "Referrer-Policy":             10,
    "Permissions-Policy":          10,
    "X-XSS-Protection":            5,
    "Cross-Origin-Opener-Policy":  10,
}
# Total = 100


def _check_csp(raw_headers):
    """
    Returns (display_value, is_missing, note)
    Checks both enforced CSP and Report-Only mode.
    """
    csp = raw_headers.get("Content-Security-Policy", "")
    if csp:
        return csp[:120] + ("…" if len(csp) > 120 else ""), False, None

    # Check report-only variant (partial credit — policy exists but not enforced)
    csp_ro = raw_headers.get("Content-Security-Policy-Report-Only", "")
    if csp_ro:
        short = csp_ro[:100] + ("…" if len(csp_ro) > 100 else "")
        return f"Report-Only (not enforced): {short}", False, "REPORT-ONLY"

    return "Missing", True, None


def _check_xfo(raw_headers):
    """
    Returns (display_value, is_missing, note)
    X-Frame-Options is deprecated — CSP frame-ancestors is the modern replacement.
    If frame-ancestors is in CSP, this header is not truly missing.
    """
    xfo = raw_headers.get("X-Frame-Options", "")
    if xfo:
        return xfo, False, None

    # Modern replacement: CSP frame-ancestors directive
    csp = raw_headers.get("Content-Security-Policy", "")
    if "frame-ancestors" in csp:
        # Extract the frame-ancestors value for display
        parts = [p.strip() for p in csp.split(";")]
        fa = next((p for p in parts if p.startswith("frame-ancestors")), "")
        return f"Protected via CSP: {fa}", False, "VIA-CSP"

    return "Missing", True, None


def _check_hsts(raw_headers, final_url):
    """
    HSTS only applies on HTTPS. If the final URL is HTTP, it's N/A not missing.
    """
    hsts = raw_headers.get("Strict-Transport-Security", "")
    if hsts:
        return hsts, False, None

    # If site is HTTP-only, HSTS is irrelevant (not a missing header, different issue)
    if final_url.startswith("http://"):
        return "N/A (site not on HTTPS)", True, "HTTP-ONLY"

    return "Missing", True, None


def _check_xxss(raw_headers):
    """
    X-XSS-Protection is deprecated in modern browsers.
    - Value "0"       → intentionally disabled (correct modern practice)
    - Value "1"       → enabled (old behaviour, not recommended)
    - Value "1; mode=block" → old block mode
    - Absent + CSP    → handled by CSP (acceptable)
    - Absent, no CSP  → missing
    """
    xxss = raw_headers.get("X-XSS-Protection", "").strip()
    csp  = raw_headers.get("Content-Security-Policy", "")

    if xxss == "0":
        # Intentionally disabled — this is the correct modern setting
        # Not a missing header — show as DISABLED (informational, no penalty)
        return "0 (disabled — correct modern practice)", False, "DISABLED"

    if xxss in ("1", "1; mode=block"):
        # Old behaviour — still present but not recommended
        return f"{xxss} (legacy — consider removing)", False, "LEGACY"

    if xxss:
        # Some other value
        return xxss, False, None

    # Header absent entirely
    if csp:
        return "Not set (CSP handles XSS — acceptable)", False, "HANDLED-BY-CSP"

    return "Missing", True, None


def scan_headers(url):
    try:
        # Use get_response so we can read the FINAL url after redirects
        response     = get_response(url)
        raw_headers  = response.headers
        final_url    = response.url   # URL after all redirects

        redirect_note = None
        if final_url.rstrip("/") != url.rstrip("/"):
            redirect_note = f"Redirected to: {final_url}"

        # ── Per-header smart checks ───────────────────────────────────────────
        headers      = {}
        missing_map  = {}   # header -> True/False
        notes_map    = {}   # header -> extra note string

        # 1. Content-Security-Policy
        val, miss, note = _check_csp(raw_headers)
        headers["Content-Security-Policy"] = val
        missing_map["Content-Security-Policy"] = miss
        if note: notes_map["Content-Security-Policy"] = note

        # 2. X-Frame-Options
        val, miss, note = _check_xfo(raw_headers)
        headers["X-Frame-Options"] = val
        missing_map["X-Frame-Options"] = miss
        if note: notes_map["X-Frame-Options"] = note

        # 3. Strict-Transport-Security
        val, miss, note = _check_hsts(raw_headers, final_url)
        headers["Strict-Transport-Security"] = val
        missing_map["Strict-Transport-Security"] = miss
        if note: notes_map["Strict-Transport-Security"] = note

        # 4. X-Content-Type-Options
        val = raw_headers.get("X-Content-Type-Options", "Missing")
        headers["X-Content-Type-Options"] = val
        missing_map["X-Content-Type-Options"] = (val == "Missing")

        # 5. Referrer-Policy
        val = raw_headers.get("Referrer-Policy", "Missing")
        headers["Referrer-Policy"] = val
        missing_map["Referrer-Policy"] = (val == "Missing")

        # 6. Permissions-Policy
        # Also check legacy Feature-Policy header name
        val = raw_headers.get("Permissions-Policy", "") or \
              raw_headers.get("Feature-Policy", "")
        if val:
            headers["Permissions-Policy"] = val
            missing_map["Permissions-Policy"] = False
        else:
            headers["Permissions-Policy"] = "Missing"
            missing_map["Permissions-Policy"] = True

        # 7. X-XSS-Protection
        val, miss, note = _check_xxss(raw_headers)
        headers["X-XSS-Protection"] = val
        missing_map["X-XSS-Protection"] = miss
        if note: notes_map["X-XSS-Protection"] = note

        # 8. Cross-Origin-Opener-Policy
        val = raw_headers.get("Cross-Origin-Opener-Policy", "Missing")
        headers["Cross-Origin-Opener-Policy"] = val
        missing_map["Cross-Origin-Opener-Policy"] = (val == "Missing")

        # ── Risk score — weighted ─────────────────────────────────────────────
        risk_score = 0
        for header, is_missing in missing_map.items():
            if is_missing:
                risk_score += HEADER_WEIGHTS.get(header, 10)

        risk_score = min(risk_score, 100)

        # ── Risk level ────────────────────────────────────────────────────────
        if risk_score <= 20:
            risk_level = "Low"
        elif risk_score <= 55:
            risk_level = "Medium"
        else:
            risk_level = "High"

        # ── Counts ───────────────────────────────────────────────────────────
        missing_count = sum(1 for v in missing_map.values() if v)
        secure_count  = len(SECURITY_HEADERS) - missing_count

        # ── Build final result ────────────────────────────────────────────────
        headers["Risk Score"]  = f"{risk_score}/100"
        headers["Risk Level"]  = risk_level

        # Private keys for app.py (prefixed with _ so template skips them)
        headers["_secure_count"]   = secure_count
        headers["_missing_count"]  = missing_count
        headers["_total_headers"]  = len(SECURITY_HEADERS)
        headers["_final_url"]      = final_url
        headers["_redirect_note"]  = redirect_note
        headers["_notes"]          = notes_map   # per-header explanation notes

        return headers

    except ConnectionError as e:
        return {"Error": str(e)}
    except Exception as e:
        return {"Error": f"Header scan failed: {str(e)}"}