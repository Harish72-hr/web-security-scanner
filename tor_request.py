import socket
import requests


# ── Tor proxy configs ────────────────────────────────────────────────────────
TOR_PROXIES_BROWSER = {
    "http":  "socks5h://127.0.0.1:9150",
    "https": "socks5h://127.0.0.1:9150"
}

TOR_PROXIES_SERVICE = {
    "http":  "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050"
}

# Public DNS servers used as fallback when system DNS fails
# (happens when Tor Browser intercepts DNS or system DNS is broken)
FALLBACK_DNS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


def _resolve_hostname(hostname):
    """
    Try to resolve hostname via system DNS first.
    If that fails (getaddrinfo failed), try Google/Cloudflare DNS via socket.
    Returns resolved IP string or raises ConnectionError with a clear message.
    """
    # 1. Try system DNS
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        pass

    # 2. Try forcing DNS via known public resolvers using dnspython if available
    try:
        import dns.resolver
        for dns_server in FALLBACK_DNS:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                answer = resolver.resolve(hostname, "A")
                return str(answer[0])
            except Exception:
                continue
    except ImportError:
        pass

    # 3. Last resort — try connecting directly to 8.8.8.8 to check internet
    try:
        socket.setdefaulttimeout(5)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
    except OSError:
        raise ConnectionError(
            "No internet connection detected. "
            "Check your network or disable any VPN/firewall blocking DNS."
        )

    raise ConnectionError(
        f"DNS resolution failed for '{hostname}'. "
        "Possible causes:\n"
        "  • Tor Browser is intercepting DNS — close Tor Browser and retry\n"
        "  • Your antivirus/firewall is blocking DNS queries\n"
        "  • No internet connection\n"
        "Try running: nslookup " + hostname + " 8.8.8.8"
    )


def get_tor_proxies():
    """Try Tor Browser port 9150, fall back to system Tor port 9050."""
    for proxies, label in [
        (TOR_PROXIES_BROWSER, "9150"),
        (TOR_PROXIES_SERVICE, "9050")
    ]:
        try:
            requests.get(
                "https://check.torproject.org/api/ip",
                proxies=proxies,
                timeout=10
            )
            return proxies, label
        except Exception:
            continue
    return None, None


def tor_status():
    """
    Returns Tor connectivity info:
    { connected, port, ip, error }
    """
    proxies, port = get_tor_proxies()
    if proxies is None:
        return {
            "connected": False,
            "port": None,
            "ip": None,
            "error": "Tor is not running on port 9150 or 9050. Start Tor Browser."
        }
    try:
        r    = requests.get("https://check.torproject.org/api/ip",
                            proxies=proxies, timeout=10)
        data = r.json()
        return {
            "connected": data.get("IsTor", False),
            "port":      port,
            "ip":        data.get("IP", "Unknown"),
            "error":     None
        }
    except Exception as e:
        return {
            "connected": False,
            "port":      port,
            "ip":        None,
            "error":     str(e)
        }


def make_request(url, timeout=30):
    """
    Make an HTTP request — Tor-aware and DNS-resilient.

    .onion URLs  → always routed through Tor (socks5h = DNS inside Tor)
    Surface URLs → direct connection with DNS pre-check + clear error messages
    """
    is_onion = ".onion" in url

    if is_onion:
        # Tor handles DNS resolution internally (socks5h)
        proxies, port = get_tor_proxies()
        if proxies is None:
            raise ConnectionError(
                "Cannot reach .onion site: Tor is not running on port 9150 or 9050.\n"
                "Please start Tor Browser or install the Tor service."
            )
        try:
            response = requests.get(url, proxies=proxies, timeout=timeout)
            return response
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(
                f"Tor connection failed for {url}.\n"
                f"Make sure Tor Browser is open and fully connected.\n"
                f"Detail: {str(e)}"
            )

    else:
        # Surface web — check DNS first to give a clear error
        hostname = url.replace("https://", "").replace("http://", "").split("/")[0]

        # Pre-flight DNS check with helpful error if it fails
        try:
            _resolve_hostname(hostname)
        except ConnectionError as dns_err:
            raise ConnectionError(str(dns_err))

        # DNS resolved — now make the request
        session = requests.Session()
        session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        })

        try:
            response = session.get(
                url,
                timeout=timeout,
                allow_redirects=True
            )
            return response

        except requests.exceptions.SSLError as e:
            raise ConnectionError(
                f"SSL error connecting to {hostname}.\n"
                f"The site may have an invalid certificate.\n"
                f"Detail: {str(e)}"
            )
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(
                f"Connection refused or network error for {hostname}.\n"
                f"The site may be down or blocking automated requests.\n"
                f"Detail: {str(e)}"
            )
        except requests.exceptions.Timeout:
            raise ConnectionError(
                f"Request to {hostname} timed out after {timeout}s.\n"
                "The site may be slow or blocking requests."
            )


def get_headers(url):
    """Return response headers for a URL (Tor-aware)."""
    return make_request(url).headers


def get_response(url):
    """Return full response object for a URL (Tor-aware)."""
    return make_request(url)