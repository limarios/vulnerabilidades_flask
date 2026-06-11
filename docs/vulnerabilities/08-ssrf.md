# 08 — Server-Side Request Forgery (SSRF)

## Overview

| | |
|---|---|
| **OWASP** | A10:2021 — Server-Side Request Forgery |
| **CWE** | [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html) |
| **Red Team slug** | `ssrf` |
| **Vulnerable route** | `GET /vulnerable/fetch?url=http://example.com` |
| **Secure route** | `GET /secure/fetch?url=http://example.com` |

SSRF tricks the server into making HTTP requests to a destination the attacker chooses. Because the request originates *from* the server, it bypasses network perimeter controls and reaches internal-only resources: cloud metadata endpoints, localhost admin ports, and internal services.

## The Vulnerability

`src/lab/vulnerable/ssrf.py` fetches whatever URL the user supplies:

```python
@bp.route("/fetch")
def fetch():
    url = request.args.get("url", "http://example.com")
    # VULNERABLE: no scheme allowlist, no IP filtering. Fetches anything.
    resp = requests.get(url, timeout=3)
    return jsonify(url=url, status=resp.status_code, body=resp.text[:2000])
```

There is no restriction on scheme or destination, so `file://`, `http://127.0.0.1`, and the cloud metadata IP are all reachable.

## Exploit (Red Team)

The canonical target is the cloud instance metadata service at `169.254.169.254`, which on misconfigured cloud hosts hands out IAM credentials:

```
/vulnerable/fetch?url=http://169.254.169.254/latest/meta-data/
/vulnerable/fetch?url=http://127.0.0.1:5000/secure/account/1
```

```bash
curl "http://127.0.0.1:5000/vulnerable/fetch?url=http://169.254.169.254/latest/meta-data/"
```

CLI (`src/red_team/attacks.py::ssrf`):

```bash
python -m red_team ssrf --target http://127.0.0.1:5000
```

The attack points `url` at `169.254.169.254` and shows the vulnerable endpoint attempting the internal fetch while the secure endpoint refuses it.

## The Fix (Blue Team)

`src/lab/secure/ssrf.py` enforces a scheme allowlist and resolves the host to verify it is public:

```python
_ALLOWED_SCHEMES = {"http", "https"}

def _is_public_host(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True

@bp.route("/fetch")
def fetch():
    url = request.args.get("url", "http://example.com")
    parsed = urlparse(url)

    if parsed.scheme not in _ALLOWED_SCHEMES:
        return jsonify(error="Only http/https URLs are allowed"), 400
    if not parsed.hostname or not _is_public_host(parsed.hostname):
        return jsonify(error="Refusing to fetch a non-public address"), 400

    resp = requests.get(url, timeout=3, allow_redirects=False)
    return jsonify(status=resp.status_code, body=resp.text[:2000])
```

**Why it works:**
- The scheme allowlist blocks `file://`, `gopher://`, `dict://` and other dangerous protocols.
- `socket.getaddrinfo` resolves the hostname to its actual IP(s), and each is rejected if it falls in a private, loopback, link-local, reserved, or multicast range. This blocks `127.0.0.1`, the RFC1918 space, and crucially `169.254.169.254` (link-local — the metadata endpoint). Resolving *before* checking defeats hostnames that point at internal IPs (a DNS-rebinding-style evasion).
- `allow_redirects=False` prevents a public URL from bouncing the request to an internal one via a 3xx redirect.

## Detection (Blue Team)

`src/lab/blue_team/detection.py` `ssrf` signatures:

```python
"ssrf": [
    re.compile(r"(169\.254\.169\.254|metadata\.google|127\.0\.0\.1|localhost)", re.I),
    re.compile(r"\bfile://", re.I),
],
```

The metadata-IP payload matches the first pattern; `file://` schemes match the second. Note this is signature-based and therefore incomplete — an attacker can use an alternate IP encoding or a rebinding hostname; the resolve-then-validate logic in the fix is what actually stops those.

## References

- [OWASP A10:2021 — Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [CWE-918](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
