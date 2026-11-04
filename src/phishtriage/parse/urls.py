import re
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

import idna

_SCHEMES = ("http", "https")

_PROOFPOINT_V3_REGEX = re.compile(r"^https://urldefense\.com/v3/__(.+?)__;")


def normalize_url(raw: str) -> str | None:
    url = raw.strip()

    for left, right in (("<", ">"), ('"', '"'), ("'", "'")):
        if url.startswith(left) and url.endswith(right):
            url = url[1:-1]
            break

    url = url.strip()

    try:
        parts = urlsplit(url)
    except ValueError:
        return None

    scheme = parts.scheme.lower()

    if scheme not in _SCHEMES:
        return None

    if not parts.hostname:
        return None

    hostname = parts.hostname

    if ":" in hostname:
        host = f"[{hostname}]"
    else:
        try:
            host = idna.encode(parts.hostname, uts46=True).decode("ascii")
        except UnicodeError:
            if not hostname.isascii():
                return None

            host = hostname

    try:
        port = parts.port
    except ValueError:
        return None

    if (port == 80 and scheme == "http") or (port == 443 and scheme == "https"):
        port = None

    userinfo = parts.netloc.rpartition("@")[0]

    netloc = host

    if port is not None:
        netloc = f"{netloc}:{port}"
    if userinfo:
        netloc = f"{userinfo}@{netloc}"

    return urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))


def unwrap_url(url: str, max_depth: int = 3) -> tuple[str, str | None]:
    """Remove known link-protection wrappers by decoding them offline (no network access)."""

    current = url
    outermost: str | None = None
    current_depth = 0
    embedded: str | None
    name: str

    while current_depth < max_depth:
        parts = urlsplit(current)
        host = parts.hostname or ""

        if host == "safelinks.protection.outlook.com" or host.endswith(
            ".safelinks.protection.outlook.com"
        ):
            values = parse_qs(parts.query).get("url")
            embedded = values[0] if values else None
            name = "safelinks"

        elif host == "urldefense.proofpoint.com" and parts.path.startswith("/v2/url"):
            values = parse_qs(parts.query).get("u")
            embedded = unquote(values[0].replace("-", "%").replace("_", "/")) if values else None
            name = "proofpoint_v2"

        elif (m := _PROOFPOINT_V3_REGEX.match(current)) is not None:
            embedded = m.group(1)
            if "*" in embedded:
                return (current, outermost or "proofpoint_v3_unresolved")
            name = "proofpoint_v3"

        else:
            break

        if embedded is None:
            break

        inner = normalize_url(embedded)

        if inner is None:
            break

        current = inner
        current_depth += 1

        if outermost is None:
            outermost = name

    return (current, outermost)
