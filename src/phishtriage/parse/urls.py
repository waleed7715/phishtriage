import re
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

import idna
from bs4 import BeautifulSoup, Tag

from phishtriage.parse.limits import DEFAULT_LIMITS, ParseLimits

_SCHEMES = ("http", "https")

_PROOFPOINT_V3_REGEX = re.compile(r"^https://urldefense\.com/v3/__(.+?)__;")

_URL_FROM_TEXT_REGEX = re.compile(r"""https?://[^\s<>"'{}|\\^\[\]]+""", re.IGNORECASE)


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


@dataclass(frozen=True, slots=True)
class ExtractedUrl:
    url: str
    original: str
    source: str
    anchor_text: str | None
    wrapper: str | None
    host: str
    has_userinfo: bool


def urls_from_text(text: str) -> list[str]:
    """Extract URLs from text using a regex pattern."""

    matches = re.findall(_URL_FROM_TEXT_REGEX, text)
    urls = []

    for url in matches:
        current = url

        while True:
            stripped = current.rstrip(".,;:!?]}'\"")

            if stripped.endswith(")") and stripped.count("(") < stripped.count(")"):
                stripped = stripped[:-1]

            if stripped == current:
                break

            current = stripped

        if current:
            urls.append(current)

    return urls


def urls_from_html(html: str) -> list[tuple[str, str, str | None]]:
    """Extract URLs from HTML content using BeautifulSoup."""

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return []

    urls: list[tuple[str, str, str | None]] = []

    items = soup.find_all(True)

    for item in items:
        if not isinstance(item, Tag):
            continue

        if item.name in ("a", "area"):
            attr = item.get("href")
            if not isinstance(attr, str):
                continue

            src = "html_href"

            anchor_text = (
                " ".join(item.get_text(strip=True).split())[:200] or "" if item.name == "a" else ""
            )

            urls.append((attr, src, anchor_text))
            continue

        if item.name in ("img", "iframe", "frame", "embed", "source"):
            attr = item.get("src")

            if not isinstance(attr, str):
                continue

            src = "html_src"

            urls.append((attr, src, None))
            continue

        if item.name == "form":
            attr = item.get("action")

            if not isinstance(attr, str):
                continue

            src = "html_form"

            urls.append((attr, src, None))
            continue

        if item.name == "meta" and str(item.get("http-equiv", "")).lower() == "refresh":
            content = str(item.get("content", ""))
            match = re.search(r"url=(.+)", content, re.IGNORECASE)

            attr = match.group(1).strip().strip("\"'").strip() if match else None

            if not isinstance(attr, str):
                continue

            src = "html_meta_refresh"

            urls.append((attr, src, None))
            continue

    return urls


def extract_urls(
    plain: Sequence[str], html: Sequence[str], limits: ParseLimits = DEFAULT_LIMITS
) -> tuple[ExtractedUrl, ...]:
    """Collect, normalize, unwrap and deduplicate URLs from HTML and plain-text bodies.

    HTML is processed first, so a link that also appears in the text keeps its
    anchor text. Stops once limits.max_urls unique URLs have been found.
    """

    candidates: list[tuple[str, str, str | None]] = []
    for body in html:
        candidates.extend(urls_from_html(body))
    for body in plain:
        candidates.extend((raw, "text", None) for raw in urls_from_text(body))

    extracted: list[ExtractedUrl] = []
    seen: set[str] = set()

    for raw, source, anchor_text in candidates:
        if len(extracted) >= limits.max_urls:
            break

        normalized = normalize_url(raw)
        if normalized is None:
            continue

        final, wrapper = unwrap_url(normalized)
        if final in seen:
            continue
        seen.add(final)

        parts = urlsplit(final)
        extracted.append(
            ExtractedUrl(
                url=final,
                original=normalized,
                source=source,
                anchor_text=anchor_text,
                wrapper=wrapper,
                host=parts.hostname or "",
                has_userinfo="@" in parts.netloc,
            )
        )

    return tuple(extracted)
