import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime

from phishtriage.parse.limits import DEFAULT_LIMITS, ParseLimits


@dataclass(frozen=True, slots=True)
class Address:
    """Represents an email address with an optional display name."""

    display_name: str
    address: str
    domain: str


def normalize_header(value: str, limit: int) -> str:
    """Unfold, sanitize, and truncate a header value."""

    value = re.sub(r"\s+", " ", value).strip()
    return value.encode("utf-8", "surrogateescape").decode("utf-8", "replace")[:limit]


def header_text(msg: Message, name: str, limit: int) -> str | None:
    """Returns the text of a header, truncated to the specified limit."""

    try:
        value = msg[name]
        if value is None:
            return None

        return normalize_header(str(value), limit)

    except Exception:
        for header_name, raw_value in msg.raw_items():
            if header_name.casefold() == name.casefold():
                return normalize_header(str(raw_value), limit)

        return None


def header_texts(msg: Message, name: str, limit: int) -> tuple[str, ...]:
    """Returns a tuple of all values for a header, truncated to the specified limit."""

    values: list[str] = []

    for header_name, raw_value in msg.raw_items():
        if header_name.casefold() == name.casefold():
            values.append(normalize_header(str(raw_value), limit))

    return tuple(values)


def parse_addresses(
    msg: Message, name: str, limits: ParseLimits = DEFAULT_LIMITS
) -> tuple[Address, ...]:
    """Parses email addresses from a header, returning a tuple of Address objects."""

    result: list[Address] = []

    try:
        header = msg[name]
        if header is None:
            return ()

        addresses = getattr(header, "addresses", None)
        if addresses is None:
            raise ValueError(f"Header '{name}' does not have an 'addresses' attribute.")

        for addr_obj in addresses[: limits.max_addresses]:
            display_name = normalize_header(
                addr_obj.display_name or "",
                limits.max_header_value_chars,
            )
            addr = normalize_header(addr_obj.addr_spec or "", limits.max_header_value_chars).lower()

            if not addr:
                continue

            domain = addr.rpartition("@")[2] if "@" in addr else ""

            result.append(Address(display_name, addr, domain))

        return tuple(result)
    except Exception:
        result.clear()

        raw_values = [
            raw_value
            for header_name, raw_value in msg.raw_items()
            if header_name.casefold() == name.casefold()
        ]

        parsed_addresses = getaddresses(raw_values)

        for display_name, raw_addr in parsed_addresses:
            if len(result) >= limits.max_addresses:
                break

            if not raw_addr:
                continue

            display_name = normalize_header(display_name or "", limits.max_header_value_chars)
            addr = normalize_header(raw_addr or "", limits.max_header_value_chars).lower()
            domain = addr.rpartition("@")[2] if "@" in addr else ""

            result.append(Address(display_name, addr, domain))

    return tuple(result)


def parse_date(text: str | None) -> datetime | None:
    """Parses a date string into a datetime object, or returns None if parsing fails."""

    if text is None:
        return None

    try:
        dt = parsedate_to_datetime(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except Exception:
        return None


@dataclass(frozen=True, slots=True)
class ReceivedHop:
    """Represents a single hop in the Received header chain."""

    index: int
    from_host: str | None
    by_host: str | None
    ip: str | None
    timestamp: datetime | None
    raw: str


_FROM_CLAUSE_RE = re.compile(
    r"\bfrom\s+([^\s;()\[\]]+)(.*?)(?=\bby\s|;|$)",
    re.IGNORECASE | re.DOTALL,
)
_BY_RE = re.compile(r"\bby\s+([^\s;()\[\]]+)", re.IGNORECASE)
_BRACKETED_IP_RE = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]", re.IGNORECASE)


def _first_valid_ip(text: str) -> str | None:
    for candidate in _BRACKETED_IP_RE.findall(text):
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


def parse_received(value: str, index: int) -> ReceivedHop:
    """Parses a Received header value into a ReceivedHop object."""
    from_host = ip = by_host = timestamp = None

    if m := _FROM_CLAUSE_RE.search(value):
        from_host = m.group(1).lower()
        ip = _first_valid_ip(m.group(0))

    if m := _BY_RE.search(value):
        by_host = m.group(1).lower()

    _, sep, tail = value.rpartition(";")
    timestamp = parse_date(tail.strip()) if sep else None

    return ReceivedHop(
        index=index,
        from_host=from_host,
        by_host=by_host,
        ip=ip,
        timestamp=timestamp,
        raw=value,
    )


@dataclass(frozen=True, slots=True)
class HeaderInfo:
    """Represents parsed information from email headers."""

    subject: str | None
    from_: tuple[Address, ...]
    reply_to: tuple[Address, ...]
    sender: tuple[Address, ...]
    return_path: str | None
    to_count: int
    cc_count: int
    message_id: str | None
    date: datetime | None
    received: tuple[ReceivedHop, ...]
    auth_results: tuple[str, ...]
    arc_auth_results: tuple[str, ...]
    list_unsubscribe: str | None
    x_mailer: str | None


def extract_headers(msg: Message, limits: ParseLimits = DEFAULT_LIMITS) -> HeaderInfo:
    """Extracts and parses relevant headers from an email message."""

    subject = header_text(msg, "Subject", limits.max_header_value_chars)
    from_ = parse_addresses(msg, "From", limits)
    reply_to = parse_addresses(msg, "Reply-To", limits)
    sender = parse_addresses(msg, "Sender", limits)

    values = header_texts(msg, "Return-Path", limits.max_header_value_chars)
    return_path = values[0].strip("<>").lower() if values and values[0] else None

    to_count = len(parse_addresses(msg, "To", limits))
    cc_count = len(parse_addresses(msg, "Cc", limits))

    message_id = header_text(msg, "Message-ID", limits.max_header_value_chars)
    date = parse_date(header_text(msg, "Date", limits.max_header_value_chars))

    received = tuple(
        parse_received(value, index)
        for index, value in enumerate(
            header_texts(msg, "Received", limits.max_header_value_chars)[: limits.max_received_hops]
        )
    )

    auth_results = header_texts(msg, "Authentication-Results", limits.max_header_value_chars)
    arc_auth_results = header_texts(
        msg, "ARC-Authentication-Results", limits.max_header_value_chars
    )

    list_unsubscribe = header_text(msg, "List-Unsubscribe", limits.max_header_value_chars)
    x_mailer = header_text(msg, "X-Mailer", limits.max_header_value_chars)

    return HeaderInfo(
        subject=subject,
        from_=from_,
        reply_to=reply_to,
        sender=sender,
        return_path=return_path,
        to_count=to_count,
        cc_count=cc_count,
        message_id=message_id,
        date=date,
        received=received,
        auth_results=auth_results,
        arc_auth_results=arc_auth_results,
        list_unsubscribe=list_unsubscribe,
        x_mailer=x_mailer,
    )
