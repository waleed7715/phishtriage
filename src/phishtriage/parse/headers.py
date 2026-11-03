import re
from dataclasses import dataclass
from email.message import Message
from email.utils import getaddresses

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

        addresses = header.addresses

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
