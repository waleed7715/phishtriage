from dataclasses import dataclass
from email.message import Message

from phishtriage.parse.limits import DEFAULT_LIMITS, ParseLimits


@dataclass(frozen=True, slots=True)
class BodyPart:
    """Represents a part of an email message body."""

    content_type: str
    charset: str
    text: str
    truncated: bool
    decode_errors: bool


@dataclass(frozen=True, slots=True)
class Bodies:
    """Represents the bodies of an email message."""

    plain: tuple[BodyPart, ...]
    html: tuple[BodyPart, ...]
    truncated: bool


def decode_part(part: Message, max_chars: int) -> BodyPart | None:
    """Decodes a single part of an email message body."""

    content_type = part.get_content_type()

    if content_type not in ("text/plain", "text/html"):
        return None

    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        payload = b""

    charsets = [
        part.get_content_charset(),
        "utf-8",
        "windows-1252",
    ]

    decode_errors = False
    truncated = False

    for charset in dict.fromkeys(cs for cs in charsets if cs):
        try:
            text = payload.decode(charset, errors="strict")
            break
        except Exception:
            decode_errors = True
            continue
    else:
        charset = "utf-8"
        text = payload.decode(charset, errors="replace")
        decode_errors = True

    text = text.replace("\r\n", "\n").replace("\x00", "")

    if len(text) > max_chars:
        truncated = True
        text = text[:max_chars]

    return BodyPart(
        content_type=content_type,
        charset=charset,
        text=text,
        truncated=truncated,
        decode_errors=decode_errors,
    )


def collect_bodies(msg: Message, limits: ParseLimits = DEFAULT_LIMITS) -> Bodies:
    """Collects the bodies of an email message."""

    stack: list[Message] = [msg]
    plain_parts: list[BodyPart] = []
    html_parts: list[BodyPart] = []
    remaining_chars = limits.max_text_chars
    truncated = False

    while stack:
        if remaining_chars <= 0:
            truncated = True
            break

        part = stack.pop()

        if part.get_content_disposition() == "attachment":
            continue

        if part.get_content_type() == "message/rfc822":
            continue

        payload = part.get_payload()
        if isinstance(payload, list):
            children = [child for child in payload if isinstance(child, Message)]
            stack.extend(reversed(children))
            continue

        if part.get_content_type() not in ("text/plain", "text/html"):
            continue

        body_part = decode_part(part, remaining_chars)
        if not body_part:
            continue

        if body_part.content_type == "text/plain":
            plain_parts.append(body_part)
        elif body_part.content_type == "text/html":
            html_parts.append(body_part)

        remaining_chars -= len(body_part.text)
        truncated = truncated or body_part.truncated

    return Bodies(
        plain=tuple(plain_parts),
        html=tuple(html_parts),
        truncated=truncated,
    )
