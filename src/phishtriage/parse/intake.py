from dataclasses import dataclass
from email import policy
from email.message import EmailMessage, MIMEPart
from email.parser import BytesParser

from phishtriage.parse.errors import (
    InputTooLarge,
    MimeTooDeep,
    NotAnEmail,
    ParseError,
    TooManyParts,
)
from phishtriage.parse.limits import DEFAULT_LIMITS, ParseLimits

REQUIRED_ANY = ("From", "Date", "Subject", "Message-ID", "Received")


@dataclass(frozen=True, slots=True)
class MimeStats:
    """Represents the state of a MIME type during parsing."""

    part_count: int
    max_depth: int
    defects: tuple[str, ...]


def load_message(
    raw: bytes, limits: ParseLimits = DEFAULT_LIMITS
) -> tuple[EmailMessage, MimeStats]:
    """Load a raw email message and return the parsed message and its MIME state."""

    if len(raw) > limits.max_message_bytes:
        raise InputTooLarge(f"{len(raw)} bytes > {limits.max_message_bytes}")

    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
        if not isinstance(message, EmailMessage):
            raise ParseError("Parser returned an unexpected type, expected EmailMessage.")
    except ParseError:
        raise
    except Exception as e:
        raise ParseError(type(e).__name__) from e

    try:
        if not any(name in message for name in REQUIRED_ANY):
            raise NotAnEmail("no From, Date, Subject, Message-ID or Received header")
    except ParseError:
        raise
    except Exception as e:
        raise ParseError(type(e).__name__) from e

    try:
        stack: list[tuple[MIMEPart, int]] = [(message, 0)]
        part_count = 0
        max_depth = 0
        defects: list[str] = []

        while stack:
            current_part, depth = stack.pop()

            part_count += 1
            max_depth = max(max_depth, depth)

            if part_count > limits.max_parts:
                raise TooManyParts(f"{part_count} parts > {limits.max_parts}.")

            if max_depth > limits.max_mime_depth:
                raise MimeTooDeep(f"MIME depth {max_depth} > {limits.max_mime_depth}.")

            for defect in current_part.defects:
                name = defect.__class__.__name__
                if name not in defects and len(defects) < limits.max_defects:
                    defects.append(name)

            if current_part.is_multipart():
                for child in current_part.iter_parts():
                    stack.append((child, depth + 1))
    except ParseError:
        raise
    except Exception as e:
        raise ParseError(type(e).__name__) from e

    mime_stats = MimeStats(part_count=part_count, max_depth=max_depth, defects=tuple(defects))
    return (message, mime_stats)
