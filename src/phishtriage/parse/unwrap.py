from dataclasses import dataclass
from email.message import EmailMessage

from phishtriage.parse.errors import NotAnEmail
from phishtriage.parse.headers import header_text
from phishtriage.parse.intake import load_message
from phishtriage.parse.limits import DEFAULT_LIMITS, ParseLimits


@dataclass(frozen=True, slots=True)
class UnwrapResult:
    """Represents the result of unwrapping an email message."""

    message: EmailMessage
    layers: int
    reporter: str | None
    wrapper_subject: str | None
    candidates: int


def unwrap_report(message: EmailMessage, limits: ParseLimits = DEFAULT_LIMITS) -> UnwrapResult:
    """Unwraps a message and returns the result of the unwrapping process."""

    current = message
    layers = 0
    candidates = 0

    while layers < limits.max_unwrap_layers:
        found: list[EmailMessage] = []

        if current.is_multipart():
            for child in current.iter_parts():
                filename = child.get_filename()

                if child.get_content_type() == "message/rfc822":
                    payload_list = child.get_payload()

                    if (
                        isinstance(payload_list, list)
                        and payload_list
                        and isinstance(payload_list[0], EmailMessage)
                    ):
                        found.append(payload_list[0])

                elif filename and filename.lower().endswith(".eml"):
                    payload = child.get_payload(decode=True)

                    if not isinstance(payload, bytes):
                        raise NotAnEmail("Expected bytes payload in .eml attachment.")

                    found.append(load_message(payload, limits=limits)[0])

        if layers == 0:
            candidates = len(found)
        if len(found) != 1:
            break
        current = found[0]
        layers += 1

    reporter: str | None = None
    wrapper_subject: str | None = None

    if layers > 0:
        reporter = header_text(message, "From", limits.max_header_value_chars)
        wrapper_subject = header_text(message, "Subject", limits.max_header_value_chars)

    return UnwrapResult(
        message=current,
        layers=layers,
        reporter=reporter,
        wrapper_subject=wrapper_subject,
        candidates=candidates,
    )
