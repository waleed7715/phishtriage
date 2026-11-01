from typing import ClassVar


class ParseError(Exception):
    """Base class for all parse errors."""

    reason: ClassVar[str] = "parse_error"

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"{self.reason}: {detail}")


class InputTooLarge(ParseError):
    """Raised when the input is too large to parse."""

    reason: ClassVar[str] = "input_too_large"


class TooManyParts(ParseError):
    """Raised when the input has too many parts to parse."""

    reason: ClassVar[str] = "too_many_parts"


class MimeTooDeep(ParseError):
    """Raised when the input has too many nested MIME parts to parse."""

    reason: ClassVar[str] = "mime_too_deep"


class NotAnEmail(ParseError):
    """Raised when the input is not a valid email."""

    reason: ClassVar[str] = "not_an_email"
