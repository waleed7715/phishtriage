import dataclasses
from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class ParseLimits:
    """Limits for parsing emails."""

    max_message_bytes: int = 25 * 1024 * 1024
    max_mime_depth: int = 10
    max_parts: int = 200
    max_attachment_bytes: int = 20 * 1024 * 1024
    max_archive_members: int = 1000
    max_archive_uncompressed_bytes: int = 200 * 1024 * 1024
    max_header_value_chars: int = 8192
    max_text_chars: int = 200_000
    max_urls: int = 200
    max_defects: int = 50
    max_unwrap_layers: int = 3
    max_addresses: int = 100
    max_received_hops: int = 50

    def __post_init__(self) -> None:
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)

            if type(value) is not int or value <= 0:
                raise ValueError(f"{field.name} must be a positive integer, got {value!r}")


DEFAULT_LIMITS: Final = ParseLimits()
