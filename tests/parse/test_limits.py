import dataclasses
from typing import Any

import pytest

from phishtriage.parse.limits import DEFAULT_LIMITS, ParseLimits

ALL_FIELDS = [
    "max_message_bytes",
    "max_mime_depth",
    "max_parts",
    "max_attachment_bytes",
    "max_archive_members",
    "max_archive_uncompressed_bytes",
    "max_header_value_chars",
    "max_text_chars",
    "max_urls",
    "max_defects",
    "max_unwrap_layers",
    "max_addresses",
]

BAD_VALUES: list[Any] = [0, -1, True, False, "10", None, 3.14]


def test_default_limits() -> None:
    limits = ParseLimits()
    assert limits.max_message_bytes == 25 * 1024 * 1024
    assert limits.max_mime_depth == 10
    assert limits.max_parts == 200
    assert limits.max_attachment_bytes == 20 * 1024 * 1024
    assert limits.max_archive_members == 1000
    assert limits.max_archive_uncompressed_bytes == 200 * 1024 * 1024
    assert limits.max_header_value_chars == 8192
    assert limits.max_text_chars == 200_000
    assert limits.max_urls == 200
    assert limits.max_defects == 50
    assert limits.max_unwrap_layers == 3
    assert limits.max_addresses == 100
    assert limits.max_received_hops == 50


def test_override_field() -> None:
    limits = ParseLimits(max_parts=3)
    assert limits.max_parts == 3
    assert limits.max_attachment_bytes == 20 * 1024 * 1024


def test_frozen() -> None:
    limits = ParseLimits()
    with pytest.raises(dataclasses.FrozenInstanceError):
        limits.max_parts = 10  # type: ignore[misc]


def test_slots() -> None:
    limits = ParseLimits()
    assert not hasattr(limits, "__dict__")


@pytest.mark.parametrize("field", ALL_FIELDS)
@pytest.mark.parametrize("value", BAD_VALUES)
def test_invalid_field_values(field: str, value: Any) -> None:
    with pytest.raises(ValueError, match=field):
        ParseLimits(**{field: value})


def test_default_constants() -> None:
    assert ParseLimits() == DEFAULT_LIMITS
