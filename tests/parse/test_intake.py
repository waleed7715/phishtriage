"""Tests for phishtriage.parse.intake.load_message."""

import contextlib
import email.parser
from email.message import EmailMessage, Message
from typing import NoReturn

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from phishtriage.parse.errors import (
    InputTooLarge,
    MimeTooDeep,
    NotAnEmail,
    ParseError,
    TooManyParts,
)
from phishtriage.parse.intake import MimeStats, load_message
from phishtriage.parse.limits import ParseLimits

# ---------- builders ----------


def _with_attachments(count: int) -> bytes:
    """multipart/mixed: one text part plus `count` attachments."""
    msg = EmailMessage()
    msg["From"] = "alice@example.com"
    msg["Subject"] = "attachments"
    msg.set_content("see attached")
    for i in range(count):
        msg.add_attachment(
            f"file {i}".encode(),
            maintype="application",
            subtype="octet-stream",
            filename=f"f{i}.bin",
        )
    return bytes(msg)


def _nested_raw(levels: int) -> bytes:
    """Raw bytes with `levels` nested multiparts and a text part at depth `levels`.

    Built by hand (not via email.mime) so very deep nesting doesn't hit
    recursion in the serializer.
    """
    out = [b"From: alice@example.com\r\nMIME-Version: 1.0\r\n"]
    for i in range(levels):
        out.append(f"Content-Type: multipart/mixed; boundary=b{i}\r\n\r\n--b{i}\r\n".encode())
    out.append(b"Content-Type: text/plain\r\n\r\ndeep\r\n")
    for i in reversed(range(levels)):
        out.append(f"--b{i}--\r\n".encode())
    return b"".join(out)


# ---------- happy paths ----------


def test_minimal_email(minimal_email: bytes) -> None:
    msg, stats = load_message(minimal_email)
    assert isinstance(msg, EmailMessage)
    assert isinstance(stats, MimeStats)
    assert stats.part_count == 1
    assert stats.max_depth == 0
    assert stats.defects == ()


def test_multipart_counts_parts_and_depth() -> None:
    _, stats = load_message(_with_attachments(2))
    assert stats.part_count == 4  # root + text + 2 attachments
    assert stats.max_depth == 1


def test_attached_email_counts_depth_through_rfc822() -> None:
    inner = EmailMessage()
    inner["From"] = "mallory@evil.test"
    inner["Subject"] = "inner"
    inner.set_content("inner body")

    outer = EmailMessage()
    outer["From"] = "reporter@example.com"
    outer["Subject"] = "FW: suspicious"
    outer.set_content("please check")
    outer.add_attachment(inner)  # creates a message/rfc822 part

    _, stats = load_message(bytes(outer))
    assert stats.part_count == 4  # root + text + rfc822 wrapper + inner message
    assert stats.max_depth == 2


def test_nested_counts() -> None:
    _, stats = load_message(_nested_raw(3))
    assert stats.part_count == 4
    assert stats.max_depth == 3


# ---------- limits ----------


def test_too_large(minimal_email: bytes) -> None:
    with pytest.raises(InputTooLarge, match="input_too_large"):
        load_message(minimal_email, ParseLimits(max_message_bytes=100))


def test_exactly_at_size_limit_is_allowed(minimal_email: bytes) -> None:
    _, stats = load_message(minimal_email, ParseLimits(max_message_bytes=len(minimal_email)))
    assert stats.part_count == 1


def test_too_many_parts() -> None:
    with pytest.raises(TooManyParts, match="too_many_parts"):
        load_message(_with_attachments(5), ParseLimits(max_parts=3))


@pytest.mark.parametrize(("levels", "raises"), [(10, False), (11, True)])
def test_depth_limit_boundary(levels: int, raises: bool) -> None:
    raw = _nested_raw(levels)
    if raises:
        with pytest.raises(MimeTooDeep, match="mime_too_deep"):
            load_message(raw)
    else:
        _, stats = load_message(raw)
        assert stats.max_depth == 10


def test_very_deep_nesting_is_a_parse_error_not_a_crash() -> None:
    # Far beyond any limit; must surface as ParseError (MimeTooDeep or a wrapped
    # RecursionError from the stdlib parser), never as an unhandled exception.
    with pytest.raises(ParseError):
        load_message(_nested_raw(2000))


# ---------- not an email ----------


@pytest.mark.parametrize(
    "raw",
    [b"", b"\x00\x01\x02 binary junk", b"just some text without headers\r\n"],
)
def test_not_an_email(raw: bytes) -> None:
    with pytest.raises(NotAnEmail, match="not_an_email"):
        load_message(raw)


# ---------- defects ----------


def test_defects_recorded_and_deduplicated() -> None:
    raw = (
        b"From: alice@example.com\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=XYZ\r\n"
        b"\r\n"
        b"no boundary marker anywhere\r\n"
    )
    _, stats = load_message(raw)
    assert stats.defects  # at least one defect name
    assert len(stats.defects) == len(set(stats.defects))


# ---------- properties: hostile input never escapes as a non-ParseError ----------


@settings(max_examples=500)
@given(st.binary(max_size=4096))
def test_random_bytes_never_crash(data: bytes) -> None:
    with contextlib.suppress(ParseError):
        _, stats = load_message(data)
        assert stats.part_count >= 1


@settings(max_examples=500)
@given(st.binary(max_size=4096))
def test_random_emails_never_crash(data: bytes) -> None:
    with contextlib.suppress(ParseError):
        _, stats = load_message(b"From: a@b.c\r\n" + data)
        assert stats.part_count >= 1


def test_header_check_is_case_insensitive() -> None:
    _, stats = load_message(b"message-id: <abc@example.com>\r\n\r\nbody\r\n")
    assert stats.part_count == 1


def test_defects_respect_max_defects() -> None:
    raw = (
        b"From: alice@example.com\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=XYZ\r\n"
        b"\r\n"
        b"no boundary marker anywhere\r\n"
    )
    _, stats = load_message(raw, ParseLimits(max_defects=1))
    assert len(stats.defects) == 1


def _boom(*_args: object, **_kwargs: object) -> NoReturn:
    raise ValueError("synthetic failure")


def test_unexpected_parser_error_is_wrapped(
    monkeypatch: pytest.MonkeyPatch, minimal_email: bytes
) -> None:
    monkeypatch.setattr(email.parser.BytesParser, "parsebytes", _boom)
    with pytest.raises(ParseError, match="ValueError") as exc_info:
        load_message(minimal_email)
    assert isinstance(exc_info.value.__cause__, ValueError)  # original kept via `from e`


def test_non_emailmessage_result_is_rejected(
    monkeypatch: pytest.MonkeyPatch, minimal_email: bytes
) -> None:
    monkeypatch.setattr(email.parser.BytesParser, "parsebytes", lambda *_a, **_k: Message())
    with pytest.raises(ParseError, match="parse_error"):
        load_message(minimal_email)


def test_unexpected_walk_error_is_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(EmailMessage, "iter_parts", _boom)
    with pytest.raises(ParseError, match="ValueError"):
        load_message(_with_attachments(1))
