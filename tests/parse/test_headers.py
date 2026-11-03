"""Tests for phishtriage.parse.headers: header text and address helpers."""

import email.policy
from email.message import EmailMessage
from typing import NoReturn

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from phishtriage.parse.errors import ParseError
from phishtriage.parse.headers import Address, header_text, header_texts, parse_addresses
from phishtriage.parse.intake import load_message
from phishtriage.parse.limits import ParseLimits

# ---------- builders ----------


def _msg(*header_lines: bytes, body: bytes = b"body") -> EmailMessage:
    raw = b"\r\n".join(header_lines) + b"\r\n\r\n" + body + b"\r\n"
    msg, _ = load_message(raw)
    return msg


def _boom(*_args: object, **_kwargs: object) -> NoReturn:
    raise ValueError("synthetic header failure")


# ---------- header_text ----------


def test_header_text_decodes_encoded_words() -> None:
    msg = _msg(b"From: a@example.com", b"Subject: =?utf-8?b?SGVsbG8gV29ybGQ=?=")
    assert header_text(msg, "Subject", 100) == "Hello World"


def test_header_text_missing_is_none() -> None:
    assert header_text(_msg(b"From: a@example.com"), "Subject", 100) is None


def test_header_text_unfolds() -> None:
    msg = _msg(b"From: a@example.com", b"Subject: part one\r\n   part two")
    assert header_text(msg, "Subject", 100) == "part one part two"


def test_header_text_truncates() -> None:
    msg = _msg(b"From: a@example.com", b"Subject: " + b"x" * 50)
    assert header_text(msg, "Subject", 10) == "x" * 10


def test_header_text_is_case_insensitive() -> None:
    msg = _msg(b"FROM: a@example.com", b"subject: hi")
    assert header_text(msg, "Subject", 100) == "hi"


def test_header_text_falls_back_to_raw(monkeypatch: pytest.MonkeyPatch) -> None:
    msg = _msg(b"From: a@example.com", b"Subject: raw value")
    # Make every structured header read fail; raw_items() doesn't use this method.
    monkeypatch.setattr(email.policy.EmailPolicy, "header_fetch_parse", _boom)
    assert header_text(msg, "Subject", 100) == "raw value"


def test_header_text_output_is_valid_utf8() -> None:
    msg = _msg(b"From: a@example.com", b"Subject: caf\xff bar")
    value = header_text(msg, "Subject", 100)
    assert value is not None
    value.encode("utf-8")  # raises on lone surrogates
    assert "bar" in value


# ---------- header_texts ----------


def test_header_texts_returns_all_in_order() -> None:
    msg = _msg(
        b"Received: from b.test by c.test",
        b"Received: from a.test\r\n by b.test",
        b"From: x@y.test",
    )
    assert header_texts(msg, "Received", 500) == (
        "from b.test by c.test",
        "from a.test by b.test",
    )


def test_header_texts_missing_is_empty() -> None:
    assert header_texts(_msg(b"From: x@y.test"), "Received", 500) == ()


def test_header_texts_case_insensitive_and_truncated() -> None:
    msg = _msg(b"From: x@y.test", b"received: " + b"r" * 50)
    assert header_texts(msg, "Received", 10) == ("r" * 10,)


def test_header_texts_output_is_valid_utf8() -> None:
    msg = _msg(b"From: x@y.test", b"X-Test: caf\xff")
    (value,) = header_texts(msg, "X-Test", 100)
    value.encode("utf-8")


# ---------- parse_addresses ----------


def test_parse_single_address() -> None:
    msg = _msg(b"From: Alice Example <Alice@Example.COM>")
    assert parse_addresses(msg, "From") == (
        Address("Alice Example", "alice@example.com", "example.com"),
    )


def test_parse_multiple_addresses() -> None:
    msg = _msg(b"From: x@y.test", b"To: a@x.test, B <b@y.test>")
    result = parse_addresses(msg, "To")
    assert [a.address for a in result] == ["a@x.test", "b@y.test"]
    assert result[1].display_name == "B"


def test_parse_missing_is_empty() -> None:
    assert parse_addresses(_msg(b"From: x@y.test"), "Reply-To") == ()


def test_display_name_holding_an_address_is_kept() -> None:
    msg = _msg(b'From: "support@paypal.com" <x@evil.test>')
    (addr,) = parse_addresses(msg, "From")
    assert addr.display_name == "support@paypal.com"
    assert addr.address == "x@evil.test"
    assert addr.domain == "evil.test"


def test_empty_group_yields_no_addresses() -> None:
    msg = _msg(b"From: x@y.test", b"To: undisclosed-recipients:;")
    assert parse_addresses(msg, "To") == ()


def test_addresses_are_capped() -> None:
    to = b", ".join(f"u{i}@x.test".encode() for i in range(5))
    msg = _msg(b"From: x@y.test", b"To: " + to)
    assert len(parse_addresses(msg, "To", ParseLimits(max_addresses=2))) == 2


def test_parse_addresses_falls_back_to_raw(monkeypatch: pytest.MonkeyPatch) -> None:
    msg = _msg(b"From: Alice <alice@example.com>")
    monkeypatch.setattr(email.policy.EmailPolicy, "header_fetch_parse", _boom)
    (addr,) = parse_addresses(msg, "From")
    assert addr.address == "alice@example.com"


@settings(max_examples=300)
@given(st.text(max_size=200))
def test_parse_addresses_never_raises(value: str) -> None:
    line = value.encode("utf-8").replace(b"\r", b"").replace(b"\n", b"")
    try:
        msg, _ = load_message(b"Subject: x\r\nTo: " + line + b"\r\n\r\nbody\r\n")
    except ParseError:
        assume(False)
    for addr in parse_addresses(msg, "To"):
        addr.address.encode("utf-8")
        addr.display_name.encode("utf-8")
