"""Tests for phishtriage.parse.bodies."""

import contextlib
from email.message import EmailMessage

from hypothesis import given, settings
from hypothesis import strategies as st

from phishtriage.parse.bodies import Bodies, BodyPart, collect_bodies, decode_part
from phishtriage.parse.errors import ParseError
from phishtriage.parse.intake import load_message
from phishtriage.parse.limits import ParseLimits

# ---------- builders ----------


def _raw(content_type: bytes, body: bytes, cte: bytes = b"8bit") -> EmailMessage:
    """Single-part email from exact bytes, so charset tests control every byte."""
    raw = (
        b"From: a@example.com\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: " + content_type + b"\r\n"
        b"Content-Transfer-Encoding: " + cte + b"\r\n\r\n" + body
    )
    msg, _ = load_message(raw)
    return msg


def _parse(msg: EmailMessage) -> EmailMessage:
    parsed, _ = load_message(bytes(msg))
    return parsed


def _multipart(subtype: bytes, *parts: bytes) -> EmailMessage:
    """multipart/<subtype> from raw part blocks (headers + blank line + body)."""
    body = b"".join(b"--B\r\n" + p + b"\r\n" for p in parts) + b"--B--\r\n"
    raw = (
        b"From: a@example.com\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: multipart/" + subtype + b"; boundary=B\r\n\r\n" + body
    )
    msg, _ = load_message(raw)
    return msg


# ---------- structure ----------


def test_plain_only() -> None:
    msg = EmailMessage()
    msg["From"] = "a@example.com"
    msg.set_content("Hello")
    bodies = collect_bodies(_parse(msg))
    assert isinstance(bodies, Bodies)
    assert len(bodies.plain) == 1
    assert isinstance(bodies.plain[0], BodyPart)
    assert bodies.plain[0].content_type == "text/plain"
    assert bodies.plain[0].text.strip() == "Hello"
    assert bodies.plain[0].decode_errors is False
    assert bodies.html == ()
    assert bodies.truncated is False


def test_alternative_has_plain_and_html() -> None:
    msg = EmailMessage()
    msg["From"] = "a@example.com"
    msg.set_content("plain version")
    msg.add_alternative("<p>html version</p>", subtype="html")
    bodies = collect_bodies(_parse(msg))
    assert bodies.plain[0].text.strip() == "plain version"
    assert bodies.html[0].content_type == "text/html"
    assert "html version" in bodies.html[0].text


def test_document_order_is_kept() -> None:
    msg = _multipart(
        b"mixed",
        b"Content-Type: text/plain; charset=utf-8\r\n\r\nfirst",
        b"Content-Type: text/plain; charset=utf-8\r\n\r\nsecond",
    )
    assert [p.text for p in collect_bodies(msg).plain] == ["first", "second"]


def test_text_attachment_is_not_a_body() -> None:
    msg = EmailMessage()
    msg["From"] = "a@example.com"
    msg.set_content("main body")
    msg.add_attachment(b"secret notes", maintype="text", subtype="plain", filename="notes.txt")
    bodies = collect_bodies(_parse(msg))
    assert [p.text.strip() for p in bodies.plain] == ["main body"]


def test_attached_email_body_is_not_included() -> None:
    inner = EmailMessage()
    inner["From"] = "mallory@evil.test"
    inner.set_content("INNER BODY")
    outer = EmailMessage()
    outer["From"] = "reporter@example.com"
    outer.set_content("outer body")
    outer.add_attachment(inner)
    bodies = collect_bodies(_parse(outer))
    assert all("INNER BODY" not in p.text for p in bodies.plain + bodies.html)


def test_non_text_part_decodes_to_none() -> None:
    msg = _raw(b"image/png", b"\x89PNG\r\n", cte=b"binary")
    assert decode_part(msg, 100) is None
    bodies = collect_bodies(msg)
    assert bodies.plain == ()
    assert bodies.html == ()


# ---------- charsets ----------


def test_declared_windows_1252() -> None:
    part = collect_bodies(_raw(b"text/plain; charset=windows-1252", b"caf\xe9")).plain[0]
    assert part.text == "café"
    assert part.charset == "windows-1252"
    assert part.decode_errors is False


def test_mislabeled_utf8_falls_back_and_flags() -> None:
    part = collect_bodies(_raw(b"text/plain; charset=utf-8", b"caf\xe9")).plain[0]
    assert part.text == "café"
    assert part.charset == "windows-1252"
    assert part.decode_errors is True


def test_unknown_charset_falls_back_and_flags() -> None:
    part = collect_bodies(_raw(b"text/plain; charset=x-bogus", b"hello")).plain[0]
    assert part.text == "hello"
    assert part.charset == "utf-8"
    assert part.decode_errors is True


def test_non_text_codec_is_never_applied() -> None:
    # rot13 is a Python codec but not a text encoding; the body must stay as sent.
    part = collect_bodies(_raw(b"text/plain; charset=rot13", b"uryyb")).plain[0]
    assert part.text == "uryyb"
    assert part.decode_errors is True


def test_undecodable_bytes_use_replacement() -> None:
    # 0x81 and 0x8D are invalid in UTF-8 and undefined in Windows-1252.
    part = collect_bodies(_raw(b"text/plain; charset=utf-8", b"ab\x81\x8dcd")).plain[0]
    assert part.text == "ab\ufffd\ufffdcd"
    assert part.charset == "utf-8"
    assert part.decode_errors is True


def test_base64_transfer_encoding_is_decoded() -> None:
    msg = EmailMessage()
    msg["From"] = "a@example.com"
    msg.set_content("Hello base64", cte="base64")
    assert collect_bodies(_parse(msg)).plain[0].text.strip() == "Hello base64"


# ---------- cleaning ----------


def test_nul_bytes_are_removed() -> None:
    assert collect_bodies(_raw(b"text/plain; charset=utf-8", b"a\x00b")).plain[0].text == "ab"


def test_crlf_becomes_lf() -> None:
    part = collect_bodies(_raw(b"text/plain; charset=utf-8", b"line1\r\nline2\r\n")).plain[0]
    assert part.text == "line1\nline2\n"


# ---------- budget ----------


def test_single_part_is_truncated() -> None:
    msg = _raw(b"text/plain; charset=utf-8", b"x" * 50)
    bodies = collect_bodies(msg, ParseLimits(max_text_chars=10))
    assert bodies.plain[0].text == "x" * 10
    assert bodies.plain[0].truncated is True
    assert bodies.truncated is True


def test_total_budget_spans_parts_and_skips_the_rest() -> None:
    msg = _multipart(
        b"mixed",
        b"Content-Type: text/plain; charset=utf-8\r\n\r\naaaaaaaa",
        b"Content-Type: text/html; charset=utf-8\r\n\r\nbbbbbbbb",
        b"Content-Type: text/plain; charset=utf-8\r\n\r\ncccc",
    )
    bodies = collect_bodies(msg, ParseLimits(max_text_chars=10))
    assert bodies.plain[0].text == "aaaaaaaa"
    assert bodies.html[0].text == "bb"
    assert bodies.html[0].truncated is True
    assert len(bodies.plain) == 1  # "cccc" skipped: budget spent
    assert bodies.truncated is True


# ---------- property ----------


@settings(max_examples=300)
@given(st.binary(max_size=4096))
def test_collect_bodies_never_raises_and_text_is_clean(data: bytes) -> None:
    with contextlib.suppress(ParseError):
        msg, _ = load_message(b"From: a@b.c\r\nContent-Type: text/plain\r\n\r\n" + data)
        for part in collect_bodies(msg).plain:
            assert "\x00" not in part.text
            part.text.encode("utf-8")


def test_nul_between_cr_and_lf_still_normalizes() -> None:
    part = collect_bodies(_raw(b"text/plain; charset=utf-8", b"a\r\x00\nb")).plain[0]
    assert part.text == "a\nb"


def test_exact_budget_with_trailing_attachment_is_not_truncated() -> None:
    msg = _multipart(
        b"mixed",
        b"Content-Type: text/plain; charset=utf-8\r\n\r\naaaa",
        b"Content-Type: application/pdf\r\n"
        b"Content-Disposition: attachment; filename=a.pdf\r\n\r\n%PDF",
    )
    bodies = collect_bodies(msg, ParseLimits(max_text_chars=4))
    assert bodies.plain[0].text == "aaaa"
    assert bodies.truncated is False
