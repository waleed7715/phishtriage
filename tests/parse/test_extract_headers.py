"""Tests for extract_headers."""

import contextlib
from datetime import UTC, datetime
from email.message import EmailMessage

from hypothesis import given, settings
from hypothesis import strategies as st

from phishtriage.parse.errors import ParseError
from phishtriage.parse.headers import HeaderInfo, extract_headers
from phishtriage.parse.intake import load_message
from phishtriage.parse.limits import ParseLimits

PHISH = b"\r\n".join(
    [
        b"Received: from mx.relay.test (mx.relay.test [198.51.100.2]) by mx.example.com;"
        b" Mon, 02 Nov 2026 10:05:00 +0000",
        b"Received: from mail.evil.test (mail.evil.test [203.0.113.7]) by mx.relay.test;"
        b" Mon, 02 Nov 2026 10:00:00 +0000",
        b"Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=evil.test;"
        b" dkim=none; dmarc=fail header.from=paypal.com",
        b"Return-Path: <Bounce@Evil.TEST>",
        b'From: "PayPal Support" <support@paypa1.test>',
        b"Reply-To: collect@evil.test",
        b"To: victim@example.com, other@example.com",
        b"Cc: boss@example.com",
        b"Subject: =?utf-8?b?QWN0aW9uIHJlcXVpcmVk?=",
        b"Date: Mon, 02 Nov 2026 05:00:00 -0500",
        b"Message-ID: <abc123@evil.test>",
        b"X-Mailer: PHPMailer 6.0",
        b"List-Unsubscribe: <mailto:unsub@evil.test>",
        b"",
        b"Your account is locked.",
        b"",
    ]
)


def _msg(raw: bytes) -> EmailMessage:
    msg, _ = load_message(raw)
    return msg


def test_extracts_full_phish() -> None:
    info = extract_headers(_msg(PHISH))
    assert isinstance(info, HeaderInfo)
    assert info.subject == "Action required"
    assert info.from_[0].display_name == "PayPal Support"
    assert info.from_[0].address == "support@paypa1.test"
    assert info.reply_to[0].domain == "evil.test"
    assert info.sender == ()
    assert info.return_path == "bounce@evil.test"
    assert info.to_count == 2
    assert info.cc_count == 1
    assert info.message_id == "<abc123@evil.test>"
    assert info.date == datetime(2026, 11, 2, 10, 0, tzinfo=UTC)
    assert info.x_mailer == "PHPMailer 6.0"
    assert info.list_unsubscribe == "<mailto:unsub@evil.test>"
    assert info.arc_auth_results == ()
    assert info.auth_results == (
        "mx.example.com; spf=fail smtp.mailfrom=evil.test; dkim=none; "
        "dmarc=fail header.from=paypal.com",
    )


def test_received_order_is_topmost_first() -> None:
    hops = extract_headers(_msg(PHISH)).received
    assert [h.index for h in hops] == [0, 1]
    assert hops[0].by_host == "mx.example.com"  # last server, closest to the recipient
    assert hops[1].ip == "203.0.113.7"  # bottom hop: where it came from


def test_null_return_path_is_empty_string() -> None:
    info = extract_headers(_msg(b"Return-Path: <>\r\nFrom: a@example.com\r\n\r\nbody\r\n"))
    assert info.return_path == ""


def test_minimal_message_has_empty_optional_fields() -> None:
    info = extract_headers(_msg(b"From: a@example.com\r\n\r\nbody\r\n"))
    assert info.subject is None
    assert info.return_path is None
    assert info.message_id is None
    assert info.date is None
    assert info.received == ()
    assert info.auth_results == ()
    assert info.to_count == 0


def test_received_hops_are_capped_keeping_the_top() -> None:
    hops = b"".join(
        f"Received: from h{i}.test by mx.test; Mon, 02 Nov 2026 10:00:00 +0000\r\n".encode()
        for i in range(5)
    )
    info = extract_headers(
        _msg(hops + b"From: a@example.com\r\n\r\nbody\r\n"), ParseLimits(max_received_hops=2)
    )
    assert [h.from_host for h in info.received] == ["h0.test", "h1.test"]


@settings(max_examples=300)
@given(st.binary(max_size=4096))
def test_extract_headers_never_raises(data: bytes) -> None:
    with contextlib.suppress(ParseError):
        msg, _ = load_message(b"From: a@b.c\r\n" + data)
        extract_headers(msg)
