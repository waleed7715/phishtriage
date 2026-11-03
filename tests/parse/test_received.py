"""Tests for parse_date and parse_received."""

from datetime import UTC, datetime

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from phishtriage.parse.headers import ReceivedHop, parse_date, parse_received

# ---------- parse_date ----------


def test_parse_date_converts_to_utc() -> None:
    assert parse_date("Mon, 02 Nov 2026 10:00:00 -0800") == datetime(2026, 11, 2, 18, 0, tzinfo=UTC)


def test_parse_date_naive_minus_zero_is_utc() -> None:
    assert parse_date("Mon, 02 Nov 2026 10:00:00 -0000") == datetime(2026, 11, 2, 10, 0, tzinfo=UTC)


@pytest.mark.parametrize("text", [None, "", "not a date", "Mon, 99 Foo 20xx"])
def test_parse_date_bad_input_is_none(text: str | None) -> None:
    assert parse_date(text) is None


# ---------- parse_received ----------


def test_typical_hop() -> None:
    value = (
        "from mail.evil.test (mail.evil.test [203.0.113.7]) by mx.google.com with ESMTPS "
        "id abc123 for <victim@example.com>; Mon, 02 Nov 2026 10:00:00 -0800 (PST)"
    )
    hop = parse_received(value, 3)
    assert isinstance(hop, ReceivedHop)
    assert hop.index == 3
    assert hop.from_host == "mail.evil.test"
    assert hop.by_host == "mx.google.com"
    assert hop.ip == "203.0.113.7"
    assert hop.timestamp == datetime(2026, 11, 2, 18, 0, tzinfo=UTC)
    assert hop.raw == value


def test_ipv6_literal() -> None:
    hop = parse_received(
        "from host.test ([IPv6:2001:db8:0::1]) by mx.test; Mon, 02 Nov 2026 10:00:00 +0000", 0
    )
    assert hop.ip == "2001:db8::1"  # compressed form


def test_ip_only_in_by_clause_is_ignored() -> None:
    hop = parse_received(
        "from unknown by mx.test [198.51.100.9]; Mon, 02 Nov 2026 10:00:00 +0000", 0
    )
    assert hop.ip is None


def test_invalid_ip_is_skipped() -> None:
    hop = parse_received("from h.test ([999.1.1.1]) by mx.test; Mon, 02 Nov 2026 10:00:00 +0000", 0)
    assert hop.ip is None


def test_hosts_are_lowercased() -> None:
    hop = parse_received(
        "from MAIL.EVIL.TEST by MX.EXAMPLE.COM; Mon, 02 Nov 2026 10:00:00 +0000", 0
    )
    assert hop.from_host == "mail.evil.test"
    assert hop.by_host == "mx.example.com"


def test_hop_without_from() -> None:
    hop = parse_received("by mx.internal.test with LMTP; Mon, 02 Nov 2026 10:00:00 +0000", 0)
    assert hop.from_host is None
    assert hop.ip is None
    assert hop.by_host == "mx.internal.test"


def test_by_inside_a_word_is_not_a_keyword() -> None:
    hop = parse_received(
        "from standby.test ([192.0.2.1]) by mx.test; Mon, 02 Nov 2026 10:00:00 +0000", 0
    )
    assert hop.from_host == "standby.test"
    assert hop.by_host == "mx.test"
    assert hop.ip == "192.0.2.1"


@pytest.mark.parametrize(
    "value",
    ["from a.test by b.test", "from a.test by b.test; garbage date"],
)
def test_missing_or_bad_timestamp_is_none(value: str) -> None:
    assert parse_received(value, 0).timestamp is None


@settings(max_examples=500)
@given(st.text(max_size=300))
def test_parse_received_never_raises(value: str) -> None:
    hop = parse_received(value, 0)
    assert hop.raw == value
