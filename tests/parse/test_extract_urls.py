"""Tests for urls_from_text, urls_from_html and extract_urls."""

from urllib.parse import quote

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from phishtriage.parse.limits import ParseLimits
from phishtriage.parse.urls import ExtractedUrl, extract_urls, urls_from_html, urls_from_text

SL = "https://nam12.safelinks.protection.outlook.com/?url="

# ---------- urls_from_text ----------


def test_text_basic() -> None:
    assert urls_from_text("Visit https://evil.test/login now") == ["https://evil.test/login"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("see https://a.test/x.", "https://a.test/x"),
        ("first https://a.test/x, then", "https://a.test/x"),
        ("(see https://a.test/x)", "https://a.test/x"),
        ("https://en.wikipedia.org/wiki/Foo_(bar)", "https://en.wikipedia.org/wiki/Foo_(bar)"),
        ("<https://a.test/x>", "https://a.test/x"),
        ('"https://a.test/x"!', "https://a.test/x"),
    ],
)
def test_text_trailing_punctuation(text: str, expected: str) -> None:
    assert urls_from_text(text) == [expected]


def test_text_multiple_in_order_and_case_insensitive() -> None:
    assert urls_from_text("HTTPS://A.test/1 and http://b.test/2") == [
        "HTTPS://A.test/1",
        "http://b.test/2",
    ]


def test_text_requires_a_scheme() -> None:
    assert urls_from_text("go to www.evil.test today") == []


# ---------- urls_from_html ----------


def test_html_href_keeps_anchor_text() -> None:
    html = '<p>Log in: <a href="https://evil.test/login">https://paypal.com</a></p>'
    assert urls_from_html(html) == [("https://evil.test/login", "html_href", "https://paypal.com")]


@pytest.mark.parametrize(
    ("html", "source"),
    [
        ('<img src="https://t.test/pixel.gif">', "html_src"),
        ('<iframe src="https://evil.test/frame"></iframe>', "html_src"),
        ('<form action="https://evil.test/collect"></form>', "html_form"),
    ],
)
def test_html_other_sources(html: str, source: str) -> None:
    (entry,) = urls_from_html(html)
    assert entry[1] == source
    assert entry[2] is None


def test_html_meta_refresh() -> None:
    html = '<meta http-equiv="Refresh" content="0; URL=\'https://evil.test/r\'">'
    assert urls_from_html(html) == [("https://evil.test/r", "html_meta_refresh", None)]


def test_html_entities_in_href_are_decoded() -> None:
    (entry,) = urls_from_html('<a href="https://a.test/?a=1&amp;b=2">x</a>')
    assert entry[0] == "https://a.test/?a=1&b=2"


def test_html_anchor_text_is_collapsed_and_capped() -> None:
    html = '<a href="https://a.test/">  click\n\n  ' + "z" * 300 + "</a>"
    (entry,) = urls_from_html(html)
    assert entry[2] is not None
    assert entry[2].startswith("click z")
    assert len(entry[2]) <= 200


def test_html_document_order() -> None:
    html = '<a href="https://a.test/1">a</a><img src="https://b.test/2"><a href="https://c.test/3">c</a>'
    assert [e[0] for e in urls_from_html(html)] == [
        "https://a.test/1",
        "https://b.test/2",
        "https://c.test/3",
    ]


# ---------- extract_urls ----------


def test_extract_unwraps_and_records_original() -> None:
    wrapped = SL + quote("https://evil.test/login", safe="") + "&data=1"
    (u,) = extract_urls([f"click {wrapped}"], [])
    assert isinstance(u, ExtractedUrl)
    assert u.url == "https://evil.test/login"
    assert u.original == wrapped
    assert u.wrapper == "safelinks"
    assert u.host == "evil.test"
    assert u.source == "text"
    assert u.anchor_text is None


def test_extract_drops_non_http() -> None:
    html = '<a href="mailto:x@example.com">mail</a><a href="javascript:void(0)">js</a>'
    assert extract_urls([], [html]) == ()


def test_extract_dedupes_with_html_first() -> None:
    html = '<a href="https://evil.test/login">Sign in</a>'
    text = "Or paste https://evil.test/login into your browser"
    (u,) = extract_urls([text], [html])
    assert u.source == "html_href"
    assert u.anchor_text == "Sign in"


def test_extract_flags_userinfo_and_uses_real_host() -> None:
    (u,) = extract_urls(["https://paypal.com@evil.test/verify"], [])
    assert u.host == "evil.test"
    assert u.has_userinfo is True


def test_extract_is_capped() -> None:
    text = " ".join(f"https://h{i}.test/" for i in range(10))
    assert len(extract_urls([text], [], ParseLimits(max_urls=3))) == 3


@settings(max_examples=300)
@given(st.text(max_size=2000))
def test_extract_never_raises(text: str) -> None:
    for u in extract_urls([text], [text]):
        assert u.url.startswith(("http://", "https://"))
