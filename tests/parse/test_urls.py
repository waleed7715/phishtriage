"""Tests for phishtriage.parse.urls: normalize_url and unwrap_url."""

from urllib.parse import quote

import pytest

from phishtriage.parse.urls import normalize_url, unwrap_url

SL = "https://nam12.safelinks.protection.outlook.com/?url="
PP2 = "https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.test_login&d=DwMF&c=x"

# ---------- normalize_url ----------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("HTTP://Example.COM/Path?q=1#Frag", "http://example.com/Path?q=1#Frag"),
        ("  <https://a.test/x>  ", "https://a.test/x"),
        ('"https://a.test/x"', "https://a.test/x"),
        ("https://a.test:443/x", "https://a.test/x"),
        ("http://a.test:80/", "http://a.test/"),
        ("https://a.test:8443/x", "https://a.test:8443/x"),
        ("https://bücher.example/", "https://xn--bcher-kva.example/"),
        ("http://192.0.2.1/x", "http://192.0.2.1/x"),
        ("http://[2001:DB8::1]:8080/x", "http://[2001:db8::1]:8080/x"),
        ("http://my_host.test/", "http://my_host.test/"),
    ],
)
def test_normalize(raw: str, expected: str) -> None:
    assert normalize_url(raw) == expected


def test_userinfo_is_kept_and_host_is_after_the_at_sign() -> None:
    # Classic trick: everything before @ is a username; the real host is evil.test.
    assert normalize_url("https://PayPal.com@Evil.TEST/x") == "https://PayPal.com@evil.test/x"


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "mailto:x@example.com",
        "javascript:alert(1)",
        "data:text/html,<script>x</script>",
        "ftp://files.test/a",
        "/relative/path",
        "http://[::1",
        "https://a.test:99999/",
        "https:///no-host",
    ],
)
def test_normalize_rejects(raw: str) -> None:
    assert normalize_url(raw) is None


# ---------- unwrap_url ----------


def test_not_wrapped() -> None:
    assert unwrap_url("https://example.com/a") == ("https://example.com/a", None)


def test_safelinks() -> None:
    wrapped = SL + quote("https://evil.test/login", safe="") + "&data=05%7C01%7C"
    assert unwrap_url(wrapped) == ("https://evil.test/login", "safelinks")


def test_safelinks_without_url_param_is_left_alone() -> None:
    url = "https://nam12.safelinks.protection.outlook.com/?data=05"
    assert unwrap_url(url) == (url, None)


def test_lookalike_safelinks_host_is_not_trusted() -> None:
    fake = "https://safelinks.protection.outlook.com.evil.test/?url=https%3A%2F%2Fbenign.test"
    assert unwrap_url(fake) == (fake, None)


def test_proofpoint_v2() -> None:
    assert unwrap_url(PP2) == ("https://evil.test/login", "proofpoint_v2")


def test_proofpoint_v3() -> None:
    url = "https://urldefense.com/v3/__https://evil.test/login__;!!ABC!xyz$"
    assert unwrap_url(url) == ("https://evil.test/login", "proofpoint_v3")


def test_proofpoint_v3_keeps_embedded_query() -> None:
    url = "https://urldefense.com/v3/__https://evil.test/login?id=1__;!!ABC$"
    assert unwrap_url(url) == ("https://evil.test/login?id=1", "proofpoint_v3")


def test_proofpoint_v3_with_placeholders_is_flagged_unresolved() -> None:
    url = "https://urldefense.com/v3/__https://evil.test/a*b__;Iw!!X$"
    assert unwrap_url(url) == (url, "proofpoint_v3_unresolved")


def test_nested_wrappers_report_the_outermost() -> None:
    wrapped = SL + quote(PP2, safe="") + "&data=1"
    assert unwrap_url(wrapped) == ("https://evil.test/login", "safelinks")


def test_max_depth_stops_unwrapping() -> None:
    url = "https://evil.test/x"
    for _ in range(4):
        url = SL + quote(url, safe="") + "&data=1"
    final, wrapper = unwrap_url(url, max_depth=3)
    assert wrapper == "safelinks"
    assert "safelinks.protection.outlook.com" in final  # one layer remains


def test_unwrapped_non_http_target_stops() -> None:
    wrapped = SL + quote("javascript:alert(1)", safe="") + "&data=1"
    assert unwrap_url(wrapped) == (wrapped, None)


def test_proofpoint_v2_without_u_param_is_left_alone() -> None:
    url = "https://urldefense.proofpoint.com/v2/url?d=DwMF"
    assert unwrap_url(url) == (url, None)
