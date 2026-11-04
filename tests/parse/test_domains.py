"""Tests for phishtriage.parse.domains.domain_info."""

import socket
from typing import NoReturn

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from phishtriage.parse.domains import DomainInfo, domain_info


def _no_network(*_args: object, **_kwargs: object) -> NoReturn:
    raise AssertionError("domain_info attempted network access")


# Keep this test first: it must run before anything else loads the suffix list.
def test_never_uses_the_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket.socket, "connect", _no_network)
    assert domain_info("login.evil.co.uk").registrable == "evil.co.uk"


def test_multi_part_suffix() -> None:
    info = domain_info("login.secure.evil.co.uk")
    assert isinstance(info, DomainInfo)
    assert info.registrable == "evil.co.uk"
    assert info.suffix == "co.uk"
    assert info.subdomain == "login.secure"
    assert info.label_count == 5
    assert info.is_ip is False


def test_host_is_normalized() -> None:
    info = domain_info("Example.COM.")
    assert info.host == "example.com"
    assert info.registrable == "example.com"


def test_private_suffix_makes_each_site_its_own_domain() -> None:
    info = domain_info("evil.github.io")
    assert info.registrable == "evil.github.io"
    assert info.suffix == "github.io"


@pytest.mark.parametrize("host", ["localhost", "host.notarealtld", ""])
def test_no_registrable_domain(host: str) -> None:
    assert domain_info(host).registrable is None


@pytest.mark.parametrize("host", ["192.0.2.1", "2001:db8::1", "[2001:db8::1]"])
def test_ip_hosts(host: str) -> None:
    info = domain_info(host)
    assert info.is_ip is True
    assert info.registrable is None
    assert info.suffix is None
    assert info.subdomain == ""
    assert info.label_count == 0


def test_idn_host() -> None:
    info = domain_info("xn--bcher-kva.de")
    assert info.is_idn is True
    assert info.unicode_host == "bücher.de"
    assert info.registrable == "xn--bcher-kva.de"


def test_plain_ascii_is_not_idn() -> None:
    info = domain_info("paypal.com")
    assert info.is_idn is False
    assert info.unicode_host == "paypal.com"


@settings(max_examples=500)
@given(st.text(max_size=100))
def test_never_raises(host: str) -> None:
    info = domain_info(host)
    assert info.label_count >= 0


def test_idn_in_a_later_label() -> None:
    info = domain_info("login.xn--bcher-kva.de")
    assert info.is_idn is True
    assert info.unicode_host == "login.bücher.de"
    assert info.registrable == "xn--bcher-kva.de"
