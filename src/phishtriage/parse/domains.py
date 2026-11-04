import ipaddress
from dataclasses import dataclass

import idna
from tldextract import tldextract

_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)


@dataclass(frozen=True, slots=True)
class DomainInfo:
    host: str
    registrable: str | None
    suffix: str | None
    subdomain: str
    is_ip: bool
    is_idn: bool
    unicode_host: str
    label_count: int


def domain_info(host: str) -> DomainInfo:
    """Extract domain information from a host."""

    stripped = host.strip("[]").removesuffix(".").lower()

    try:
        ipaddress.ip_address(stripped)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        return DomainInfo(
            host=stripped,
            registrable=None,
            suffix=None,
            subdomain="",
            is_ip=True,
            is_idn=False,
            unicode_host=stripped,
            label_count=0,
        )

    r = _EXTRACT(stripped)

    unicode_host = stripped
    is_idn = any(label.startswith("xn--") for label in stripped.split("."))

    if is_idn:
        try:
            unicode_host = idna.decode(stripped)
        except UnicodeError:
            unicode_host = stripped

    registrable = f"{r.domain}.{r.suffix}" if r.domain and r.suffix else None

    return DomainInfo(
        host=stripped,
        registrable=registrable,
        suffix=r.suffix or None,
        subdomain=r.subdomain or "",
        is_ip=False,
        is_idn=is_idn,
        unicode_host=unicode_host,
        label_count=len([label for label in stripped.split(".") if label]),
    )
