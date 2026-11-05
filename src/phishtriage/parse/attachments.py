import hashlib
import io
import unicodedata
import zipfile
from dataclasses import dataclass
from email.message import Message

from phishtriage.parse.limits import DEFAULT_LIMITS, ParseLimits

_PREFIX_SIGNATURES: tuple[tuple[str, tuple[bytes, ...]], ...] = (
    ("pe", (b"MZ",)),
    ("elf", (b"\x7fELF",)),
    (
        "zip",
        (
            b"PK\x03\x04",
            b"PK\x05\x06",
            b"PK\x07\x08",
        ),
    ),
    ("ole", (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",)),
    ("rar", (b"Rar!\x1a\x07",)),
    ("7z", (b"7z\xbc\xaf\x27\x1c",)),
    ("gzip", (b"\x1f\x8b",)),
    ("lnk", (b"\x4c\x00\x00\x00\x01\x14\x02\x00",)),
    ("rtf", (b"{\\rtf",)),
    ("png", (b"\x89PNG\r\n\x1a\n",)),
    ("jpeg", (b"\xff\xd8\xff",)),
    ("gif", (b"GIF87a", b"GIF89a")),
)

_ALLOWED_EXTS: dict[str, frozenset[str]] = {
    "pe": frozenset({"exe", "dll", "scr", "sys", "cpl", "com", "ocx", "drv", "efi"}),
    "elf": frozenset({"", "so", "bin", "elf"}),
    "zip": frozenset(
        {
            "zip",
            "docx",
            "docm",
            "xlsx",
            "xlsm",
            "pptx",
            "pptm",
            "jar",
            "apk",
            "odt",
            "ods",
            "odp",
            "epub",
            "xpi",
            "vsix",
            "nupkg",
            "msix",
            "appx",
            "kmz",
        }
    ),
    "ole": frozenset({"doc", "xls", "ppt", "msg", "msi", "dot", "xlt", "pps", "pub", "vsd"}),
    "pdf": frozenset({"pdf"}),
    "rar": frozenset({"rar"}),
    "7z": frozenset({"7z"}),
    "gzip": frozenset({"gz", "tgz"}),
    "iso": frozenset({"iso", "img"}),
    "lnk": frozenset({"lnk"}),
    "rtf": frozenset({"rtf", "doc"}),
    "png": frozenset({"png"}),
    "jpeg": frozenset({"jpg", "jpeg", "jpe"}),
    "gif": frozenset({"gif"}),
    "html": frozenset({"htm", "html", "shtml", "xhtml", "hta"}),
}

_DOC_EXTS: frozenset[str] = frozenset(
    {
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "txt",
        "rtf",
        "csv",
        "jpg",
        "jpeg",
        "png",
        "gif",
    }
)

_BIDI_CHARS: frozenset[str] = frozenset(
    {
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }
)


@dataclass(frozen=True, slots=True)
class ArchiveMember:
    name: str
    size: int
    compressed_size: int
    encrypted: bool


@dataclass(frozen=True, slots=True)
class Attachment:
    filename: str | None
    declared_type: str
    detected_type: str
    extension: str
    double_extension: bool
    bidi_override: bool
    extension_mismatch: bool
    inline: bool
    size: int
    sha256: str
    sha1: str
    md5: str
    archive_members: tuple[ArchiveMember, ...]
    archive_encrypted: bool
    archive_error: str | None


def _sanitize_name(raw: str, keep_path: bool) -> tuple[str, bool]:
    """Remove bidi and control characters; return (clean_name, had_bidi)."""

    had_bidi = any(char in _BIDI_CHARS for char in raw)

    cleaned = "".join(
        char for char in raw if char not in _BIDI_CHARS and unicodedata.category(char) != "Cc"
    )

    if not keep_path:
        cleaned = cleaned.replace("\\", "/").rsplit("/", 1)[-1]

    cleaned = cleaned.strip().rstrip(". ")[:255]

    return cleaned, had_bidi


def _extension(filename: str | None) -> str:
    """Return the extension of a filename, or an empty string if none."""

    if not filename or "." not in filename[1:]:
        return ""

    return filename.rsplit(".", 1)[-1].lower()


def _is_double_extension(filename: str | None) -> bool:
    """Return True if the filename has a double extension."""

    if not filename or "." not in filename:
        return False

    parts = filename.lower().split(".")
    return len(parts) > 2 and parts[-2] in _DOC_EXTS and parts[-1] != parts[-2]


def _detect_type(data: bytes) -> str:
    """Detect the type of a file based on its magic number."""

    for type_name, signatures in _PREFIX_SIGNATURES:
        if any(data.startswith(sig) for sig in signatures):
            return type_name

    if data[32769:32774] == b"CD001":
        return "iso"

    if b"%PDF-" in data[:1024]:
        return "pdf"

    html_data = data[:1024].removeprefix(b"\xef\xbb\xbf").lstrip().lower()

    if html_data.startswith((b"<!doctype html", b"<html", b"<head", b"<body")):
        return "html"

    return "unknown"


def _list_zip(data: bytes, limits: ParseLimits) -> tuple[tuple[ArchiveMember, ...], str | None]:
    """List the members of a ZIP archive, returning a tuple of ArchiveMember objects."""

    if len(data) > limits.max_attachment_bytes:
        return (), "too_large"

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            info_list = zf.infolist()
    except Exception:
        return (), "bad_archive"

    error: str | None = None

    if len(info_list) > limits.max_archive_members:
        info_list = info_list[: limits.max_archive_members]
        error = "too_many_members"

    archive_members: list[ArchiveMember] = []

    for member in info_list:
        archive_members.append(
            ArchiveMember(
                name=_sanitize_name(member.filename, keep_path=True)[0],
                size=member.file_size,
                compressed_size=member.compress_size,
                encrypted=bool(member.flag_bits & 0x1),
            )
        )

    if (
        error is None
        and sum(member.file_size for member in info_list) > limits.max_archive_uncompressed_bytes
    ):
        error = "too_large_uncompressed"

    return tuple(archive_members), error


def _make_attachment(part: Message, data: bytes, limits: ParseLimits) -> Attachment:
    """Create an Attachment object from a message part and its data."""

    try:
        raw_name = part.get_filename()
    except Exception:
        raw_name = None

    if raw_name:
        name, bidi = _sanitize_name(raw_name, keep_path=False)
    else:
        name, bidi = "", False

    extension = _extension(name)
    double_extension = _is_double_extension(name)
    detected = _detect_type(data)
    mismatch = detected != "unknown" and extension not in _ALLOWED_EXTS[detected]

    disposition = part.get_content_disposition()
    inline = disposition == "inline" or ("Content-ID" in part and disposition != "attachment")

    members, archive_error = _list_zip(data, limits) if detected == "zip" else ((), None)
    archive_encrypted = any(member.encrypted for member in members)

    return Attachment(
        filename=name or None,
        declared_type=part.get_content_type(),
        detected_type=detected,
        extension=extension,
        double_extension=double_extension,
        bidi_override=bidi,
        extension_mismatch=mismatch,
        inline=inline,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        sha1=hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
        archive_members=members,
        archive_encrypted=archive_encrypted,
        archive_error=archive_error,
    )


def collect_attachments(
    message: Message, limits: ParseLimits = DEFAULT_LIMITS
) -> tuple[Attachment, ...]:
    """Collect all attachments from a message, returning a tuple of Attachment objects."""

    stack: list[Message] = [message]
    result: list[Attachment] = []

    while stack:
        part = stack.pop()
        ctype = part.get_content_type()

        if ctype == "message/rfc822":
            payload = part.get_payload()

            try:
                if isinstance(payload, list) and payload and isinstance(payload[0], Message):
                    data = payload[0].as_bytes()
                else:
                    data = b""
            except Exception:
                data = b""

            result.append(_make_attachment(part, data, limits))
            continue

        if part.is_multipart():
            payload = part.get_payload()

            if isinstance(payload, list):
                children = [child for child in payload if isinstance(child, Message)]
                stack.extend(reversed(children))
            continue

        disposition = part.get_content_disposition()

        try:
            has_filename = part.get_filename() is not None
        except Exception:
            has_filename = False

        if (
            disposition != "attachment"
            and not has_filename
            and ctype
            in (
                "text/plain",
                "text/html",
            )
        ):
            continue

        raw = part.get_payload(decode=True)
        data = raw if isinstance(raw, bytes) else b""
        result.append(_make_attachment(part, data, limits))

    return tuple(result)
