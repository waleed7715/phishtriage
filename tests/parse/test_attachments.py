"""Tests for phishtriage.parse.attachments.collect_attachments."""

import contextlib
import hashlib
import io
import zipfile
from email.message import EmailMessage

from hypothesis import given, settings
from hypothesis import strategies as st

from phishtriage.parse.attachments import Attachment, collect_attachments
from phishtriage.parse.errors import ParseError
from phishtriage.parse.intake import load_message
from phishtriage.parse.limits import ParseLimits

PDF = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n"
PE = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 56
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16

# ---------- builders ----------


def _email() -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = "mallory@evil.test"
    msg["Subject"] = "invoice"
    msg.set_content("see attached")
    return msg


def _with(
    data: bytes, filename: str | None, maintype: str = "application", subtype: str = "octet-stream"
) -> Attachment:
    msg = _email()
    msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    parsed, _ = load_message(bytes(msg))
    (att,) = collect_attachments(parsed)
    return att


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _mark_encrypted(data: bytes) -> bytes:
    """Set the 'encrypted' flag bit in a single-member zip's local and central headers."""
    buf = bytearray(data)
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        buf[buf.find(signature) + offset] |= 0x01
    return bytes(buf)


# ---------- which parts are attachments ----------


def test_bodies_are_not_attachments() -> None:
    msg = _email()
    msg.add_alternative("<p>html</p>", subtype="html")
    parsed, _ = load_message(bytes(msg))
    assert collect_attachments(parsed) == ()


def test_text_file_attachment_counts() -> None:
    att = _with(b"notes", "notes.txt", maintype="text", subtype="plain")
    assert att.filename == "notes.txt"
    assert att.declared_type == "text/plain"


def test_attached_email_is_one_attachment() -> None:
    inner = _email()
    inner.add_attachment(PE, maintype="application", subtype="octet-stream", filename="x.exe")
    outer = _email()
    outer.add_attachment(inner)
    parsed, _ = load_message(bytes(outer))
    (att,) = collect_attachments(parsed)  # inner's x.exe is NOT listed separately
    assert att.declared_type == "message/rfc822"
    assert att.size > 0


def test_inline_image_with_content_id() -> None:
    msg = _email()
    msg.add_attachment(
        PNG,
        maintype="image",
        subtype="png",
        filename="logo.png",
        disposition="inline",
        cid="<logo@evil.test>",
    )
    parsed, _ = load_message(bytes(msg))
    (att,) = collect_attachments(parsed)
    assert att.inline is True
    assert att.detected_type == "png"


# ---------- hashes and types ----------


def test_pdf_hashes_and_type() -> None:
    att = _with(PDF, "invoice.pdf")
    assert att.detected_type == "pdf"
    assert att.extension == "pdf"
    assert att.extension_mismatch is False
    assert att.size == len(PDF)
    assert att.sha256 == hashlib.sha256(PDF).hexdigest()
    assert att.sha1 == hashlib.sha1(PDF).hexdigest()  # noqa: S324
    assert att.md5 == hashlib.md5(PDF).hexdigest()  # noqa: S324


def test_executable_disguised_as_pdf() -> None:
    att = _with(PE, "invoice.pdf")
    assert att.detected_type == "pe"
    assert att.extension_mismatch is True


def test_iso_detected_at_its_offset() -> None:
    iso = b"\x00" * 32769 + b"CD001" + b"\x00" * 100
    att = _with(iso, "invoice.iso")
    assert att.detected_type == "iso"
    assert att.extension_mismatch is False


def test_unknown_type_never_mismatches() -> None:
    att = _with(b"just some bytes", "data.xyz")
    assert att.detected_type == "unknown"
    assert att.extension_mismatch is False


# ---------- filename tricks ----------


def test_double_extension() -> None:
    att = _with(PE, "invoice.pdf.exe")
    assert att.extension == "exe"
    assert att.double_extension is True


def test_archive_extensions_are_not_double() -> None:
    assert _with(b"\x1f\x8b\x08\x00", "backup.tar.gz").double_extension is False


def test_right_to_left_override() -> None:
    att = _with(PE, "invoice\u202efdp.exe")
    assert att.bidi_override is True
    assert att.filename == "invoicefdp.exe"
    assert att.extension == "exe"


def test_path_components_are_removed() -> None:
    assert _with(PDF, "../../etc/passwd").filename == "passwd"
    assert _with(PE, "C:\\Users\\x\\evil.exe").filename == "evil.exe"


def test_trailing_dots_and_spaces_are_stripped() -> None:
    att = _with(PE, "evil.exe. ")
    assert att.filename == "evil.exe"
    assert att.extension == "exe"


def test_no_filename() -> None:
    att = _with(PDF, None)
    assert att.filename is None
    assert att.extension == ""


# ---------- archives ----------


def test_zip_members_are_listed() -> None:
    att = _with(_zip({"readme.txt": b"x" * 100, "payload.exe": PE}), "files.zip")
    assert att.detected_type == "zip"
    assert [m.name for m in att.archive_members] == ["readme.txt", "payload.exe"]
    assert att.archive_members[0].size == 100
    assert att.archive_encrypted is False
    assert att.archive_error is None


def test_encrypted_zip_member() -> None:
    att = _with(_mark_encrypted(_zip({"invoice.exe": PE})), "invoice.zip")
    assert att.archive_encrypted is True
    assert att.archive_members[0].encrypted is True


def test_too_many_members() -> None:
    data = _zip({f"f{i}.txt": b"x" for i in range(5)})
    msg = _email()
    msg.add_attachment(data, maintype="application", subtype="zip", filename="many.zip")
    parsed, _ = load_message(bytes(msg))
    (att,) = collect_attachments(parsed, ParseLimits(max_archive_members=3))
    assert att.archive_error == "too_many_members"
    assert len(att.archive_members) == 3


def test_zip_bomb_detected_from_declared_sizes() -> None:
    data = _zip({"zeros.bin": b"\x00" * 10_000})  # compresses to a few bytes
    msg = _email()
    msg.add_attachment(data, maintype="application", subtype="zip", filename="bomb.zip")
    parsed, _ = load_message(bytes(msg))
    (att,) = collect_attachments(parsed, ParseLimits(max_archive_uncompressed_bytes=1000))
    assert att.archive_error == "too_large_uncompressed"


def test_corrupt_zip() -> None:
    att = _with(b"PK\x03\x04" + b"garbage" * 10, "broken.zip")
    assert att.detected_type == "zip"
    assert att.archive_error == "bad_archive"
    assert att.archive_members == ()


def test_oversized_attachment_skips_listing() -> None:
    data = _zip({"a.txt": b"x" * 100})
    msg = _email()
    msg.add_attachment(data, maintype="application", subtype="zip", filename="a.zip")
    parsed, _ = load_message(bytes(msg))
    (att,) = collect_attachments(parsed, ParseLimits(max_attachment_bytes=10))
    assert att.archive_error == "too_large"
    assert att.archive_members == ()
    assert att.sha256 == hashlib.sha256(data).hexdigest()  # still hashed


# ---------- property ----------


@settings(max_examples=300)
@given(st.binary(max_size=4096))
def test_never_raises(data: bytes) -> None:
    with contextlib.suppress(ParseError):
        msg, _ = load_message(
            b"From: a@b.c\r\nContent-Type: application/octet-stream\r\n\r\n" + data
        )
        for att in collect_attachments(msg):
            assert len(att.sha256) == 64
