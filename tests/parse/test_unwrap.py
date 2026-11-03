"""Tests for phishtriage.parse.unwrap.unwrap_report."""

from email.message import EmailMessage

import pytest

from phishtriage.parse.errors import NotAnEmail
from phishtriage.parse.intake import load_message
from phishtriage.parse.limits import ParseLimits
from phishtriage.parse.unwrap import UnwrapResult, unwrap_report

# ---------- builders ----------


def _email(
    subject: str, sender: str = "mallory@evil.test", body: str = "click here"
) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = "victim@example.com"
    msg["Subject"] = subject
    msg.set_content(body)
    return msg


def _wrap(inner: EmailMessage, subject: str) -> EmailMessage:
    """A reporter's email with `inner` attached as message/rfc822."""
    outer = _email(subject, sender="Reporter <reporter@example.com>", body="Reporting this")
    outer.add_attachment(inner)
    return outer


def _parse(msg: EmailMessage) -> EmailMessage:
    """Round-trip through bytes so tests run on parsed messages, like real input."""
    parsed, _ = load_message(bytes(msg))
    return parsed


# ---------- not a report ----------


def test_plain_email_is_not_a_report() -> None:
    msg = _parse(_email("hello"))
    result = unwrap_report(msg)
    assert isinstance(result, UnwrapResult)
    assert result.layers == 0
    assert result.message is msg
    assert result.reporter is None
    assert result.wrapper_subject is None
    assert result.candidates == 0


def test_other_attachments_are_not_candidates() -> None:
    outer = _email("Quarterly report", sender="alice@example.com")
    outer.add_attachment(
        b"%PDF-1.7 fake", maintype="application", subtype="pdf", filename="report.pdf"
    )
    msg = _parse(outer)
    result = unwrap_report(msg)
    assert result.layers == 0
    assert result.candidates == 0
    assert result.message is msg


# ---------- unwrapping ----------


def test_unwraps_attached_rfc822() -> None:
    result = unwrap_report(_parse(_wrap(_email("Your account is locked"), "FW: suspicious")))
    assert result.layers == 1
    assert result.candidates == 1
    assert result.message["Subject"] == "Your account is locked"
    assert result.reporter is not None
    assert "reporter@example.com" in result.reporter
    assert result.wrapper_subject == "FW: suspicious"


@pytest.mark.parametrize("filename", ["suspicious.eml", "SUSPICIOUS.EML"])
def test_unwraps_eml_file_attachment(filename: str) -> None:
    outer = _email("FW: check this", sender="reporter@example.com", body="see attached")
    outer.add_attachment(
        bytes(_email("Invoice overdue")),
        maintype="application",
        subtype="octet-stream",
        filename=filename,
    )
    result = unwrap_report(_parse(outer))
    assert result.layers == 1
    assert result.message["Subject"] == "Invoice overdue"


def test_unwraps_nested_forwards() -> None:
    twice = _wrap(_wrap(_email("Original phish"), "FW: one"), "FW: two")
    result = unwrap_report(_parse(twice))
    assert result.layers == 2
    assert result.message["Subject"] == "Original phish"
    assert result.wrapper_subject == "FW: two"  # outermost wrapper


def test_respects_max_unwrap_layers() -> None:
    twice = _wrap(_wrap(_email("Original phish"), "FW: one"), "FW: two")
    result = unwrap_report(_parse(twice), ParseLimits(max_unwrap_layers=1))
    assert result.layers == 1
    assert result.message["Subject"] == "FW: one"


# ---------- ambiguity and failure ----------


def test_two_attached_emails_are_ambiguous() -> None:
    outer = _email("FW: two things", sender="reporter@example.com")
    outer.add_attachment(_email("first"))
    outer.add_attachment(_email("second"))
    msg = _parse(outer)
    result = unwrap_report(msg)
    assert result.layers == 0
    assert result.candidates == 2
    assert result.message is msg


def test_corrupt_eml_attachment_raises() -> None:
    outer = _email("FW: broken", sender="reporter@example.com")
    outer.add_attachment(
        b"\x00\x01 not an email",
        maintype="application",
        subtype="octet-stream",
        filename="broken.eml",
    )
    with pytest.raises(NotAnEmail, match="not_an_email"):
        unwrap_report(_parse(outer))


# ---------- header safety ----------


def test_reporter_and_subject_are_truncated() -> None:
    outer = _wrap(_email("inner"), "FW: " + "S" * 200)
    del outer["From"]
    outer["From"] = "A" * 200 + " <reporter@example.com>"
    result = unwrap_report(_parse(outer), ParseLimits(max_header_value_chars=20))
    assert result.reporter is not None
    assert len(result.reporter) <= 20
    assert result.wrapper_subject is not None
    assert len(result.wrapper_subject) <= 20


def test_missing_wrapper_subject_is_none() -> None:
    outer = _wrap(_email("inner"), "FW: x")
    del outer["Subject"]
    result = unwrap_report(_parse(outer))
    assert result.layers == 1
    assert result.wrapper_subject is None


def test_eml_named_multipart_part_raises() -> None:
    raw = (
        b"From: reporter@example.com\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=OUT\r\n\r\n"
        b"--OUT\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"
        b"--OUT\r\n"
        b"Content-Type: multipart/mixed; boundary=IN\r\n"
        b'Content-Disposition: attachment; filename="weird.eml"\r\n\r\n'
        b"--IN\r\nContent-Type: text/plain\r\n\r\nx\r\n--IN--\r\n"
        b"--OUT--\r\n"
    )
    msg, _ = load_message(raw)
    with pytest.raises(NotAnEmail, match="not_an_email"):
        unwrap_report(msg)
