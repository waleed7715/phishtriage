"""Shared fixtures for parser tests."""

from email.message import EmailMessage

import pytest


@pytest.fixture
def minimal_email() -> bytes:
    """A small, valid, single-part email."""
    msg = EmailMessage()
    msg["From"] = "alice@example.com"
    msg["To"] = "bob@example.com"
    msg["Subject"] = "hello"
    msg.set_content("plain body")
    return bytes(msg)
