import pytest

from phishtriage.parse.errors import (
    InputTooLarge,
    MimeTooDeep,
    NotAnEmail,
    ParseError,
    TooManyParts,
)

ERRORS_AND_REASONS = [
    (InputTooLarge, "input_too_large"),
    (TooManyParts, "too_many_parts"),
    (MimeTooDeep, "mime_too_deep"),
    (NotAnEmail, "not_an_email"),
    (ParseError, "parse_error"),
]

ALL_ERRORS = [cls for cls, _ in ERRORS_AND_REASONS]


def test_parse_error_inherits_from_exception() -> None:
    assert issubclass(ParseError, Exception)


@pytest.mark.parametrize("cls", ALL_ERRORS)
def test_parse_errors_inherit_from_parse_error(cls: type[ParseError]) -> None:
    assert issubclass(cls, ParseError)


@pytest.mark.parametrize(
    ("cls", "reason"),
    ERRORS_AND_REASONS,
)
def test_reason_code(cls: type[ParseError], reason: str) -> None:
    assert cls.reason == reason


@pytest.mark.parametrize(
    ("cls", "reason"),
    ERRORS_AND_REASONS,
)
def test_instance_reason_and_message(cls: type[ParseError], reason: str) -> None:
    err = cls("bad input")
    assert err.reason == reason
    assert str(err) == f"{reason}: bad input"


@pytest.mark.parametrize("cls", ALL_ERRORS)
def test_details_stored(cls: type[ParseError]) -> None:
    assert cls("detail").detail == "detail"


@pytest.mark.parametrize("cls", ALL_ERRORS)
def test_base_class_catches_subclasses(cls: type[ParseError]) -> None:
    with pytest.raises(ParseError):
        raise cls("detail")
