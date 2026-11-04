import re
from dataclasses import dataclass

from bs4 import (
    BeautifulSoup,
    CData,
    Comment,
    Declaration,
    Doctype,
    ProcessingInstruction,
)
from bs4.element import NavigableString, PageElement, Tag

_BLOCK_ELEMENTS = {
    "p",
    "div",
    "br",
    "li",
    "tr",
    "table",
    "ul",
    "ol",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "blockquote",
    "section",
    "article",
    "header",
    "footer",
    "hr",
}

_ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\u2060\ufeff\u00ad"

_DROPPED_ELEMENTS = {
    "script",
    "style",
    "head",
    "title",
    "template",
}

_ZERO_VALUE_RE = re.compile(
    r"^[+-]?(?:0+(?:\.0*)?|\.0+)(?:px|pt|em|rem|%)?$",
    re.IGNORECASE,
)

_ZW_TABLE = str.maketrans("", "", _ZERO_WIDTH_CHARS)


@dataclass(frozen=True, slots=True)
class HiddenSpan:
    text: str
    reason: str


@dataclass(frozen=True, slots=True)
class HtmlText:
    """Represents the text extracted from an HTML document."""

    visible: str
    hidden: tuple[HiddenSpan, ...]
    zero_width_chars: int
    truncated: bool
    parse_failed: bool


def _remove_zero_width(text: str) -> tuple[str, int]:
    count = sum(text.count(char) for char in _ZERO_WIDTH_CHARS)
    text = text.translate(_ZW_TABLE)
    return text, count


def _parse_inline_style(tag: Tag) -> dict[str, str]:
    style = tag.get("style")

    if not isinstance(style, str):
        return {}

    declarations: dict[str, str] = {}

    for declaration in style.split(";"):
        if ":" not in declaration:
            continue

        name, value = declaration.split(":", 1)
        name = name.strip().lower()
        value = re.sub(r"\s*!important\s*$", "", value, flags=re.IGNORECASE).strip().lower()

        if name and value:
            declarations[name] = value

    return declarations


def _is_zero_value(value: str | None) -> bool:
    return value is not None and bool(_ZERO_VALUE_RE.fullmatch(value))


def _hidden_reason(tag: Tag) -> str | None:
    # 1. HTML hidden attribute
    if tag.has_attr("hidden"):
        return "html_hidden_attr"

    style = _parse_inline_style(tag)

    # 2. display: none
    if style.get("display") == "none":
        return "css_display_none"

    # 3. visibility: hidden or collapse
    if style.get("visibility") in {"hidden", "collapse"}:
        return "css_visibility_hidden"

    # 4. Outlook mso-hide
    if style.get("mso-hide") == "all":
        return "css_mso_hide"

    # 5. opacity: zero
    if _is_zero_value(style.get("opacity")):
        return "css_opacity_zero"

    # 6. font-size: zero
    if _is_zero_value(style.get("font-size")):
        return "css_zero_font"

    # 7. Zero dimensions combined with overflow: hidden
    if style.get("overflow") == "hidden" and any(
        _is_zero_value(style.get(dimension)) for dimension in ("width", "height", "max-height")
    ):
        return "css_zero_size"

    # 8. Same foreground and background colors
    color = style.get("color")
    background_color = style.get("background-color")

    if color and background_color and color == background_color:
        return "css_same_color"

    return None


def normalize_visible_text(text: str) -> str:
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in text.splitlines()]

    return "\n".join(line for line in lines if line)


def split_html(html: str, max_chars: int) -> HtmlText:
    """Splits an HTML document into visible and hidden text."""

    visible: list[str] = []
    hidden: list[HiddenSpan] = []
    zero_width_chars = 0
    truncated = False

    hidden_remaining = max_chars

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return HtmlText("", (), 0, False, True)

    stack: list[PageElement] = [soup]

    while stack:
        current = stack.pop()

        if isinstance(current, Tag) and current.name in _DROPPED_ELEMENTS:
            continue

        if isinstance(current, Comment):
            text, removed = _remove_zero_width(str(current))
            zero_width_chars += removed
            text = re.sub(r"\s+", " ", text).strip()

            if text:
                if hidden_remaining <= 0:
                    truncated = True

                elif len(text) > hidden_remaining:
                    hidden.append(HiddenSpan(text=text[:hidden_remaining], reason="html_comment"))
                    hidden_remaining = 0
                    truncated = True

                else:
                    hidden.append(HiddenSpan(text=text, reason="html_comment"))
                    hidden_remaining -= len(text)

            continue

        if isinstance(current, (CData, Declaration, Doctype, ProcessingInstruction)):
            continue

        if isinstance(current, Tag):
            reason = _hidden_reason(current)

            if reason is not None:
                text = current.get_text(" ")
                text, removed = _remove_zero_width(text)
                zero_width_chars += removed
                text = re.sub(r"\s+", " ", text).strip()

                if text:
                    if hidden_remaining <= 0:
                        truncated = True

                    elif len(text) > hidden_remaining:
                        hidden.append(HiddenSpan(text=text[:hidden_remaining], reason=reason))
                        hidden_remaining = 0
                        truncated = True

                    else:
                        hidden.append(HiddenSpan(text=text, reason=reason))
                        hidden_remaining -= len(text)

                continue

            if current.name in _BLOCK_ELEMENTS:
                visible.append("\n")

            stack.extend(reversed(current.contents))
            continue

        if isinstance(current, NavigableString):
            text, removed = _remove_zero_width(str(current))
            zero_width_chars += removed
            visible.append(text)

    visible_text = normalize_visible_text("".join(visible))
    truncated = truncated or len(visible_text) > max_chars

    visible_text = visible_text[:max_chars]

    return HtmlText(
        visible=visible_text,
        hidden=tuple(hidden),
        zero_width_chars=zero_width_chars,
        truncated=truncated,
        parse_failed=False,
    )
