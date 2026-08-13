"""Dependency-neutral primitives shared by focused EIP renderers."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol

from .text import inline, one_line

_AUTHOR_ROLE_LABELS = {"author": "Author", "owner": "Repository owner"}
_SERIES_LIMIT = 8
_POINT_LIMIT = 12
_FILE_LIMIT = 200
_COVERAGE_LIMIT = 20
CURSOR_MAX_CHARS = 2048

VIEWABILITY_POLICY = (
    "Viewability is the API's decision: a file is viewable only when it is at most "
    "1 MiB and its extension or filename is in the API's text allowlist, and its "
    "bytes decode as UTF-8. A small text file can be non-viewable for its extension "
    "alone."
)

INDEX_BEHIND_CORPUS = (
    "This checkpoint differs from the corpus source checkpoint above: the index "
    "was built from a different snapshot, so a code-search result may omit "
    "artifacts the rest of this server can see. EIP states the difference and "
    "makes no claim about which is newer."
)

UNDATED_TOTALS = (
    "These totals carry no date: the API returns them without a checkpoint or a "
    "build time. Call `get_corpus_readiness` for the corpus checkpoint and "
    "projection build time to date any figure quoted from this page."
)

MANIFEST_UNREACHABLE = (
    "This tool takes no cursor or offset, so the omitted paths cannot be listed "
    "through it; a known path can still be read directly with `path`. Anything "
    "screening this artifact has not seen them."
)


def _mapping(value: Any) -> dict[str, Any]:
    """Return an API object, or an empty object for a malformed nested shape."""

    return value if isinstance(value, dict) else {}


def _objects(value: Any) -> list[dict[str, Any]]:
    """Return only object entries from an API collection."""

    if not isinstance(value, list):
        return []
    return [entry for entry in value if isinstance(entry, dict)]


def _sequence(value: Any) -> list[Any]:
    """Return list entries, tolerating one documented scalar value."""

    if isinstance(value, list):
        return value
    return [] if value is None or value == "" else [value]


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _number(value: Any) -> str:
    count = _count(value)
    return f"{count:,}" if count is not None else inline(value, max_len=24)


def _plain(value: Any) -> str:
    count = _count(value)
    return str(count) if count is not None else inline(value, max_len=24)


def _quantity(value: Any, plural: str, singular: str | None = None) -> str:
    rendered = _number(value)
    if not rendered:
        return ""
    if _count(value) == 1:
        noun = singular if singular is not None else plural.removesuffix("s")
    else:
        noun = plural
    return f"{rendered} {noun}"


def _wire_value(value: Any, *, max_len: int = 88) -> str:
    if isinstance(value, bool):
        return inline("true" if value else "false", max_len=max_len)
    return inline(value, max_len=max_len)


def _date(value: Any) -> str:
    text = one_line(value, max_len=40)
    return inline(text.split("T")[0], max_len=40) if text else ""


def _labelled(item: dict[str, Any], fields: Sequence[tuple[str, str, int]]) -> list[str]:
    return [
        f"{label} {span}"
        for label, key, ceiling in fields
        if (span := inline(item.get(key), max_len=ceiling))
    ]


class _PointerRegistry(Protocol):
    def pointer(self, value: Any) -> str: ...


_POINTER_MAX = 200
_SOURCE_FIELDS: tuple[tuple[str, str, int], ...] = (
    ("source", "source", 60),
    ("provider", "provider", 60),
)
_POINTER_FIELD: tuple[str, str, int] = ("pointer", "pointer", _POINTER_MAX)
_PROVENANCE_FIELDS: tuple[tuple[str, str, int], ...] = (*_SOURCE_FIELDS, _POINTER_FIELD)


def format_provenance(prov: Any, records: _PointerRegistry | None = None) -> str:
    item = _mapping(prov)
    if records is None:
        bits = _labelled(item, _PROVENANCE_FIELDS)
    else:
        bits = _labelled(item, _SOURCE_FIELDS)
        if fragment := records.pointer(item.get("pointer")):
            bits.append(fragment)
    return f" - {', '.join(bits)}" if bits else ""


_CURSOR_INSTRUCTION = (
    "More results available (next_cursor). Pass this value back verbatim as `cursor`, "
    "and repeat the rest of the call unchanged - every filter and the same `limit`. "
    "The cursor is bound to the query that produced it, so changing any of them is "
    "refused rather than silently re-paged:"
)

# ``inline`` counts dynamically sized delimiters in its ceiling. In the worst case
# an opaque 2,048-character cursor is itself all backticks, requiring a delimiter one
# character longer on each side plus padding. This ceiling preserves every valid
# cursor byte-for-byte instead of putting a truncated value beside "pass verbatim".
_CURSOR_SPAN_MAX_CHARS = CURSOR_MAX_CHARS * 3 + 4


def _cursor_line(data: dict[str, Any]) -> list[str]:
    cursor = inline(data.get("next_cursor"), max_len=_CURSOR_SPAN_MAX_CHARS)
    if not cursor:
        return ["", "No further pages."]
    return ["", _CURSOR_INSTRUCTION, cursor]
