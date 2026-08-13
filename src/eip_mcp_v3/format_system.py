"""Corpus state and artifact-file presentation."""

from __future__ import annotations

from typing import Any

from .format_common import (
    _COVERAGE_LIMIT,
    _FILE_LIMIT,
    _POINT_LIMIT,
    _SERIES_LIMIT,
    INDEX_BEHIND_CORPUS,
    MANIFEST_UNREACHABLE,
    UNDATED_TOTALS,
    VIEWABILITY_POLICY,
    _date,
    _mapping,
    _number,
    _objects,
    _quantity,
    _wire_value,
)
from .text import (
    UNTRUSTED_NOTE,
    UNTRUSTED_NOTE_SHORT,
    code_block,
    inline,
    one_line,
)

# --------------------------------------------------------------------------
# Corpus statistics and readiness.
# --------------------------------------------------------------------------

_TOTAL_LABELS: tuple[tuple[str, str], ...] = (
    ("Vulnerabilities", "vulnerabilities"),
    ("With artifacts", "with_artifacts"),
    ("With PoCs", "with_pocs"),
    ("CISA KEV listed", "cisa_kev"),
    ("Known ransomware use", "ransomware"),
    ("With Nuclei templates", "with_nuclei"),
)


# The identifier is short, stable and the half of a series a reader can act on, so
# it is written first and given a ceiling of its own. The label is prose and the
# half that gets cut: on `Leading CWEs` every entry's label opens with the same
# forty characters of boilerplate - "Improper Neutralization of Input During Web
# P…" and "Improper Neutralization of Special Elements u…" - so a row rendered from
# the label alone was indistinguishable from the row above it, while `CWE-79` and
# `CWE-89` sat unrendered in the same payload. Both halves are corpus values and
# both stay inert; neither is dropped when the other is present, because deciding
# one is redundant means matching corpus text loosely, and this module does not.
_SERIES_KEY_MAX = 40
_SERIES_LABEL_MAX = 60


def _series_name(entry: dict[str, Any]) -> str:
    """Render a series' identifier and its label, in that order, as inert spans."""
    key = inline(entry.get("key"), max_len=_SERIES_KEY_MAX)
    label = inline(entry.get("label"), max_len=_SERIES_LABEL_MAX)
    return " · ".join(bit for bit in (key, label) if bit) or "(unlabelled series)"


def _render_series(lines: list[str], title: str, entries: Any) -> None:
    """Append one titled group of series, keeping the order and window disclosed."""
    present = _objects(entries)
    if not present:
        return
    lines.append("")
    lines.append(f"## {title}")
    for entry in present[:_SERIES_LIMIT]:
        points = _objects(entry.get("points"))
        shown = points[-_POINT_LIMIT:]
        tail = ", ".join(
            f"{period}={_number(point.get('count'))}"
            for point in shown
            if (period := _date(point.get("period")))
        )
        name = _series_name(entry)
        window = (
            f" (most recent {_number(len(shown))} of {_number(len(points))})"
            if len(points) > len(shown)
            else ""
        )
        lines.append(f"- {name}{window}: {tail}")
    dropped = len(present) - _SERIES_LIMIT
    if dropped > 0:
        lines.append(f"- …{_number(dropped)} more series omitted.")


def _coverage_lines(coverage: Any) -> list[str]:
    """Render per-source PoC date coverage, bounded and disclosed.

    The corpus has a handful of sources today, so the ceiling never bites in
    practice - which is exactly why it has to be here rather than assumed.
    """
    returned = _objects(coverage)
    rows = []
    for row in returned[:_COVERAGE_LIMIT]:
        source = inline(row.get("source"), max_len=40)
        dated = _number(row.get("dated"))
        total = _number(row.get("total"))
        if dated and total:
            rows.append(f"- {source or '(unnamed source)'}: {dated} dated of {total}")
    if not rows:
        return []
    lines = ["", "### PoC date coverage"]
    omitted = len(returned) - len(rows)
    if omitted > 0:
        lines.append(
            f"Showing {_number(len(rows))} of {_number(len(returned))} source(s) returned; "
            f"{_number(omitted)} omitted."
        )
    lines.extend(rows)
    return lines


def format_statistics(totals: dict[str, Any], trends: dict[str, Any] | None, series: str) -> str:
    """Render corpus totals, and optionally one or more trend series."""
    totals = _mapping(totals)
    trends = _mapping(trends)
    # The short note, not the full paragraph: this page renders no corpus prose and
    # no corpus source, only counts and short identifiers inside code spans. See
    # `UNTRUSTED_NOTE_SHORT` for what that buys and what it must not drop.
    lines = ["# EIP corpus statistics", "", UNTRUSTED_NOTE_SHORT, ""]
    lines.extend(
        f"- {label}: {rendered}"
        for label, key in _TOTAL_LABELS
        if key in totals and (rendered := _number(totals[key]))
    )
    if not trends or series == "none":
        # The totals endpoint carries no date, no checkpoint and no read-model
        # version, so the default call renders six bare numbers a reader cannot
        # date. EIP cannot supply one - inventing "as of today" would be a claim
        # about the corpus this response does not support - but leaving the page
        # silent lets the numbers be quoted as current indefinitely. So it says
        # what it does not know, and names the surface that does know.
        lines.extend(("", UNDATED_TOTALS))
        return "\n".join(lines)

    as_of = _date(trends.get("as_of"))
    lines.append("")
    lines.append(
        (f"Trends as of {as_of}. " if as_of else "Trends. ")
        + "CISA and VulnCheck values are catalog-addition dates, "
        "not first-exploitation dates."
    )

    if series in ("cve_published", "all"):
        _render_series(lines, "CVEs published (completed months)", [trends.get("cve_published")])
    if series in ("cwe", "all"):
        _render_series(lines, "Leading CWEs", trends.get("cve_weaknesses"))
    if series in ("catalog_additions", "all"):
        _render_series(
            lines, "Catalog additions (completed months)", trends.get("catalog_additions")
        )
    if series in ("poc_supply", "all"):
        _render_series(lines, "PoC supply (completed quarters)", trends.get("poc_supply"))
        lines.extend(_coverage_lines(trends.get("poc_date_coverage")))
    return "\n".join(lines)


_READINESS_FIELDS: tuple[tuple[str, str], ...] = (
    ("Status", "status"),
    ("Read model", "read_model_version"),
    ("API policy revision", "api_policy_revision"),
    ("Source checkpoint", "source_checkpoint_sha256"),
    ("Projection built at", "built_at"),
)


def format_readiness(data: dict[str, Any]) -> str:
    """Render deployment readiness, reporting the code-search index separately."""
    data = _mapping(data)
    # The short note. This page is EIP's own words plus a handful of deployment
    # identifiers in code spans; the full paragraph was about half of it.
    lines = ["# EIP corpus readiness", "", UNTRUSTED_NOTE_SHORT, ""]
    lines.extend(
        f"- {label}: {value}"
        for label, key in _READINESS_FIELDS
        if (value := inline(data.get(key), max_len=88))
    )
    read_only = _wire_value(data.get("database_read_only"), max_len=16)
    if read_only:
        lines.append(f"- Database read-only: {read_only}")

    lines.append("")
    lines.append("## Code search subsystem")
    status = inline(data.get("code_search_status"), max_len=32)
    if not status:
        lines.append("- Not reported by this deployment.")
        return "\n".join(lines)
    lines.append(f"- Status: {status}")
    built_at = inline(data.get("code_search_built_at"), max_len=40)
    if built_at:
        lines.append(f"- Index built at: {built_at}")
    # The one field that says *what* the index was built from. `code_search_status:
    # ready` is subsystem health - an index built from a stale checkpoint reports
    # `ready` exactly like a current one, and this page's own tool description
    # promises it distinguishes an empty result from a degraded index. Without the
    # checkpoint the two build times sit side by side with nothing reconciling them,
    # and an empty `search_exploit_code` result reads as corpus absence.
    index_checkpoint = inline(data.get("code_search_checkpoint_sha256"), max_len=88)
    if index_checkpoint:
        lines.append(f"- Index checkpoint: {index_checkpoint}")
        source_checkpoint = inline(data.get("source_checkpoint_sha256"), max_len=88)
        if source_checkpoint and source_checkpoint != index_checkpoint:
            lines.append(f"- {INDEX_BEHIND_CORPUS}")
    for label, key in (
        ("Artifacts indexed", "code_search_artifact_count"),
        ("Files indexed", "code_search_file_count"),
    ):
        rendered = _number(data.get(key))
        if rendered:
            lines.append(f"- {label}: {rendered}")
    if data.get("code_search_status") != "ready":
        lines.append(
            "- Code search will fail closed while the index is not ready. "
            "Metadata tools are unaffected."
        )
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Artifact files.
# --------------------------------------------------------------------------


def format_file_list(data: dict[str, Any]) -> str:
    """Render the file manifest of one artifact, in the order returned, bounded.

    A manifest is one collection with no page size of its own, and a repository
    artifact can hold tens of thousands of paths. The ceiling is disclosed rather
    than silent: a truncated list a reader believes is complete is worse than a
    short one that says so.
    """
    data = _mapping(data)
    listing = data.get("items")
    items = _objects(listing)
    artifact_id = inline(data.get("artifact_id"), max_len=128)
    head = f"# Files in artifact {artifact_id}" if artifact_id else "# Files in artifact"
    # A response with no `items` at all is not a response of "0 files": one says
    # the manifest did not arrive, the other says the artifact is empty.
    count = f"{_number(len(items))} returned" if isinstance(listing, list) else "no file list"
    lines = [
        f"{head} - {count}",
        "Pass a `path` to `read_exploit_file` to read one viewable text file.",
        VIEWABILITY_POLICY,
        "",
        UNTRUSTED_NOTE,
        "",
    ]
    shown = items[:_FILE_LIMIT]
    omitted = len(items) - len(shown)
    if omitted > 0:
        # `read_exploit_file` takes only `artifact_id` and `path` - no cursor, no
        # offset - so the omitted paths are not reachable through this tool at all.
        # Saying only "299 omitted" invited a reader to look for the knob that
        # would show them, and, worse, let a screening pass treat a partial
        # manifest as the whole artifact.
        lines.append(
            f"Showing the first {_number(len(shown))} of {_number(len(items))}; "
            f"{_number(omitted)} omitted. {MANIFEST_UNREACHABLE}"
        )
    for item in shown:
        path = inline(item.get("path"), max_len=300)
        viewable = "viewable" if item.get("viewable") else "not viewable"
        detail = ", ".join(bit for bit in (_quantity(item.get("size"), "bytes"), viewable) if bit)
        lines.append(f"- {path or '(path not returned)'} - {detail}")
    if data.get("truncated"):
        lines.append("- …more files exist than this response returned.")
    return "\n".join(lines)


def format_file_content(data: dict[str, Any]) -> str:
    """Render one artifact file as a fenced, labelled, inert block.

    The extension is read off the flattened path rather than the rendered span:
    splitting the span would cut off its closing delimiter. It is a hint for
    ``code_block`` to resolve, not a value rendered as itself - the path it came
    from is already on the heading line as a span.
    """
    data = _mapping(data)
    path = one_line(data.get("path"), max_len=300)
    suffix = path.rsplit(".", 1)[-1] if "." in path else ""
    lines = [f"# File {inline(path, max_len=300)}".rstrip()]
    artifact_id = inline(data.get("artifact_id"), max_len=128)
    if artifact_id:
        lines.append(f"artifact_id: {artifact_id}")
    sha256 = inline(data.get("sha256"), max_len=88)
    if sha256:
        lines.append(f"sha256: {sha256}")
    lines.extend(("", UNTRUSTED_NOTE, ""))
    lines.extend(code_block(data.get("content") or "", language=suffix, max_len=40_000))
    return "\n".join(lines)
