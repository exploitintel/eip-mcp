"""Every declared parameter must demonstrably take effect. Live API required.

    EIP_MCP_TEST_API_BASE_URL=https://exploit-intel.com pytest tests/test_live_parameter_effects.py

Why this file exists, stated plainly so it is never weakened back into a smoke
test: a call that returns a well-formed page proves nothing about the arguments
that produced it. ``search_vulnerabilities(query="struts", min_cvss=9.0)``
returned a perfect page for weeks while ``min_cvss`` was silently discarded,
because ``min_cvss`` was never a parameter and the SDK dropped it. Asserting
"the call succeeded" would have passed throughout.

So no test here asserts success. Each one pins a parameter to an *observable
consequence* and fails if the consequence is absent:

* a filter must hold on **every** row returned, not merely somewhere on the page;
* a sort must produce a monotonic key across the page;
* a pagination cursor must yield a disjoint page;
* a selector must change the page relative to the same call without it;
* an enum must be accepted at every declared value and refused outside them.

``tests/test_declared_arguments.py`` covers the other half - that a name this
server does not declare is refused rather than dropped. Together they are what
lets coverage be stated as a count instead of an impression.
"""

from __future__ import annotations

import os
import re

import pytest

from eip_mcp_v3 import format as fmt
from eip_mcp_v3.api_client import EipApiClient
from eip_mcp_v3.config import Settings
from eip_mcp_v3.errors import ApiError
from eip_mcp_v3.tools import (
    ASSOCIATIONS,
    AUTHOR_ROLES,
    AUTHOR_SOURCES,
    CATALOG_KINDS,
    LAB_ANALYSIS,
    LAB_ASSOCIATIONS,
    LAB_KINDS,
    POC_SOURCES,
    SEVERITIES,
    SORTS,
    TREND_SERIES,
    EipTools,
)

# Every heading `format_labs._analysis` can emit. Matching only two of them
# read a stored analysis as absent whenever one of the others was the only
# heading rendered.
_ANALYSIS_MARKERS = (
    "Model-reported",
    "Model-stated",
    "Model safety reasoning",
    "Model assessment",
    "Model environment summary",
    "Model suspicious indicator",
)


def lab_rows(page: str) -> list[dict]:
    rows = []
    for block in _blocks(page, "Lab"):
        rows.append(
            {
                # The identity line is anchor_kind, then shape, then counts.
                # Reading a fixed position captured `shape` while the assertion
                # below and its comment both mean `anchor_kind`; both happen to
                # contain the family word, so the mistake never showed. Keep
                # every span and let the caller match against all of them.
                "kinds": _bare_spans(_span_first_bits(block)),
                # Both read the whole block before, so a repository title
                # containing either phrase forged them.
                "linked": not any(
                    _unspanned(line).strip() == "Linked vulnerabilities: none returned"
                    for line in _row_lines(block)
                ),
                # `_analysis` can emit any one of these headings alone, so
                # matching only two of them read a stored analysis as absent.
                # The whole-row scan and the quote skip are defence in depth:
                # the first heading always precedes any blank line, and a
                # "> "-prefixed body line cannot start with a marker anyway.
                "analysis": any(
                    _unspanned(line).startswith(_ANALYSIS_MARKERS)
                    for line in block.splitlines()[1:]
                    if not line.lstrip().startswith(">")
                ),
            }
        )
    return rows

BASE_URL = os.environ.get("EIP_MCP_TEST_API_BASE_URL")

pytestmark = pytest.mark.skipif(
    not BASE_URL, reason="set EIP_MCP_TEST_API_BASE_URL to run live tests"
)


@pytest.fixture
async def tools():
    settings = Settings.from_env({"EIP_API_BASE_URL": BASE_URL})
    client = EipApiClient(settings)
    yield EipTools(client, settings)
    await client.aclose()


# --------------------------------------------------------------------------
# Parsers for the rendered page. Deliberately reading what the client reads.
# --------------------------------------------------------------------------

_NUM = r"[\d,]+(?:\.\d+)?"


def _n(text: str) -> float:
    return float(text.replace(",", ""))


_FENCED = re.compile(r"(?m)^(`{3,})[^\n]*\n.*?^\1[ \t]*$", re.S)


def _outside_fences(page: str) -> str:
    """Blank fenced regions, keeping the line count.

    `code_block()` writes corpus source at column 0, so a snippet containing
    "## Match in ` … `" injected a phantom row with an attacker-chosen path and
    source, and a snippet echoing the cursor sentence forged the cursor this
    suite then sent back to the API. Page-level patterns must not read inside a
    fence.
    """
    return _FENCED.sub(lambda m: "\n" * m.group(0).count("\n"), page)


def _truncated(page: str) -> bool:
    return "truncated at" in page


def _expect_parsed(page: str, blocks: list, rows: list, what: str) -> None:
    """Every block the renderer emitted must parse.

    `cap()` cuts at a character offset, so a truncated page's final block is
    routinely half a row. Tolerate that one, and only that one: dropping rows
    quietly is what made a parser fault read as "returned nothing".
    """
    allowed = 1 if _truncated(page) else 0
    missing = len(blocks) - len(rows)
    assert missing <= allowed, (
        f"{missing} of {len(blocks)} {what} row(s) did not parse; the renderer "
        "and this parser disagree"
    )


def _blocks(page: str, *headings: str) -> list[str]:
    """Split a rendered page into one string per result row.

    Pass every heading label the surface can emit; a page may mix them, as the
    CWE directory does with Weakness, Category and View.

    A heading this parser does not know used to surface as an empty row list,
    which callers then reported as "returned nothing" - indistinguishable from
    the API genuinely having no data, and wrong. If the page carries result
    headings but none is one we asked for, either the renderer changed or this
    parser is reading the wrong page. Say so rather than returning nothing.
    """
    pattern = "|".join(re.escape(h) for h in headings)
    parts = re.split(rf"(?m)^## (?:{pattern}) ", _outside_fences(page))
    # `cap()` cuts at a character offset, so it can slice a heading in half. A
    # truncated page cannot testify about the renderer's headings.
    if len(parts) == 1 and not _truncated(page):
        present = re.findall(r"(?m)^## (.+)$", page)
        if present:
            shown = [h[:80] for h in present[:3]]
            raise AssertionError(
                f"no '## {' / '.join(headings)} ' rows, but the page renders "
                f"{len(present)} heading(s): {shown}. Either the renderer's "
                "heading changed, or this parser is reading the wrong page."
            )
    return parts[1:]


def vuln_rows(page: str) -> list[dict]:
    rows = []
    for block in _blocks(page, "Vulnerability"):
        cve = re.match(r"` ([^`]+) `", block)
        published = re.match(r"` [^`]+ ` \(` ([^`]+) `\)", block)
        # `CVSS ` v4.0 ` ` 8.6 ` ` HIGH `` - the version span is present whenever
        # the record carries one, so both of these skip it optionally rather than
        # assuming a fixed number of spans.
        cvss = re.search(rf"^CVSS (?:` v[\d.]+ ` )?` ({_NUM}) `", block, re.M)
        sev = re.search(r"^CVSS (?:` v[\d.]+ ` )?` [^`]+ ` ` ([A-Z]+) `", block, re.M)
        version = re.search(r"^CVSS ` v([\d.]+) `", block, re.M)
        # These four read the whole block before, so a corpus title containing
        # "EPSS ` 0.99999 `", "4242 Nuclei templates", "CISA KEV listed" or
        # "known ransomware use" forged them. The title is a code span, so
        # blanking spans leaves only labels this renderer wrote.
        # `_unspanned` decides whether a label is one this renderer wrote; the
        # value itself lives inside the span, so read it from the original line.
        epss_value = next(
            (
                value
                for line in _row_lines(block)
                if (value := _labelled_span(line, "EPSS"))
            ),
            None,
        )
        counts = "\n".join(_unspanned(line) for line in _row_lines(block))
        pocs = re.search(rf"(?m)^({_NUM}) linked PoCs?", counts)
        nuclei = re.search(rf"({_NUM}) Nuclei templates?", counts)
        rows.append(
            {
                "cve": cve.group(1) if cve else None,
                "published": published.group(1) if published else None,
                "cvss": _n(cvss.group(1)) if cvss else None,
                "severity": sev.group(1) if sev else None,
                "cvss_version": version.group(1) if version else None,
                "epss": _n(epss_value) if epss_value else None,
                "pocs": _n(pocs.group(1)) if pocs else 0.0,
                "nuclei": _n(nuclei.group(1)) if nuclei else 0.0,
                "kev": "CISA KEV listed" in counts,
                "ransomware": "known ransomware use" in counts,
            }
        )
    return rows


# `inline()` escalates the code-span delimiter when the value itself contains a
# backtick, so a fixed single backtick silently fails to match those rows.
_SPAN = r"(`+) (.+?) \1"
# `inline()` appends this outside the closing delimiter when it shortens a value.
_CUT = r"(?: …truncated| …)?"

# `inline()` marks a value it had to shorten outside the closing delimiter, so
# the marker lands on a bit that is otherwise a bare span.
_BIT = re.compile(rf"{_SPAN}{_CUT}$")


_SPAN_RE = re.compile(_SPAN)


def _unspanned(line: str) -> str:
    """The line with its code spans blanked, character for character.

    Labels are rendered outside spans and corpus values inside them, so a
    "source date ` … `" forged inside a corpus value vanishes here while the
    real label survives. Blanking preserves length so an offset found in the
    blanked line still points at the same character in the original.
    """
    return _SPAN_RE.sub(lambda m: " " * len(m.group(0)), line)


def _labelled_span(line: str, label: str) -> str | None:
    """The span following `label`, where `label` is one this renderer wrote.

    Reading the value with a plain search finds the leftmost match, so a corpus
    span rendered earlier on the same line wins - `language` set to
    "source date ` 1999-01-01 `" forged the artifact's date. Locate the label
    in the blanked line, then read the value at exactly that offset.
    """
    for m in re.finditer(re.escape(label), _unspanned(line)):
        value = re.compile(rf"{re.escape(label)} {_SPAN}").match(line, m.start())
        if value:
            return value.group(2)
    return None


def _row_lines(block: str) -> list[str]:
    """The lines belonging to this row.

    `_blocks` splits on the heading, so line 0 is the heading tail, which
    carries the row's own identity rather than its facts. The final block also
    runs to the end of the page and would otherwise pick up the cursor line, so
    stop at the blank line that separates a row from what follows it.
    """
    lines = []
    for line in block.splitlines()[1:]:
        if not line.strip():
            break
        lines.append(line)
    return lines


def _span_first_bits(block: str) -> list[str]:
    """The row's first " · "-joined line that begins with a bare span."""
    for line in _row_lines(block):
        if re.match(rf"{_SPAN}(?: · | \[|$)", line):
            return line.split(" · ")
    return []


def _bare_spans(bits: list[str]) -> list[str]:
    """The bits that are nothing but a code span, as their values.

    Both callers split on " · " first, so a bit cannot hold two whole spans.
    """
    return [m.group(2) for bit in bits if (m := _BIT.fullmatch(bit.strip()))]


def artifact_rows(page: str) -> list[dict]:
    rows = []
    for block in _blocks(page, "Artifact"):
        # The heading is "` #id ` · ` source `", but `_artifact_heading` drops
        # the id span when the record has no public_id. `_public_id_span`
        # always renders "#<id>", so pick the span that is not one rather than
        # trusting a position - otherwise a record with no source reports its
        # own public id as the source.
        heading = _bare_spans(block.splitlines()[0].split(" · ")) if block else []
        source = next((s for s in reversed(heading) if not s.startswith("#")), None)
        # `catalog_kind` and `language` are deliberately not read. The renderer
        # emits them as bare spans in a " · " chain whose every other member
        # carries a word, so recovering which is which means guessing - by
        # position, by neighbour, or by a client-side closed set. All three
        # were tried and all three returned wrong values. They come back when
        # `format.py` labels them the way it labels provider, counts and date.
        date = next(
            (
                value
                for line in _row_lines(block)
                if (value := _labelled_span(line, "source date"))
            ),
            None,
        )
        rows.append(
            {
                "artifact_id": next(
                    (
                        m.group(2)
                        for line in _row_lines(block)
                        if _unspanned(line).lstrip().startswith("artifact_id:")
                        and (m := re.search(rf"artifact_id: {_SPAN}", line))
                    ),
                    None,
                ),
                "source": source,
                "source_date": date,
                "linked": any(
                    (m := re.search(r"([\d,]+) linked vulnerabilit", _unspanned(line)))
                    and _n(m.group(1)) > 0
                    for line in _row_lines(block)
                ),
            }
        )
    return rows


def code_rows(page: str) -> list[dict]:
    blocks = _blocks(page, "Match in")
    rows = []
    for block in blocks:
        # `_SPAN`, not a fixed backtick: a corpus file path may contain one, and
        # `inline()` then widens the delimiter. The old pattern returned None,
        # which the disjointness assertions read as a repeated page.
        path = re.match(_SPAN, block)
        # `source` is deliberately not read here: it is a bare span, so a hit
        # without one promotes the catalog kind into its place. The filter test
        # reads it from the structured channel instead.
        if path:
            rows.append({"path": path.group(2)})
        elif block.startswith("(path not returned)"):
            # The renderer says so itself when the API omits the path. That is
            # an API omission, not a disagreement between these two halves.
            rows.append({"path": None})
    _expect_parsed(page, blocks, rows, "code match")
    return rows


# Anchored to the whole role line. An unanchored `source ` ...`` search crosses
# newlines, so a display name containing " · source " bound `source_scope` to
# text from the heading line and produced a plausible wrong value rather than
# no value - worse than dropping the row, because the assertion then blames the
# API for a parser fault.
_AUTHOR_ROLE_LINE = re.compile(
    r"(?m)^((?:Author|Repository owner)(?: / (?:Author|Repository owner))*)"
    r" · source (`+) (.+?) \2"
    rf" · source identity (`+) (.+?) \4{_CUT}\s*$"
)


def author_rows(page: str) -> list[dict]:
    rows = []
    # `_blocks` strips the heading label. Splitting on a bare "## " left
    # "Exploit contributor " in front of the name span, so the match below
    # found nothing and every author assertion failed as "returned nothing"
    # while the tool was returning correct rows.
    blocks = _blocks(page, "Exploit contributor")
    for block in blocks:
        match = re.match(_SPAN + r" · #(\d+)", block)
        role_line = _AUTHOR_ROLE_LINE.search(block)
        if not match or not role_line:
            continue
        roles = set()
        labels = role_line.group(1)
        if "Author" in labels:
            roles.add("author")
        if "Repository owner" in labels:
            roles.add("owner")
        rows.append(
            {
                "name": match.group(2),
                "public_id": int(match.group(3)),
                "source_scope": role_line.group(3),
                "external_id": role_line.group(5),
                "roles": roles,
            }
        )
    _expect_parsed(page, blocks, rows, "author")
    return rows


# ==========================================================================
# browse_authors/get_author - 6 parameters across two tools
# ==========================================================================


async def test_author_query_changes_the_result_set(tools):
    base = author_rows(await tools.browse_authors(limit=10))
    assert base
    needle = base[0]["external_id"]
    assert needle
    found = author_rows(await tools.browse_authors(query=needle, limit=10))
    assert found
    assert all(
        needle.lower() in row["name"].lower()
        or needle.lower() in (row["external_id"] or "").lower()
        for row in found
    )


@pytest.mark.parametrize("source_scope", AUTHOR_SOURCES)
async def test_author_source_scope_holds_on_every_row(tools, source_scope):
    rows = author_rows(await tools.browse_authors(source_scope=source_scope, limit=10))
    assert rows, f"source_scope={source_scope} returned nothing"
    assert all(row["source_scope"] == source_scope for row in rows)


@pytest.mark.parametrize("role", AUTHOR_ROLES)
async def test_author_role_holds_on_every_row(tools, role):
    rows = author_rows(await tools.browse_authors(role=role, limit=10))
    assert rows, f"role={role} returned nothing"
    assert all(role in row["roles"] for row in rows)


async def test_author_limit_and_cursor_page_forward(tools):
    first = await tools.browse_authors(limit=5)
    first_rows = author_rows(first)
    assert len(first_rows) == 5
    cursor = _cursor(first)
    assert cursor
    second_rows = author_rows(await tools.browse_authors(limit=5, cursor=cursor))
    assert second_rows
    first_ids = {row["public_id"] for row in first_rows}
    second_ids = {row["public_id"] for row in second_rows}
    assert not (first_ids & second_ids)


async def test_author_public_id_returns_that_identity(tools):
    row = author_rows(await tools.browse_authors(limit=1))[0]
    detail = await tools.get_author(public_id=row["public_id"])
    assert f"#{row['public_id']}" in detail


async def test_exploit_author_id_changes_the_result_set(tools):
    author = author_rows(await tools.browse_authors(limit=1))[0]
    filtered = artifact_rows(
        await tools.search_exploits(author_id=author["public_id"], limit=10)
    )
    assert filtered
    for row in filtered:
        detail = await tools.get_exploit(row["artifact_id"])
        contributor_ids = {
            int(value) for value in re.findall(r"author_id #(\d+)", detail)
        }
        assert author["public_id"] in contributor_ids, row["artifact_id"]


def _spans(page: str, blocks: list[str], what: str) -> list[str]:
    """Read the leading code span of each block, loudly."""
    values = [m.group(2) for b in blocks if (m := re.match(_SPAN, b))]
    _expect_parsed(page, blocks, values, what)
    return values


def vendor_rows(page: str) -> list[str]:
    return _spans(page, _blocks(page, "Vendor"), "vendor")


def product_rows(page: str) -> list[tuple[str, str]]:
    blocks = _blocks(page, "Product")
    rows = []
    for block in blocks:
        product = re.match(_SPAN, block)
        vendor = re.search(rf"(?m)^Vendor: (`+) (.+?) \1{_CUT}\s*$", block)
        if product and vendor:
            rows.append((vendor.group(2), product.group(2)))
    _expect_parsed(page, blocks, rows, "product")
    return rows


def ecosystem_rows(page: str) -> list[str]:
    return _spans(page, _blocks(page, "Ecosystem"), "ecosystem")


def ecosystem_entries(page: str) -> list[tuple[str, int]]:
    blocks = _blocks(page, "Ecosystem")
    rows = []
    for block in blocks:
        ecosystem = re.match(_SPAN, block)
        package_count = re.search(rf"({_NUM}) packages?", block)
        if ecosystem and package_count:
            rows.append((ecosystem.group(2), int(_n(package_count.group(1)))))
    _expect_parsed(page, blocks, rows, "ecosystem")
    return rows


def package_rows(page: str) -> list[tuple[str, str]]:
    blocks = _blocks(page, "Package")
    rows = []
    for block in blocks:
        package = re.match(_SPAN, block)
        ecosystem = re.search(rf"(?m)^Ecosystem: (`+) (.+?) \1{_CUT}\s*$", block)
        if package and ecosystem:
            rows.append((ecosystem.group(2), package.group(2)))
    _expect_parsed(page, blocks, rows, "package")
    return rows


def weakness_rows(page: str) -> list[str]:
    # browse_weaknesses has no kind filter, so a page can carry any mix of
    # Weakness, Category and View. Matching only "Weakness" returned [] for an
    # all-category page, which made the disjoint-page assertions pass vacuously.
    return _spans(page, _blocks(page, "Weakness", "Category", "View"), "weakness")


def _nonincreasing(values: list[float | str]) -> bool:
    present = [v for v in values if v is not None]
    return all(a >= b for a, b in zip(present, present[1:], strict=False))


def _comparable(values: list) -> int:
    """How many of a sort column were actually read.

    Comparing nothing is not monotonicity: an all-None column makes
    `_nonincreasing` vacuously true, so a renamed label used to leave the sort
    unverified while green.
    """
    return len([v for v in values if v is not None])


def _cursor(page: str) -> str | None:
    # Outside fences: a snippet echoing this sentence forged the cursor, which
    # the caller then sent back to the API as `cursor=`.
    m = re.search(
        r"changing any of them is refused rather than silently re-paged:\n` (\S+) `",
        _outside_fences(page),
    )
    return m.group(1) if m else None


# ==========================================================================
# get_corpus_readiness - 0 parameters
# ==========================================================================


async def test_get_corpus_readiness_takes_no_arguments(tools):
    """Nothing to vary; pin that it is genuinely nullary and renders."""
    page = await tools.get_corpus_readiness()
    assert "# EIP corpus readiness" in page
    assert "Code search subsystem" in page


# ==========================================================================
# STIX, generic artifacts and lab discovery
# ==========================================================================


async def test_stix_identifier_selects_the_requested_cve(tools):
    page = await tools.get_vulnerability_stix(identifier="cve-2021-44228")
    assert "STIX 2.1 bundle" in page
    assert "CVE-2021-44228" in page


async def test_generic_artifact_identifier_selects_that_artifact(tools):
    vulnerability = await tools._api.get("/api/v1/vulnerabilities/CVE-2021-44228")
    candidates = vulnerability.get("nuclei") or vulnerability.get("artifacts") or []
    if isinstance(candidates, dict):
        candidates = candidates.get("items", [])
    artifact_id = next(
        (
            item.get("artifact_id")
            for item in candidates
            if isinstance(item, dict) and item.get("artifact_id")
        ),
        None,
    )
    if not artifact_id:
        pytest.skip("fixture CVE currently exposes no generic artifact")
    page = await tools.get_artifact(artifact_id=artifact_id)
    assert artifact_id in page


async def test_lab_query_limit_and_cursor_take_effect(tools):
    raw = await tools._api.get("/api/v1/labs", {"limit": 1})
    items = raw.get("items", [])
    if not items:
        pytest.skip("corpus currently exposes no labs")
    title = items[0].get("owner", {}).get("title")
    assert title
    token = title[: min(12, len(title))]
    first = await tools.search_labs(query=token, limit=1)
    assert title in first
    cursor = _cursor(first)
    # Conditional on purpose, unlike the directory cursor tests: this queries a
    # 12-character prefix of one lab's own title, so a corpus where exactly one
    # lab matches has no second page and offers no cursor. Requiring one here
    # fails against a healthy API.
    if cursor:
        second = await tools.search_labs(query=token, limit=1, cursor=cursor)
        assert first != second


@pytest.mark.parametrize("kind", LAB_KINDS)
async def test_lab_kind_is_reflected_by_every_result(tools, kind):
    page = await tools.search_labs(kind=kind, limit=10)
    rows = lab_rows(page)
    assert rows, f"kind={kind} returned no lab units"
    if kind == "all":
        return
    # The API filter is a family selector. Rows retain the more precise
    # source-backed identity (`compose_stack`, `standalone_dockerfile_directory`,
    # and the shape beside it), so the family must appear in one of them.
    # `kinds` is [anchor_kind, shape]. A lab missing its anchor kind would put
    # the shape at index 0, silently reinstating the bug this parser was
    # rewritten to fix, so require both before indexing.
    assert all(len(row["kinds"]) == 2 for row in rows), (
        "a lab row parsed no anchor kind, so kinds[0] would be the shape"
    )
    # Matching any span would accept a compose-family lab returned for
    # kind="dockerfile" on the strength of its shape alone.
    assert all(kind in row["kinds"][0] for row in rows)


@pytest.mark.parametrize("association", LAB_ASSOCIATIONS)
async def test_lab_association_holds_on_every_result(tools, association):
    rows = lab_rows(await tools.search_labs(association=association, limit=10))
    if association == "linked":
        assert rows and all(row["linked"] for row in rows)
    elif association == "unlinked":
        assert rows and all(not row["linked"] for row in rows)
    else:
        assert rows


@pytest.mark.parametrize("analysis", LAB_ANALYSIS)
async def test_lab_analysis_filter_and_include_analysis_take_effect(tools, analysis):
    plain = await tools.search_labs(analysis=analysis, include_analysis=False, limit=10)
    rows = lab_rows(plain)
    if analysis == "available":
        assert rows
        expanded = await tools.search_labs(
            analysis=analysis, include_analysis=True, limit=10
        )
        assert expanded != plain
        assert any(row["analysis"] for row in lab_rows(expanded))
    elif analysis == "pending":
        assert all(not row["analysis"] for row in rows)


# ==========================================================================
# get_corpus_statistics - 1 parameter: trends
# ==========================================================================

TREND_HEADING = {
    "cve_published": "CVEs published (completed months)",
    "cwe": "Leading CWEs",
    "catalog_additions": "Catalog additions",
    "poc_supply": "PoC supply (completed quarters)",
}


@pytest.mark.parametrize("series", TREND_SERIES)
async def test_trends_selects_exactly_the_requested_series(tools, series):
    """Every declared value is accepted, and selects what its name promises."""
    page = await tools.get_corpus_statistics(trends=series)
    assert "# EIP corpus statistics" in page
    headings = {name for name, head in TREND_HEADING.items() if head in page}
    if series == "none":
        assert headings == set(), f"trends='none' still rendered {headings}"
    elif series == "all":
        assert headings == set(TREND_HEADING), f"trends='all' rendered only {headings}"
    else:
        assert headings == {series}, f"trends={series!r} rendered {headings}"


async def test_trends_rejects_an_undeclared_value(tools):
    with pytest.raises(Exception, match="trends must be one of"):
        await tools.get_corpus_statistics(trends="quarterly")


# ==========================================================================
# search_vulnerabilities - 14 parameters
# ==========================================================================


async def test_query_restricts_and_changes_the_result_set(tools):
    unfiltered = {r["cve"] for r in vuln_rows(await tools.search_vulnerabilities(limit=10))}
    filtered = vuln_rows(await tools.search_vulnerabilities(query="struts", limit=10))
    assert filtered, "query returned nothing at all"
    assert {r["cve"] for r in filtered} != unfiltered, "query did not change the page"


@pytest.mark.parametrize("severity", SEVERITIES)
async def test_severity_holds_on_every_row(tools, severity):
    rows = vuln_rows(await tools.search_vulnerabilities(severity=[severity], limit=10))
    if not rows:
        pytest.skip(f"corpus has no {severity} rows to check")
    off = [r["severity"] for r in rows if r["severity"] != severity]
    assert not off, f"severity={severity} returned rows labelled {off}"


async def test_severity_is_case_insensitive(tools):
    """`tools.py` upper-cases; a lowercase caller must not silently get everything."""
    lower = vuln_rows(await tools.search_vulnerabilities(severity=["critical"], limit=5))
    assert lower and all(r["severity"] == "CRITICAL" for r in lower)


async def test_severity_accepts_several_values(tools):
    rows = vuln_rows(await tools.search_vulnerabilities(severity=["CRITICAL", "HIGH"], limit=20))
    assert rows and all(r["severity"] in {"CRITICAL", "HIGH"} for r in rows)
    assert len({r["severity"] for r in rows}) == 2, "a two-value filter returned one severity"


async def test_severity_rejects_an_undeclared_value(tools):
    with pytest.raises(Exception, match="severity values must be among"):
        await tools.search_vulnerabilities(severity=["SEVERE"])


async def test_cwe_holds_on_every_row(tools):
    """Rows do not print the CWE, so each hit is confirmed against its own record."""
    rows = vuln_rows(await tools.search_vulnerabilities(cwe="CWE-79", limit=3))
    assert rows, "cwe=CWE-79 returned nothing"
    for row in rows:
        detail = await tools.get_vulnerability(row["cve"], sections=["weaknesses"])
        assert "CWE-79" in detail, f"{row['cve']} came back for CWE-79 but does not carry it"


async def test_cwe_is_normalised_and_validated(tools):
    lower = vuln_rows(await tools.search_vulnerabilities(cwe="cwe-79", limit=3))
    assert lower, "lowercase cwe was not normalised"
    with pytest.raises(Exception, match="cwe must look like"):
        await tools.search_vulnerabilities(cwe="79")


async def test_vendor_filter_matches_the_public_api_result_exactly(tools):
    directory = await tools._api.get("/api/v1/vendors", {"limit": 1})
    vendor = directory["items"][0]["vendor"]
    expected = await tools._api.get(
        "/api/v1/vulnerabilities", {"vendor": vendor, "limit": 5}
    )
    rows = vuln_rows(await tools.search_vulnerabilities(vendor=vendor, limit=5))
    assert rows, f"vendor={vendor!r} returned nothing"
    assert [row["cve"] for row in rows] == [item["identifier"] for item in expected["items"]]


async def test_product_filter_matches_the_public_api_result_exactly(tools):
    vendor_page = await tools._api.get("/api/v1/vendors", {"limit": 1})
    vendor = vendor_page["items"][0]["vendor"]
    product_page = await tools._api.get(
        "/api/v1/products", {"vendor": vendor, "limit": 1}
    )
    product = product_page["items"][0]["product"]
    expected = await tools._api.get(
        "/api/v1/vulnerabilities",
        {"vendor": vendor, "product": product, "limit": 5},
    )
    rows = vuln_rows(
        await tools.search_vulnerabilities(vendor=vendor, product=product, limit=5)
    )
    assert rows, f"vendor={vendor!r}, product={product!r} returned nothing"
    assert [row["cve"] for row in rows] == [item["identifier"] for item in expected["items"]]


async def test_ecosystem_filter_matches_the_public_api_result_exactly(tools):
    directory = await tools._api.get("/api/v1/ecosystems", {"limit": 1})
    ecosystem = directory["items"][0]["ecosystem"]
    expected = await tools._api.get(
        "/api/v1/vulnerabilities", {"ecosystem": ecosystem, "limit": 5}
    )
    rows = vuln_rows(await tools.search_vulnerabilities(ecosystem=ecosystem, limit=5))
    assert rows, f"ecosystem={ecosystem!r} returned nothing"
    assert [row["cve"] for row in rows] == [item["identifier"] for item in expected["items"]]


async def test_package_filter_matches_the_public_api_result_exactly(tools):
    ecosystem_page = await tools._api.get("/api/v1/ecosystems", {"limit": 1})
    ecosystem = ecosystem_page["items"][0]["ecosystem"]
    package_page = await tools._api.get(
        "/api/v1/packages", {"ecosystem": ecosystem, "limit": 1}
    )
    package = package_page["items"][0]["package_name"]
    expected = await tools._api.get(
        "/api/v1/vulnerabilities",
        {"ecosystem": ecosystem, "package": package, "limit": 5},
    )
    rows = vuln_rows(
        await tools.search_vulnerabilities(
            ecosystem=ecosystem,
            package=package,
            limit=5,
        )
    )
    assert rows, f"ecosystem={ecosystem!r}, package={package!r} returned nothing"
    assert [row["cve"] for row in rows] == [item["identifier"] for item in expected["items"]]


# ==========================================================================
# vendor/product discovery - all seven parameters across the two tools
# ==========================================================================


async def test_vendor_query_restricts_names_and_limit_changes_page_size(tools):
    first = vendor_rows(await tools.browse_vendors(limit=1))
    assert len(first) == 1
    token = first[0][: min(5, len(first[0]))]
    filtered = vendor_rows(await tools.browse_vendors(query=token, limit=3))
    assert filtered and len(filtered) <= 3
    assert all(token.casefold() in vendor.casefold() for vendor in filtered)


async def test_vendor_cursor_returns_a_disjoint_page(tools):
    first = await tools.browse_vendors(limit=2)
    cursor = _cursor(first)
    assert cursor, "vendor directory returned no cursor"
    second = await tools.browse_vendors(limit=2, cursor=cursor)
    assert vendor_rows(second), "the second page returned no rows, so disjointness proves nothing"
    assert set(vendor_rows(first)).isdisjoint(vendor_rows(second))


async def test_product_vendor_query_limit_and_cursor_take_effect(tools):
    vendor = vendor_rows(await tools.browse_vendors(limit=1))[0]
    first = await tools.browse_products(vendor=vendor, limit=2)
    rows = product_rows(first)
    assert rows and len(rows) <= 2
    assert all(returned_vendor.casefold() == vendor.casefold() for returned_vendor, _ in rows)

    token = rows[0][1][: min(5, len(rows[0][1]))]
    filtered = product_rows(
        await tools.browse_products(vendor=vendor, query=token, limit=3)
    )
    assert filtered
    assert all(token.casefold() in product.casefold() for _, product in filtered)

    cursor = _cursor(first)
    assert cursor, "product directory returned no cursor"
    second = product_rows(await tools.browse_products(vendor=vendor, limit=2, cursor=cursor))
    assert second, "the second page returned no rows, so disjointness proves nothing"
    assert set(rows).isdisjoint(second)


# ==========================================================================
# ecosystem/package discovery - all seven parameters across the two tools
# ==========================================================================


async def test_ecosystem_query_restricts_names_and_limit_changes_page_size(tools):
    first = ecosystem_rows(await tools.browse_ecosystems(limit=1))
    assert len(first) == 1
    token = first[0][: min(5, len(first[0]))]
    filtered = ecosystem_rows(await tools.browse_ecosystems(query=token, limit=3))
    assert filtered and len(filtered) <= 3
    assert all(token.casefold() in ecosystem.casefold() for ecosystem in filtered)


async def test_ecosystem_cursor_returns_a_disjoint_page(tools):
    first = await tools.browse_ecosystems(limit=2)
    cursor = _cursor(first)
    assert cursor, "ecosystem directory returned no cursor"
    second = await tools.browse_ecosystems(limit=2, cursor=cursor)
    assert ecosystem_rows(second), (
        "the second page returned no rows, so disjointness proves nothing"
    )
    assert set(ecosystem_rows(first)).isdisjoint(ecosystem_rows(second))


async def test_package_ecosystem_query_limit_and_cursor_take_effect(tools):
    candidates = [
        item
        for item in ecosystem_entries(await tools.browse_ecosystems(limit=100))
        if item[1] > 2
    ]
    assert candidates, "corpus has no ecosystem large enough to prove package pagination"
    ecosystem = max(candidates, key=lambda item: item[1])[0]
    first = await tools.browse_packages(ecosystem=ecosystem, limit=2)
    rows = package_rows(first)
    assert rows and len(rows) <= 2
    assert all(returned.casefold() == ecosystem.casefold() for returned, _ in rows)

    token = rows[0][1][: min(5, len(rows[0][1]))]
    filtered = package_rows(
        await tools.browse_packages(ecosystem=ecosystem, query=token, limit=3)
    )
    assert filtered
    assert all(token.casefold() in package.casefold() for _, package in filtered)

    cursor = _cursor(first)
    assert cursor, "package directory returned no cursor"
    second = package_rows(
        await tools.browse_packages(ecosystem=ecosystem, limit=2, cursor=cursor)
    )
    assert second, "the second page returned no rows, so disjointness proves nothing"
    assert set(rows).isdisjoint(second)


# ===========================================================================
# CWE discovery - all four parameters across the two tools
# ===========================================================================


async def test_weakness_query_limit_and_cursor_take_effect(tools):
    first = await tools.browse_weaknesses(limit=2)
    rows = weakness_rows(first)
    assert rows and len(rows) <= 2

    token = rows[0]
    filtered = weakness_rows(await tools.browse_weaknesses(query=token, limit=3))
    assert filtered
    assert all(token.casefold() in cwe_id.casefold() for cwe_id in filtered)

    cursor = _cursor(first)
    assert cursor, "CWE catalog returned no cursor"
    second = weakness_rows(await tools.browse_weaknesses(limit=2, cursor=cursor))
    assert second, "the second page returned no rows, so disjointness proves nothing"
    assert set(rows).isdisjoint(second)


async def test_get_weakness_normalises_and_resolves_the_selected_id(tools):
    selected = weakness_rows(await tools.browse_weaknesses(limit=1))[0]
    rendered = await tools.get_weakness(selected.lower())
    assert re.search(rf"# CWE (?:Weakness|Category|View) ` {re.escape(selected)} `", rendered)
    assert re.search(r"associated vulnerabilit(?:y|ies)", rendered)
    with pytest.raises(Exception, match="cwe_id must look like"):
        await tools.get_weakness("79")


# Written out rather than parametrised over `**{flag: True}`: a dict-unpacked
# keyword is invisible to the static guard in test_declared_arguments.py, so a
# parameter covered only that way reads as uncovered - or, worse, a deleted test
# reads as covered.
async def test_cisa_kev_holds_on_every_row(tools):
    rows = vuln_rows(await tools.search_vulnerabilities(cisa_kev=True, limit=10))
    assert rows, "cisa_kev=True returned nothing"
    missing = [r["cve"] for r in rows if not r["kev"]]
    assert not missing, f"cisa_kev=True returned rows without the marker: {missing}"


async def test_ransomware_holds_on_every_row(tools):
    rows = vuln_rows(await tools.search_vulnerabilities(ransomware=True, limit=10))
    assert rows, "ransomware=True returned nothing"
    missing = [r["cve"] for r in rows if not r["ransomware"]]
    assert not missing, f"ransomware=True returned rows without the marker: {missing}"


async def test_nuclei_flag_holds_on_every_row(tools):
    rows = vuln_rows(await tools.search_vulnerabilities(nuclei=True, limit=10))
    assert rows, "nuclei=True returned nothing"
    bare = [r["cve"] for r in rows if r["nuclei"] < 1]
    assert not bare, f"nuclei=True returned rows with no template: {bare}"


async def test_with_artifacts_holds_on_every_row(tools):
    result = await tools.search_vulnerabilities(with_artifacts=True, limit=10)
    rows = result.structured.data["items"]
    assert rows, "with_artifacts=True returned nothing"
    bare = [r["identifier"] for r in rows if r["artifact_count"] < 1]
    assert not bare, f"with_artifacts=True returned rows with no artifact: {bare}"


async def test_a_false_flag_does_not_filter(tools):
    """The default must be 'do not constrain', not 'require absent'."""
    rows = vuln_rows(await tools.search_vulnerabilities(cisa_kev=False, limit=25))
    assert any(not r["kev"] for r in rows), "cisa_kev=False behaved like a filter"


@pytest.mark.parametrize(
    "sort,key", [("published", "published"), ("cvss", "cvss"), ("epss", "epss")]
)
async def test_sort_orders_the_page_by_its_key(tools, sort, key):
    rows = vuln_rows(await tools.search_vulnerabilities(sort=sort, limit=25))
    assert len(rows) > 1
    values = [r[key] for r in rows]
    assert _comparable(values) > 1, (
        f"sort={sort}: only {_comparable(values)} of {len(values)} rows yielded a {key}"
    )
    assert _nonincreasing(values), f"sort={sort} produced non-monotonic {key}: {values}"


async def test_sorts_differ_from_one_another(tools):
    """Monotonic under its own key is necessary but not sufficient."""
    pages = {
        s: [r["cve"] for r in vuln_rows(await tools.search_vulnerabilities(sort=s, limit=10))]
        for s in SORTS
    }
    assert len({tuple(v) for v in pages.values()}) == len(SORTS), (
        f"two sorts agreed exactly: {pages}"
    )


async def test_sort_rejects_an_undeclared_value(tools):
    with pytest.raises(Exception, match="sort must be one of"):
        await tools.search_vulnerabilities(sort="cvss_desc")


def _assert_page_size(page: str, rows: list, limit: int, what: str) -> None:
    """`limit` rows, unless the output cap cut the page - which it must disclose."""
    if len(rows) == limit:
        return
    assert "truncated at" in page, f"{what} limit={limit} returned {len(rows)} rows silently"
    assert len(rows) < limit


@pytest.mark.parametrize("limit", [1, 2, 25, 100])
async def test_limit_returns_exactly_that_many(tools, limit):
    page = await tools.search_vulnerabilities(limit=limit)
    _assert_page_size(page, vuln_rows(page), limit, "search_vulnerabilities")


@pytest.mark.parametrize("limit", [0, -1, 101])
async def test_limit_is_bounded(tools, limit):
    with pytest.raises(Exception, match="limit must be between 1 and 100"):
        await tools.search_vulnerabilities(limit=limit)


async def test_cursor_pages_forward_without_repeating(tools):
    first = await tools.search_vulnerabilities(query="apache", limit=5)
    cursor = _cursor(first)
    assert cursor, "no cursor offered on a page that has more results"
    second = await tools.search_vulnerabilities(query="apache", limit=5, cursor=cursor)
    a = {r["cve"] for r in vuln_rows(first)}
    b = {r["cve"] for r in vuln_rows(second)}
    assert b and not (a & b), f"page 2 repeated page 1: {a & b}"


async def test_cursor_is_bound_to_its_query(tools):
    cursor = _cursor(await tools.search_vulnerabilities(query="apache", limit=5))
    with pytest.raises(Exception, match="cursor does not match this query"):
        await tools.search_vulnerabilities(query="apache", limit=6, cursor=cursor)


async def test_a_tampered_cursor_is_refused(tools):
    cursor = _cursor(await tools.search_vulnerabilities(query="apache", limit=5))
    with pytest.raises(Exception, match="cursor"):
        await tools.search_vulnerabilities(query="apache", limit=5, cursor=cursor[:-4] + "AAAA")


# ==========================================================================
# get_vulnerability - 3 parameters
# ==========================================================================


async def test_identifier_accepts_a_cve_and_normalises_case(tools):
    upper = await tools.get_vulnerability("CVE-2021-44228", sections=["lifecycle"])
    lower = await tools.get_vulnerability("cve-2021-44228", sections=["lifecycle"])
    assert "CVE-2021-44228" in upper and upper == lower


async def test_identifier_distinguishes_malformed_from_absent(tools):
    with pytest.raises(Exception) as bad:
        await tools.get_vulnerability("CVE-99999-1")
    with pytest.raises(Exception) as absent:
        await tools.get_vulnerability("CVE-2021-99999")
    assert str(bad.value) != str(absent.value), "a typo and a miss read identically"


def _headings(page: str) -> set[str]:
    return set(re.findall(r"^## (.+)$", page, re.M))


@pytest.mark.parametrize("section", fmt.VULN_SECTIONS)
async def test_each_section_is_selectable_alone(tools, section):
    """Asking for one section must expand that one and not the other nine.

    Not a length comparison: the default page is a *brief* that advertises what
    `sections` can expand, so naming a section legitimately makes it longer.
    """
    # Baseline is `sections=[]`, the header alone - NOT the default call. The
    # default now expands eight sections, so measuring against it would compare a
    # section to a page that already contains it and find nothing added, which is
    # the opposite of what this test is for.
    base = _headings(await tools.get_vulnerability("CVE-2021-44228", sections=[]))
    page = _headings(await tools.get_vulnerability("CVE-2021-44228", sections=[section]))
    # The inventory heading differs between the two shapes - "Available detail" on
    # a page that expanded nothing, "Also available" on one that did - and this
    # test is about the section, not about that. Drop both from the comparison.
    inventory = {h for h in base | page if h.startswith(("Available detail", "Also available"))}
    added = (page - base) - inventory
    # `== 1`, not `<= 1`: at `<= 1` this test passes when `sections` is dropped
    # on the floor, which is the exact failure this whole file exists to catch.
    assert len(added) == 1, f"sections=[{section}] expanded {len(added)} sections: {added}"


async def test_sections_rejects_an_undeclared_name(tools):
    with pytest.raises(Exception, match="sections must be among"):
        await tools.get_vulnerability("CVE-2021-44228", sections=["exploits"])


async def test_section_limit_bounds_items_within_a_section(tools):
    small = await tools.get_vulnerability("CVE-2021-44228", sections=["pocs"], section_limit=1)
    large = await tools.get_vulnerability("CVE-2021-44228", sections=["pocs"], section_limit=50)
    assert len(small) < len(large), "section_limit did not change how much was rendered"


@pytest.mark.parametrize("bad", [0, -1, fmt.SECTION_LIMIT_MAX + 1])
async def test_section_limit_is_bounded(tools, bad):
    with pytest.raises(Exception, match="section_limit must be between"):
        await tools.get_vulnerability("CVE-2021-44228", section_limit=bad)


# ==========================================================================
# search_exploits - 9 parameters
# ==========================================================================


async def test_exploit_query_changes_the_result_set(tools):
    base = {r["artifact_id"] for r in artifact_rows(await tools.search_exploits(limit=10))}
    found = artifact_rows(await tools.search_exploits(query="wordpress", limit=10))
    assert found and {r["artifact_id"] for r in found} != base


@pytest.mark.parametrize("source", POC_SOURCES)
async def test_exploit_source_holds_on_every_row(tools, source):
    rows = artifact_rows(await tools.search_exploits(source=source, limit=10))
    assert rows, f"source={source} returned nothing"
    off = {r["source"] for r in rows if r["source"] != source}
    assert not off, f"source={source} returned {off}"


@pytest.mark.parametrize("association", ASSOCIATIONS)
async def test_association_holds_on_every_row(tools, association):
    rows = artifact_rows(await tools.search_exploits(association=association, limit=10))
    assert rows, f"association={association} returned nothing"
    if association == "linked":
        assert all(r["linked"] for r in rows)
    elif association == "unlinked":
        assert not any(r["linked"] for r in rows)


async def test_source_date_from_excludes_earlier_rows(tools):
    cutoff = "2025-01-01"
    rows = artifact_rows(await tools.search_exploits(source_date_from=cutoff, limit=20))
    assert rows, "source_date_from returned nothing"
    assert all(r["source_date"] for r in rows), (
        "an undated row on a date-filtered page: either the page is not "
        "excluding undated artifacts, or artifact_rows lost the date"
    )
    early = [r["source_date"] for r in rows if r["source_date"] and r["source_date"] < cutoff]
    assert not early, f"source_date_from={cutoff} returned {early}"


async def test_source_date_to_excludes_later_rows(tools):
    cutoff = "2015-01-01"
    rows = artifact_rows(await tools.search_exploits(source_date_to=cutoff, limit=20))
    assert rows, "source_date_to returned nothing"
    assert all(r["source_date"] for r in rows), (
        "an undated row on a date-filtered page: either the page is not "
        "excluding undated artifacts, or artifact_rows lost the date"
    )
    late = [r["source_date"] for r in rows if r["source_date"] and r["source_date"] > cutoff]
    assert not late, f"source_date_to={cutoff} returned {late}"


async def test_source_date_bounds_compose(tools):
    rows = artifact_rows(
        await tools.search_exploits(
            source_date_from="2020-01-01", source_date_to="2020-12-31", limit=20
        )
    )
    assert rows, "a bounded window returned nothing"
    assert all(r["source_date"] for r in rows), (
        "an undated row on a date-filtered page: either the page is not "
        "excluding undated artifacts, or artifact_rows lost the date"
    )
    assert all(r["source_date"].startswith("2020") for r in rows)


@pytest.mark.parametrize("limit", [1, 5, 100])
async def test_exploit_limit_returns_exactly_that_many(tools, limit):
    page = await tools.search_exploits(limit=limit)
    _assert_page_size(page, artifact_rows(page), limit, "search_exploits")


async def test_exploit_cursor_pages_forward_without_repeating(tools):
    first = await tools.search_exploits(source="metasploit", limit=5)
    cursor = _cursor(first)
    assert cursor
    second = await tools.search_exploits(source="metasploit", limit=5, cursor=cursor)
    a = {r["artifact_id"] for r in artifact_rows(first)}
    b = {r["artifact_id"] for r in artifact_rows(second)}
    assert b and not (a & b)


@pytest.mark.parametrize(
    "kwargs,message",
    [
        ({"source": "github"}, "source must be one of"),
        ({"catalog_kind": "poc"}, "catalog_kind must be one of"),
        ({"association": "any"}, "association must be one of"),
        ({"limit": 0}, "limit must be between"),
    ],
)
async def test_exploit_enums_reject_undeclared_values(tools, kwargs, message):
    with pytest.raises(Exception, match=message):
        await tools.search_exploits(**kwargs)


# ==========================================================================
# get_exploit - 1 parameter
# ==========================================================================


async def test_artifact_id_returns_that_artifact(tools):
    known = artifact_rows(await tools.search_exploits(source="metasploit", limit=1))[0][
        "artifact_id"
    ]
    page = await tools.get_exploit(known)
    assert known in page


async def test_artifact_id_rejects_a_non_uuid_and_reports_a_miss(tools):
    """A malformed id and an absent one are different facts; say so.

    Both used to read `PoC artifact not found`, which tells a researcher the
    corpus does not hold something that was never an artifact id at all.
    """
    with pytest.raises(Exception, match="malformed identifier") as bad:
        await tools.get_exploit("not-a-uuid")
    with pytest.raises(Exception, match="not found") as absent:
        await tools.get_exploit("00000000-0000-5000-8000-000000000000")
    assert str(bad.value) != str(absent.value)


@pytest.mark.parametrize("kind", CATALOG_KINDS)
async def test_catalog_kind_holds_on_every_row(tools, kind):
    """Read from the structured channel, not the rendered page.

    `catalog_kind` and `language` render as bare spans in a " · " chain whose
    every other member carries a word, so recovering them from the text means
    guessing which span is which. Three attempts at that returned wrong values
    and blamed the API for it. The structured result carries the API's own
    values, which is what "the filter holds on every row" actually means.
    """
    result = await tools.search_exploits(catalog_kind=kind, limit=10)
    rows = result.structured.data["items"]
    assert rows, f"catalog_kind={kind} returned nothing"
    off = {r.get("catalog_kind") for r in rows if r.get("catalog_kind") != kind}
    assert not off, f"catalog_kind={kind} returned {off}"


async def test_language_holds_on_every_row(tools):
    result = await tools.search_exploits(language="Ruby", limit=10)
    rows = result.structured.data["items"]
    assert rows, "language=Ruby returned nothing"
    off = {r.get("language") for r in rows if r.get("language") != "Ruby"}
    assert not off, f"language=Ruby returned {off}"


# ==========================================================================
# search_exploit_code - 6 parameters
# ==========================================================================


async def test_code_query_is_required_and_restricts(tools):
    rows = code_rows(await tools.search_exploit_code(query="setuid", limit=5))
    assert rows, "code query returned nothing"
    other = code_rows(await tools.search_exploit_code(query="wp_ajax", limit=5))
    assert {r["path"] for r in rows} != {r["path"] for r in other}


@pytest.mark.parametrize("source", POC_SOURCES)
async def test_code_source_holds_on_every_row(tools, source):
    """Read from the structured channel, as `catalog_kind` and `language` do.

    On the rendered line the source is a bare span, so a record without one
    promotes the catalog kind into its place. The structured result carries the
    API's own value and needs no inference.
    """
    result = await tools.search_exploit_code(query="http", source=source, limit=5)
    rows = result.structured.data["items"]
    if not rows:
        pytest.skip(f"no code matches in {source}")
    off = {r.get("source") for r in rows if r.get("source") != source}
    assert not off, f"source={source} returned {off}"


@pytest.mark.parametrize("limit", [1, 5, 50])
async def test_code_limit_returns_at_most_that_many(tools, limit):
    assert len(code_rows(await tools.search_exploit_code(query="socket", limit=limit))) <= limit


async def test_code_limit_ceiling_is_fifty_not_one_hundred(tools):
    """The one tool with a different ceiling. Now advertised; pin it either way."""
    with pytest.raises(Exception, match="limit must be between 1 and 50"):
        await tools.search_exploit_code(query="socket", limit=51)


async def test_code_cursor_pages_forward_without_repeating(tools):
    first = await tools.search_exploit_code(query="socket", limit=5)
    cursor = _cursor(first)
    assert cursor
    second = await tools.search_exploit_code(query="socket", limit=5, cursor=cursor)
    a = {r["path"] for r in code_rows(first)}
    b = {r["path"] for r in code_rows(second)}
    assert b and not (a & b)


async def test_code_search_rejects_an_undeclared_source(tools):
    with pytest.raises(Exception, match="source must be one of"):
        await tools.search_exploit_code(query="socket", source="gitlab")


async def test_code_public_id_restricts_every_returned_hit(tools):
    unscoped = await tools.search_exploit_code(query="http", limit=50)
    candidate = next(
        (
            row
            for row in unscoped.structured.data.get("items", [])
            if isinstance(row.get("public_id"), int)
        ),
        None,
    )
    assert candidate, "no assigned code-search hit available to exercise public_id"
    public_id = candidate["public_id"]
    scoped = await tools.search_exploit_code(query="http", public_id=public_id, limit=50)
    assert scoped.structured.data.get("scope") == {
        "kind": "public-poc",
        "public_id": public_id,
    }
    rows = scoped.structured.data.get("items", [])
    assert rows and all(row.get("public_id") == public_id for row in rows)


async def test_code_vulnerability_id_restricts_every_returned_hit(tools):
    vulnerability_id = "CVE-2024-7120"
    detail = await tools.get_vulnerability(
        vulnerability_id, sections=["pocs"], section_limit=50
    )
    pocs = detail.structured.data["pocs"]
    assert pocs["truncated"] is False and pocs["total"] == len(pocs["items"])
    authoritative_ids = {item["public_id"] for item in pocs["items"]}
    assert authoritative_ids

    unscoped = await tools.search_exploit_code(query="http", limit=1)
    nonmember = unscoped.structured.data["items"][0]["public_id"]
    assert nonmember not in authoritative_ids

    scoped = await tools.search_exploit_code(
        query="http", vulnerability_id=vulnerability_id, limit=1
    )
    rows = scoped.structured.data["items"]
    assert scoped.structured.data["scope"] == {
        "kind": "vulnerability",
        "vulnerability_id": vulnerability_id,
    }
    assert rows and all(row["public_id"] in authoritative_ids for row in rows)
    assert all(row["public_id"] != nonmember for row in rows)

    cursor = _cursor(scoped)
    assert cursor
    second = await tools.search_exploit_code(
        query="http", vulnerability_id=vulnerability_id, limit=1, cursor=cursor
    )
    assert all(
        row["public_id"] in authoritative_ids
        for row in second.structured.data.get("items", [])
    )
    with pytest.raises(Exception, match="cursor"):
        await tools.search_exploit_code(
            query="http",
            public_id=next(iter(authoritative_ids)),
            limit=1,
            cursor=cursor,
        )


# ==========================================================================
# read_exploit_file - 2 parameters
# ==========================================================================

WITH_FILE = "88a4403b-0aa1-58ab-a8bb-6d04daf6d8e8"
WITH_FILE_PATH = "exploits/multiple/webapps/52629.py"


async def test_path_omitted_lists_the_manifest(tools):
    page = await tools.read_exploit_file(WITH_FILE)
    assert WITH_FILE_PATH in page
    assert "```" not in page, "a manifest listing rendered file contents"


async def test_path_selects_one_file(tools):
    page = await tools.read_exploit_file(WITH_FILE, path=WITH_FILE_PATH)
    assert "```" in page, "a file read rendered no contents"
    assert WITH_FILE_PATH in page


@pytest.mark.parametrize(
    "path",
    [
        "../../../etc/passwd",
        "/etc/passwd",
        "exploits/../../../../etc/shadow",
        "./../.ssh/id_rsa",
    ],
)
async def test_path_refuses_to_escape_the_artifact(tools, path):
    """Named message, not a bare Exception: a typo in the test must not pass."""
    with pytest.raises(ValueError, match="traversal segments|must be a relative"):
        await tools.read_exploit_file(WITH_FILE, path=path)


@pytest.mark.parametrize("bad", ["not-a-uuid", "abc", "4b33f0e8-923e-55d9-91bc-39efd00e526"])
async def test_read_exploit_file_rejects_a_non_uuid_artifact_id(tools, bad):
    """The same gate as `get_exploit`. It had none of its own coverage."""
    with pytest.raises(ValueError, match="malformed identifier"):
        await tools.read_exploit_file(bad, path="exploit.py")


async def test_path_reports_a_miss_inside_the_artifact(tools):
    """A well-formed path that is simply absent is a different fact from a refusal."""
    with pytest.raises(ApiError, match="not found|not in this artifact"):
        await tools.read_exploit_file(WITH_FILE, path="exploits/nope.py")


# ==========================================================================
# Journeys - the identifiers a page hands out must work on the next call
# ==========================================================================


async def test_a_poc_listed_on_a_vulnerability_can_be_opened(tools):
    """Follow a vulnerability into one of its PoCs, the way a reader would.

    `get_vulnerability`'s linked-PoC list identifies each artifact ONLY by its
    public id (`#3505014494080483`) and then says to use `get_exploit` - so if
    `get_exploit` does not take that form, the main path through this corpus
    dead-ends. It briefly did: a UUID-only check refused every identifier this
    page prints. No parameter test could see it, because each tool was correct
    on its own; only walking from one to the next exposes it.
    """
    page = await tools.get_vulnerability("CVE-2022-26134", sections=["pocs"], section_limit=3)
    public_ids = re.findall(r"^- ` #(\d+) `", page, re.M)
    assert public_ids, "the PoC list printed no identifier a reader could use"

    detail = await tools.get_exploit(public_ids[0])
    assert public_ids[0] in detail
    # And the detail page hands back the other form, so the journey can continue.
    uuid_form = re.search(r"artifact_id: ` ([0-9a-f-]{36}) `", detail)
    assert uuid_form, "get_exploit did not print an artifact_id"
    assert await tools.get_exploit(uuid_form.group(1))


async def test_an_artifact_found_by_search_can_be_read(tools):
    """search_exploits -> get_exploit -> read_exploit_file, on its own output."""
    listing = await tools.search_exploits(source="exploitdb", limit=1)
    artifact_id = artifact_rows(listing)[0]["artifact_id"]
    assert artifact_id

    manifest = await tools.read_exploit_file(artifact_id)
    paths = re.findall(r"^- ` ([^`]+) `", manifest, re.M)
    assert paths, f"no readable path listed for {artifact_id}"

    body = await tools.read_exploit_file(artifact_id, path=paths[0])
    assert "```" in body, "following the manifest's own path returned no content"


async def test_a_code_search_hit_can_be_opened_at_its_own_path(tools):
    """search_exploit_code prints a path and an artifact; both must resolve."""
    page = await tools.search_exploit_code(query="socket", limit=1)
    path = re.search(r"^## Match in ` ([^`]+) `", page, re.M)
    public_id = re.search(r"^artifact ` #(\d+) `", page, re.M)
    assert path and public_id, page[:400]

    body = await tools.read_exploit_file(public_id.group(1), path=path.group(1))
    assert "```" in body


async def test_a_scored_row_always_says_which_cvss_version_it_quotes(tools):
    """Live, because the mixture is a property of the corpus, not of a fixture.

    One page of real results carries both v4.0 and v3.1 rows, with the same score
    appearing under each. Unversioned, adjacent rows reading `CVSS 8.6` are two
    different measurements, and `sort="cvss"` orders across them.
    """
    rows = vuln_rows(await tools.search_vulnerabilities(with_artifacts=True, limit=50))
    scored = [r for r in rows if r["cvss"] is not None]
    assert scored, "no scored rows to check"
    unversioned = [r["cve"] for r in scored if not r["cvss_version"]]
    # A record genuinely without a version must not have one invented, so this
    # asserts the common case rather than universality.
    assert len(unversioned) < len(scored), (
        f"not one scored row named its CVSS version: {unversioned[:5]}"
    )


async def test_the_corpus_really_does_mix_cvss_versions(tools):
    """Pins the premise. If the corpus ever standardises on one version this fails,
    and the reasoning behind rendering it should be revisited rather than assumed."""
    rows = vuln_rows(await tools.search_vulnerabilities(with_artifacts=True, limit=50))
    versions = {r["cvss_version"] for r in rows if r["cvss_version"]}
    assert len(versions) > 1, f"expected a mixture, saw only {versions}"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"source_date_from": "2025-01-01"},
        {"source_date_to": "2015-01-01"},
        {"source_date_from": "2020-01-01", "source_date_to": "2020-12-31"},
    ],
)
async def test_a_date_filtered_search_discloses_the_undated_exclusion(tools, kwargs):
    """Asserted through the handler, not the renderer.

    The renderer tests pass `date_filtered` in by hand, so they prove the notice
    renders and nothing about whether the tool ever asks for it. Dropping the
    argument in `tools.py` left every one of them green.
    """
    page = await tools.search_exploits(limit=1, **kwargs)
    assert fmt.DATE_FILTER_EXCLUDES_UNDATED in page


async def test_an_undated_search_carries_no_exclusion_notice(tools):
    page = await tools.search_exploits(limit=1)
    assert fmt.DATE_FILTER_EXCLUDES_UNDATED not in page


async def test_one_call_answers_the_ordinary_question(tools):
    """The navigation property, asserted live rather than assumed.

    "Tell me about this CVE" used to cost a brief, a decision about which of ten
    section names to expand, and a second call. It is now one call, and the page
    it returns carries the material a reader actually came for.
    """
    page = await tools.get_vulnerability("CVE-2021-44228")
    headings = _headings(page)
    for wanted in ("Linked PoCs", "Nuclei templates", "References", "Weaknesses"):
        assert any(h.startswith(wanted) for h in headings), f"{wanted} absent: {headings}"
    # Still bounded, and if the ceiling did cut it the page says so.
    assert len(page) <= 40_000
    if len(page) == 40_000:
        assert "truncated at" in page


async def test_research_writeups_reach_the_page_where_research_has_run(tools):
    """`research_resources` was rendered nowhere at all until now."""
    page = await tools.get_vulnerability("CVE-2026-15409")
    assert "## Research writeups" in page
    assert "claim (" in page, "a writeup rendered without its structured claims"


async def test_a_record_without_research_says_zero_not_nothing(tools):
    """0 means research has not been run for it, which is not the same as saying
    no writeup exists - and is exactly what made this collection easy to miss."""
    page = await tools.get_vulnerability("CVE-2021-44228", sections=["research"])
    assert "## Research writeups - 0 total" in page
