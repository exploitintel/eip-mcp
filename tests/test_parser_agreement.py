"""The live suite's row parsers must agree with the renderers, in CI.

`tests/test_live_parameter_effects.py` reads rendered Markdown back into rows
so that a filter, a sort or a cursor can be checked against every row on the
page. Those parsers only run when `EIP_MCP_TEST_API_BASE_URL` is set, so they
never run here - and one of them drifted from its renderer and stayed broken,
reporting "returned nothing" while the tool returned correct rows.

This module runs the same parsers against recorded payloads and compares what
they read back against the payload they came from, so a renamed heading, a
moved separator, a reordered field or a wrong capture group fails on the pull
request that causes it. Presence is not enough: a parser that reads the public
id into the `source` field passes any check that only asks whether something
was read.

It asserts nothing about the API. It asserts only that our own two halves still
read each other.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from functools import partial
from pathlib import Path

import pytest

import test_live_parameter_effects as live  # pytest puts tests/ on sys.path
from eip_mcp_v3 import format as fmt
from eip_mcp_v3 import format_discovery as disc
from eip_mcp_v3 import format_labs as labs
from eip_mcp_v3.text import inline

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def _date(item: dict, field: str = "published_at") -> str | None:
    value = item.get(field)
    return value.split("T")[0] if value else None


def _lab_kinds(item: dict) -> list[str]:
    return [v for v in (item.get("anchor_kind"), item.get("shape")) if v]


# renderer, fixture, parser, {parsed field: how to read the same thing from the
# payload item}. Every field named here is compared by value, in order.
CASES: list[tuple[Callable, str, Callable, dict[str, Callable[[dict], object]]]] = [
    (disc.format_author_page, "authors_page", live.author_rows, {
        "name": lambda i: i["display_name"],
        "public_id": lambda i: i["public_id"],
        "source_scope": lambda i: i["source_scope"],
        "external_id": lambda i: i["external_id"],
        "roles": lambda i: set(i["roles"]),
    }),
    (fmt.format_poc_page, "pocs_page", live.artifact_rows, {
        "artifact_id": lambda i: i["artifact_id"],
        "source": lambda i: i["source"],
        "source_date": _date,
        "linked": lambda i: bool(i.get("vulnerability_count")),
    }),
    # A second poc page from a different source: within one page `source` is
    # constant, so on its own it cannot tell a correct parser from one
    # returning a literal. Its rows are dated differently too, which is what
    # keeps `source_date` from passing with a constant.
    (fmt.format_poc_page, "pocs_metasploit_page", live.artifact_rows, {
        "source": lambda i: i["source"],
        "source_date": _date,
    }),
    (fmt.format_search_page, "search_kev", live.vuln_rows, {
        "cve": lambda i: i["identifier"],
        # These four are read off the facts line. Blanking code spans to defeat
        # a forged label once blanked the values with them, which only the live
        # sort test caught; compare them here so it fails on the pull request.
        "epss": lambda i: i.get("epss_score"),
        "nuclei": lambda i: float(i.get("nuclei_count") or 0),
        "kev": lambda i: bool(i.get("cisa_kev")),
        "ransomware": lambda i: bool(i.get("known_ransomware")),
        # The three sort keys. `_comparable` catches an all-None column at live
        # runtime; these catch a single unread row on the pull request.
        "published": lambda i: _date(i),
        "cvss": lambda i: i.get("cvss_score"),
        "cvss_version": lambda i: i.get("cvss_version"),
        "severity": lambda i: i.get("cvss_severity"),
        "pocs": lambda i: float(i.get("poc_count") or 0),
    }),
    (fmt.format_code_search, "codesearch_jndi", live.code_rows, {
        "path": lambda i: i["path"],
    }),
    # A second page, so `path` is compared against two different corpora.
    (fmt.format_code_search, "codesearch_exploitdb_page", live.code_rows, {
        "path": lambda i: i["path"],
    }),
    (labs.format_lab_page, "labs_page", live.lab_rows, {
        "kinds": _lab_kinds,
    }),
    (partial(labs.format_lab_page, include_analysis=True), "labs_page", live.lab_rows, {
        "kinds": _lab_kinds,
        "linked": lambda i: bool(i.get("cve_ids")),
        "analysis": lambda i: bool(i.get("analysis")),
    }),
]

# Parsers whose rows are values, not dicts: the whole row is the compared value.
VALUE_CASES: list[tuple[Callable, str, Callable, Callable[[dict], object]]] = [
    (disc.format_vendor_page, "vendors_page", live.vendor_rows, lambda i: i["vendor"]),
    (disc.format_ecosystem_page, "ecosystems_page", live.ecosystem_rows,
     lambda i: i["ecosystem"]),
    (disc.format_weakness_page, "weaknesses_page", live.weakness_rows,
     lambda i: i["cwe_id"]),
    (disc.format_product_page, "products_page", live.product_rows,
     lambda i: (i["vendor"], i["product"])),
    (disc.format_package_page, "packages_page", live.package_rows,
     lambda i: (i["ecosystem"], i["package_name"])),
    (disc.format_ecosystem_page, "ecosystems_page", live.ecosystem_entries,
     lambda i: (i["ecosystem"], i["package_count"])),
    # Second vendor and ecosystem for the same reason: each of these pages is
    # filtered to one of them, so the column is constant within a page. The
    # pair discriminates because the two constants differ.
    (disc.format_product_page, "products_apache_page", live.product_rows,
     lambda i: (i["vendor"], i["product"])),
    (disc.format_package_page, "packages_pypi_page", live.package_rows,
     lambda i: (i["ecosystem"], i["package_name"])),
]


def _ids(cases) -> list[str]:
    # Fold the fixture in: several parsers appear twice, and a bare name gives
    # "artifact_rows0/1" without saying which corpus failed.
    return [f"{c[2].__name__}-{c[1]}" for c in cases]


@pytest.mark.parametrize("renderer,fixture,parse,fields", CASES, ids=_ids(CASES))
def test_the_parser_reads_back_what_the_renderer_was_given(
    renderer, fixture, parse, fields
) -> None:
    payload = _load(fixture)
    items = payload["items"]
    assert items, f"{fixture} carries no rows, so it proves nothing"

    rows = parse(renderer(payload))
    assert len(rows) == len(items), (
        f"{parse.__name__} read {len(rows)} of {len(items)} rendered rows"
    )
    for field, of_item in fields.items():
        assert [row.get(field) for row in rows] == [of_item(item) for item in items], (
            f"{parse.__name__} disagrees with the payload on {field}"
        )


@pytest.mark.parametrize("renderer,fixture,parse,of_item", VALUE_CASES, ids=_ids(VALUE_CASES))
def test_the_value_parser_reads_back_what_the_renderer_was_given(
    renderer, fixture, parse, of_item
) -> None:
    payload = _load(fixture)
    items = payload["items"]
    assert items, f"{fixture} carries no rows, so it proves nothing"
    # Vendors, ecosystems, products and packages drop an item whose name field
    # renders empty; weaknesses raise instead. For products and packages the
    # second tuple component is a parser precondition rather than a renderer
    # drop - the renderer just omits the line and the parser then skips the row.
    # Either way the failure would blame the parser, so state the precondition
    # here using the renderer's own predicate: `inline` collapses whitespace
    # and strips control characters before deciding a value is empty.
    expected = [of_item(item) for item in items]
    assert all(
        all(
            inline(v) and " ".join(str(v).split()) == str(v)
            for v in (e if isinstance(e, tuple) else (e,))
        )
        for e in expected
    ), f"{fixture} carries an item the renderer would drop or renormalise"
    assert parse(renderer(payload)) == expected


def test_the_weakness_fixture_still_mixes_record_types() -> None:
    """The parser splits on Weakness, Category and View; keep two of them here.

    Matching only "Weakness" returned nothing for an all-category page, which
    made the disjoint-page assertions pass vacuously. This fixture carries
    weakness and category records, so those two stay covered. No view record
    appeared on the recorded page, so that heading is split on but unexercised.
    """
    kinds = {item["record_type"] for item in _load("weaknesses_page")["items"]}
    assert {"weakness", "category"} <= kinds, kinds


def test_every_recorded_cursor_survives_the_round_trip() -> None:
    """`_cursor` has thirteen call sites and no coverage without this.

    A reworded cursor footer makes it return None, which turns every cursor
    assertion in the live suite into a silent skip or a wrong failure.
    """
    for renderer, fixture in (
        (fmt.format_poc_page, "pocs_page"),
        (fmt.format_search_page, "search_kev"),
        (fmt.format_code_search, "codesearch_jndi"),
    ):
        payload = _load(fixture)
        assert payload.get("next_cursor"), f"{fixture} records no cursor to check"
        assert live._cursor(renderer(payload)) == payload["next_cursor"], fixture


def test_an_empty_page_parses_as_no_rows_rather_than_raising() -> None:
    """The drift guard must stay silent when the corpus is genuinely empty."""
    for renderer, parse in (
        (disc.format_vendor_page, live.vendor_rows),
        (disc.format_author_page, live.author_rows),
        (disc.format_weakness_page, live.weakness_rows),
    ):
        assert parse(renderer({"items": [], "next_cursor": None})) == []

# ==========================================================================
# The guards themselves. Each of these behaviours existed with nothing
# executing it, so a regression in the guard was invisible.
# ==========================================================================


def test_a_renamed_heading_is_reported_as_drift_not_as_no_rows() -> None:
    """`_blocks` must accuse the renderer, not return an empty page."""
    page = disc.format_vendor_page(_load("vendors_page"))
    renamed = page.replace("## Vendor ", "## Supplier ")
    with pytest.raises(AssertionError, match="heading"):
        live.vendor_rows(renamed)


def test_a_row_the_parser_cannot_read_is_reported_not_dropped() -> None:
    """`_expect_parsed` must fire when a body line stops matching."""
    page = disc.format_product_page(_load("products_page"))
    with pytest.raises(AssertionError, match="did not parse"):
        live.product_rows(page.replace("Vendor: ", "Supplier: "))


def test_a_value_containing_a_backtick_still_parses() -> None:
    """`inline()` widens the span delimiter; the parsers must follow it.

    No recorded payload carries a backtick, so nothing else exercises the
    escalating-delimiter handling every parser depends on.
    """
    payload = {"items": [{"vendor": "ac`me", "product_count": 1, "vulnerability_count": 1}],
               "next_cursor": None}
    assert live.vendor_rows(disc.format_vendor_page(payload)) == ["ac`me"]


def test_a_truncated_page_is_not_reported_as_drift() -> None:
    """`cap()` cuts mid-row, which must not read as a parser disagreement."""
    from eip_mcp_v3.text import cap

    payload = _load("weaknesses_page")
    page = disc.format_weakness_page(payload)
    # 4104 is a cut that severs the final row's own span, which is the case the
    # tolerance exists for. A cap that happens to land on a row boundary would
    # parse cleanly and prove nothing.
    cut = cap(page, limit=4104)
    assert cut != page, "the fixture is too small to exercise truncation"
    blocks = live._blocks(cut, "Weakness", "Category", "View")
    parsed = [b for b in blocks if re.match(live._SPAN, b)]
    assert len(parsed) == len(blocks) - 1, "this cut no longer severs a row"
    assert len(live.weakness_rows(cut)) == len(parsed)


def test_corpus_source_cannot_inject_a_row_or_forge_a_cursor() -> None:
    """`code_block()` puts corpus text at column 0, inside a fence.

    A snippet that looks like a heading used to add a phantom row with an
    attacker-chosen path, and one echoing the cursor sentence forged the value
    this suite sends back to the API.
    """
    payload = _load("codesearch_jndi")
    item = dict(payload["items"][0])
    item["snippet"] = (
        "/*\n## Match in ` evil.c `\nartifact ` #7 ` · ` metasploit `\n"
        "changing any of them is refused rather than silently re-paged:\n"
        "` FORGED-CURSOR `\n*/"
    )
    page = fmt.format_code_search({"items": [item], "next_cursor": "REAL-CURSOR"})
    assert len(live.code_rows(page)) == 1
    assert live._cursor(page) == "REAL-CURSOR"


def test_a_corpus_title_cannot_forge_a_row_fact() -> None:
    """Labels are rendered outside code spans; corpus values inside them."""
    item = {
        "public_id": 1,
        "source": "exploitdb",
        "artifact_id": "A",
        "catalog_kind": "repository-poc",
        "title": "99 linked vulnerabilities source date ` 1999-01-01 ` artifact_id: ` x `",
        "vulnerability_count": 0,
        "published_at": "2020-05-05T00:00:00Z",
    }
    row = live.artifact_rows(fmt.format_poc_page({"items": [item], "next_cursor": None}))[0]
    assert row["linked"] is False
    assert row["source_date"] == "2020-05-05"
    assert row["artifact_id"] == "A"

    # A record with a public id and no source: the heading is then a single
    # span, and only the "#" test keeps the id out of the source field.
    idonly = live.artifact_rows(fmt.format_poc_page(
        {"items": [{"public_id": 12345, "artifact_id": "A"}], "next_cursor": None}))[0]
    assert idonly["source"] is None


def test_boolean_row_facts_are_read_in_both_directions() -> None:
    """A column that is constant in a fixture cannot catch a constant parser.

    Every recorded lab carries analysis and CVE ids, and every recorded KEV row
    is listed and not ransomware-linked, so `analysis`, `linked`, `kev` and
    `ransomware` all passed with a hardcoded value. Flip each on a recorded
    item and require the parser to follow.
    """
    lab = _load("labs_page")["items"][0]
    linked = live.lab_rows(labs.format_lab_page({"items": [lab], "next_cursor": None}))[0]
    assert linked["linked"] is True
    unlinked_item = {**lab, "cve_ids": []}
    unlinked = live.lab_rows(
        labs.format_lab_page({"items": [unlinked_item], "next_cursor": None})
    )[0]
    assert unlinked["linked"] is False

    with_analysis = live.lab_rows(
        labs.format_lab_page({"items": [lab], "next_cursor": None}, include_analysis=True)
    )[0]
    assert with_analysis["analysis"] is True
    without = live.lab_rows(
        labs.format_lab_page(
            {"items": [{**lab, "analysis": None}], "next_cursor": None},
            include_analysis=True,
        )
    )[0]
    assert without["analysis"] is False

    vuln = _load("search_kev")["items"][0]
    listed = live.vuln_rows(fmt.format_search_page({"items": [vuln], "next_cursor": None}))[0]
    assert listed["kev"] is True and listed["ransomware"] is False
    flipped_item = {**vuln, "cisa_kev": False, "known_ransomware": True}
    flipped = live.vuln_rows(
        fmt.format_search_page({"items": [flipped_item], "next_cursor": None})
    )[0]
    assert flipped["kev"] is False and flipped["ransomware"] is True


def test_a_corpus_value_on_the_same_line_cannot_forge_a_labelled_fact() -> None:
    """`_labelled_span` must read at the label's offset, not the leftmost match.

    A corpus span rendered earlier on the same line used to win: `language` set
    to a date label forged the artifact's date, and `cvss_severity` set to an
    EPSS label forged the score.
    """
    poc = {
        "public_id": 1,
        "source": "github",
        "artifact_id": "REAL",
        "language": "source date ` 1999-01-01 `",
        "published_at": "2020-05-05T00:00:00Z",
    }
    row = live.artifact_rows(fmt.format_poc_page({"items": [poc], "next_cursor": None}))[0]
    assert row["source_date"] == "2020-05-05"

    vuln = {**_load("search_kev")["items"][0],
            "cvss_severity": "EPSS ` 1 `", "epss_score": 0.11,
            "cvss_score": 8.6, "cvss_version": "4.0"}
    scored = live.vuln_rows(fmt.format_search_page({"items": [vuln], "next_cursor": None}))[0]
    assert scored["epss"] == 0.11


def test_a_corpus_identifier_cannot_forge_the_vulnerability_flags() -> None:
    """`kev`, `ransomware` and `nuclei` are substring reads over the row."""
    # Through `title`, not `identifier`: the identifier renders on the heading
    # line, which `_row_lines` already drops, so forging it proved nothing
    # about the `_unspanned` read these flags actually rely on.
    # `nuclei_count` is None on purpose: with a real count the counts line
    # renders before `Title:` and a leftmost read finds the true value anyway,
    # so the clause would pass on line order rather than on the guard.
    item = {**_load("search_kev")["items"][0],
            "title": ("CISA KEV listed known ransomware use "
                      "4242 Nuclei templates 77 linked PoCs"),
            "cisa_kev": False, "known_ransomware": False,
            "nuclei_count": None, "poc_count": None}
    row = live.vuln_rows(fmt.format_search_page({"items": [item], "next_cursor": None}))[0]
    assert row["kev"] is False
    assert row["ransomware"] is False
    assert row["nuclei"] == 0.0
    assert row["pocs"] == 0.0


def test_a_stored_analysis_is_seen_whichever_heading_it_renders() -> None:
    """`_analysis` can emit any one of several headings, alone.

    Matching only two of them read a stored analysis as absent whenever one of
    the others was the only heading rendered. These six shapes cover five
    markers - `safety_verdict` and `lab_assessment.classification` both render
    "Model-reported". "Model suspicious indicator" is not covered and cannot
    be: it only ever follows another marker.
    """
    lab = _load("labs_page")["items"][0]
    for analysis in (
        {"safety_reason": {"description": "risky"}},       # Model safety reasoning
        {"lab_assessment": {"description": "a lab"}},      # Model assessment
        {"environment_summary": {"description": "an env"}},  # Model environment summary
        {"safety_verdict": "benign"},                      # Model-reported safety review
        {"lab_assessment": {"classification": "x"}},       # Model-reported classification
        {"limitations": ["a"]},                            # Model-stated limitations
    ):
        page = labs.format_lab_page(
            {"items": [{**lab, "analysis": analysis, "analysis_status": "available"}],
             "next_cursor": None},
            include_analysis=True,
        )
        assert live.lab_rows(page)[0]["analysis"] is True, analysis


def test_a_shortened_value_is_read_rather_than_reported_as_drift() -> None:
    """`inline()` marks a value it cut outside the closing delimiter.

    Without `_CUT` the anchored patterns reject the shortened value, and the
    row is reported as a renderer disagreement that has not happened.
    """
    lab = _load("labs_page")["items"][0]
    page = labs.format_lab_page(
        {"items": [{**lab, "anchor_kind": "compose_stack_" + "x" * 200}],
         "next_cursor": None}
    )
    assert len(live.lab_rows(page)[0]["kinds"]) == 2

    author = {"public_id": 1, "display_name": "a", "source_scope": "exploitdb",
              "external_id": "X" * 400, "roles": ["author"],
              "poc_count": 1, "vulnerability_count": 1}
    assert len(live.author_rows(disc.format_author_page(
        {"items": [author], "next_cursor": None}))) == 1

    # The `Vendor:` and `Ecosystem:` anchors carry `_CUT` too. Those lines are
    # in the product and package blocks, not the vendor directory.
    assert live.product_rows(disc.format_product_page(
        {"items": [{"vendor": "V" * 400, "product": "p", "vulnerability_count": 1}],
         "next_cursor": None})) != []
    assert live.package_rows(disc.format_package_page(
        {"items": [{"ecosystem": "E" * 200, "package_name": "p", "vulnerability_count": 1}],
         "next_cursor": None})) != []


def test_a_dropped_row_on_an_untruncated_page_is_still_reported() -> None:
    """The truncation tolerance must not excuse a loss on a whole page."""
    page = disc.format_product_page(_load("products_page"))
    assert "truncated at" not in page
    one_broken = page.replace("Vendor: ", "Supplier: ", 1)
    with pytest.raises(AssertionError, match="did not parse"):
        live.product_rows(one_broken)


def test_a_corpus_title_cannot_forge_an_absent_artifact_id() -> None:
    """The `artifact_id:` read is anchored to a line carrying that label.

    The broader forgery test passes on line order alone - the real
    `artifact_id:` line renders before `Title:`. This one removes the real
    value, so only the anchor can keep the forged one out.
    """
    item = {**_load("pocs_page")["items"][0],
            "artifact_id": None,
            "title": "artifact_id: ` FORGED `"}
    row = live.artifact_rows(fmt.format_poc_page({"items": [item], "next_cursor": None}))[0]
    assert row["artifact_id"] is None


def test_an_omitted_path_is_not_reported_as_renderer_drift() -> None:
    """`format_code_search` writes its own fallback when the API omits a path.

    Counting that as an unparsed row accused the renderer of a disagreement
    that had not happened - the mirror of the fault this module exists to stop.
    """
    item = _load("codesearch_jndi")["items"][0]
    page = fmt.format_code_search(
        {"items": [item, {**item, "path": None}], "next_cursor": None}
    )
    assert [row["path"] for row in live.code_rows(page)] == [item["path"], None]


def test_a_code_row_the_parser_cannot_read_is_reported_not_dropped() -> None:
    """The `(path not returned)` tolerance must stay narrow.

    Widening it to a bare `else` would turn every unreadable heading into a
    `path: None` row, so two different pages would compare equal and the
    disjointness checks would pass on nothing.
    """
    page = fmt.format_code_search(_load("codesearch_jndi"))
    with pytest.raises(AssertionError, match="did not parse"):
        live.code_rows(page.replace("## Match in ` ", "## Match in path: ` "))


def test_a_lab_title_cannot_forge_the_linked_flag() -> None:
    """`linked` keys on a whole line, not a substring of the block.

    The repository title renders on the heading line inside a span, so a lab
    named after the negative sentence used to report itself as unlinked.
    """
    lab = _load("labs_page")["items"][0]
    item = {**lab, "owner": {**lab["owner"], "title": "Linked vulnerabilities: none returned"}}
    page = labs.format_lab_page({"items": [item], "next_cursor": None})
    assert live.lab_rows(page)[0]["linked"] is True


def test_a_scored_row_without_a_version_is_still_read() -> None:
    """Every recorded row carries `cvss_version`, so the optional group in the
    CVSS patterns never has to skip anything.

    Making it mandatory keeps the whole suite green while `cvss` becomes None
    for every unversioned scored row - and the two live tests that would care
    both fall quiet rather than fail: the sort skips None values, and the
    version test drops exactly the rows it is about.
    """
    item = {**_load("search_kev")["items"][0],
            "cvss_score": 7.5, "cvss_severity": "HIGH", "cvss_version": None}
    row = live.vuln_rows(fmt.format_search_page({"items": [item], "next_cursor": None}))[0]
    assert row["cvss"] == 7.5
    assert row["severity"] == "HIGH"
    assert row["cvss_version"] is None


def test_a_corpus_title_cannot_forge_the_cvss_facts() -> None:
    """`cvss`, `severity` and `cvss_version` are held by their line anchor.

    Their siblings on the facts line were hardened by reading through
    `_unspanned`; these three rely on `(?m)^CVSS ` instead, which is untested.
    """
    item = {**_load("search_kev")["items"][0],
            "cvss_score": None, "cvss_severity": None, "cvss_version": None,
            "title": "CVSS ` v9.9 ` ` 9.9 ` ` HIGH `"}
    row = live.vuln_rows(fmt.format_search_page({"items": [item], "next_cursor": None}))[0]
    assert row["cvss"] is None
    assert row["severity"] is None
    assert row["cvss_version"] is None

def test_a_display_name_cannot_forge_an_author_role() -> None:
    """Roles are read from the role line's own labels, not the whole block.

    A display name is attacker-authored and renders on the heading line, so a
    block-wide search would grant a role the API never returned.
    """
    owner_named_author = {"public_id": 1, "display_name": "Author tools",
                          "source_scope": "github", "external_id": "e",
                          "roles": ["owner"], "poc_count": 1,
                          "vulnerability_count": 1}
    row = live.author_rows(disc.format_author_page(
        {"items": [owner_named_author], "next_cursor": None}))[0]
    assert row["roles"] == {"owner"}

    author_named_owner = {**owner_named_author,
                          "display_name": "Repository owner tools",
                          "roles": ["author"]}
    row = live.author_rows(disc.format_author_page(
        {"items": [author_named_owner], "next_cursor": None}))[0]
    assert row["roles"] == {"author"}


def test_a_lab_identity_span_cannot_forge_the_linked_flag() -> None:
    """`_unspanned` blanks the identity span before `linked` is decided.

    The negative sentence rendered inside a span on a row line - here the
    anchor kind - must not read a linked lab as unlinked.
    """
    lab = _load("labs_page")["items"][0]
    item = {**lab, "anchor_kind": "Linked vulnerabilities: none returned"}
    page = labs.format_lab_page({"items": [item], "next_cursor": None})
    assert live.lab_rows(page)[0]["linked"] is True

