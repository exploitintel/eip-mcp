"""Every bounded collection must say what it left out, and count it correctly.

The module docstring of `format.py` states the rule - "a bounded section always
discloses what it left out" - and the suite tested it on three collections out of
sixteen. Seven mutants survived the whole suite as a result: `_more`'s `> 0`
flipped to `> 1`, every off-by-one in a slice, and four omission notices deleted
outright (citations, observables, findings, linked vulnerabilities).

Each case below feeds a collection exactly one item more than its ceiling. That is
the boundary every one of those mutants lives on: at limit+1 the correct renderer
discloses exactly one omitted item, `> 1` discloses nothing, an off-by-one slice
discloses two or zero, and a deleted notice discloses nothing.

Each case also feeds the collection exactly `limit` items and asserts silence, so a
renderer that always claims an omission is caught too.
"""

from functools import partial

import pytest

from eip_mcp_v3 import format as fmt
from eip_mcp_v3 import format_system as system_fmt

_REFERENCES = partial(fmt.format_vulnerability, sections=["references"], section_limit=3)

# Marker text long enough that a partial render cannot accidentally match, short
# enough that no per-field ceiling truncates it.
def _markers(count: int) -> list[str]:
    return [f"entry-{n:03d}" for n in range(count)]


def _detail_with_review(**review) -> dict:
    return {
        "public_id": 1,
        "analysis": {
            "model": "m",
            "technical": {"classification": "exploit"},
            "backdoor_review": {"verdict": "suspicious", **review},
        },
    }


def _detail_with_technical(**technical) -> dict:
    return {
        "public_id": 1,
        "analysis": {
            "model": "m",
            "technical": {"classification": "exploit", **technical},
            "backdoor_review": {"verdict": "suspicious"},
        },
    }


def _findings(count: int) -> dict:
    return _detail_with_review(
        findings=[{"category": marker, "text": "t"} for marker in _markers(count)]
    )


def _observables(count: int) -> dict:
    return _detail_with_review(
        observables=[{"type": "t", "value": marker} for marker in _markers(count)]
    )


def _citations(count: int) -> dict:
    return _detail_with_review(
        findings=[
            {
                "category": "c",
                "text": "t",
                "citations": [{"path": marker, "line_start": 1} for marker in _markers(count)],
            }
        ]
    )


def _limitations(count: int) -> dict:
    return _detail_with_review(limitations=_markers(count))


def _attack_types(count: int) -> dict:
    return _detail_with_technical(attack_types=_markers(count))


def _linked_vulnerabilities(count: int) -> dict:
    return {
        "public_id": 1,
        "vulnerabilities": {
            "total": count,
            "items": [{"identifier": marker} for marker in _markers(count)],
        },
    }


def _association_providers(count: int) -> dict:
    return {
        "public_id": 1,
        "vulnerabilities": {
            "total": 1,
            "items": [{"identifier": "CVE-0000-0001", "association_providers": _markers(count)}],
        },
    }


def _cve_list(count: int) -> dict:
    return {
        "items": [
            {
                "public_id": 1,
                "vulnerability_ids": _markers(count),
                "vulnerability_count": count,
            }
        ]
    }


def _files(count: int) -> dict:
    return {
        "artifact_id": "a",
        "items": [{"path": marker, "size": 1} for marker in _markers(count)],
    }


def _series(count: int) -> dict:
    return {
        "catalog_additions": [{"label": marker, "points": []} for marker in _markers(count)]
    }


def _coverage(count: int) -> dict:
    return {
        "poc_supply": [],
        "poc_date_coverage": [
            {"source": marker, "dated": 1, "total": 2} for marker in _markers(count)
        ],
    }


def _aliases(count: int) -> dict:
    return {"identifier": "CVE-0000-0002", "identifiers": ["CVE-0000-0002", *_markers(count)]}


def _cwes(count: int) -> dict:
    return {"identifier": "CVE-0000-0003", "cwe_ids": [f"CWE-{n:03d}" for n in range(count)]}


def _section(count: int) -> dict:
    return {
        "identifier": "CVE-0000-0004",
        "references": {"total": count, "items": [{"data": {"url": m}} for m in _markers(count)]},
    }


def _claim_fields(count: int) -> dict:
    return {
        "identifier": "CVE-0000-0005",
        "references": {
            "total": 1,
            "items": [{"data": {marker: "v" for marker in _markers(count)}}],
        },
    }


def _claim_list(count: int) -> dict:
    return {
        "identifier": "CVE-0000-0006",
        "references": {"total": 1, "items": [{"data": {"tags": _markers(count)}}]},
    }


def _statistics(payload: dict) -> str:
    return system_fmt.format_statistics({"vulnerabilities": 1}, payload, "all")


# (name, ceiling, payload builder, renderer, the disclosure, the last kept item)
CASES = [
    ("findings", 5, _findings, fmt.format_poc_detail, "…1 more finding(s) omitted.", "entry-004"),
    (
        "observables",
        8,
        _observables,
        fmt.format_poc_detail,
        "…1 more observable(s) omitted.",
        "entry-007",
    ),
    (
        "citations",
        6,
        _citations,
        fmt.format_poc_detail,
        "…1 more citation(s) omitted.",
        "entry-005",
    ),
    (
        "limitations",
        6,
        _limitations,
        fmt.format_poc_detail,
        "…1 more limitation(s) omitted.",
        "entry-005",
    ),
    ("attack types", 8, _attack_types, fmt.format_poc_detail, "…and 1 more listed", "entry-007"),
    (
        "linked vulnerabilities",
        10,
        _linked_vulnerabilities,
        fmt.format_poc_detail,
        "…1 more omitted.",
        "entry-009",
    ),
    (
        "association providers",
        4,
        _association_providers,
        fmt.format_poc_detail,
        "…and 1 more provider(s)",
        "entry-003",
    ),
    (
        "linked CVEs",
        10,
        _cve_list,
        fmt.format_poc_page,
        "…and 1 more on this artifact",
        "entry-009",
    ),
    ("files", 200, _files, system_fmt.format_file_list, "1 omitted.", "entry-199"),
    ("series", 8, _series, _statistics, "…1 more series omitted.", "entry-007"),
    ("coverage rows", 20, _coverage, _statistics, "1 omitted.", "entry-019"),
    ("aliases", 10, _aliases, fmt.format_vulnerability, "…and 1 more alias(es)", "entry-009"),
    ("cwe ids", 10, _cwes, fmt.format_vulnerability, "…and 1 more listed", "CWE-009"),
    ("claim fields", 8, _claim_fields, _REFERENCES, "…and 1 more field(s)", "entry-007"),
    ("claim list", 6, _claim_list, _REFERENCES, "…and 1 more value(s)", "entry-005"),
]


@pytest.mark.parametrize("name,ceiling,build,renderer,disclosure,last", CASES)
def test_one_item_past_the_ceiling_is_disclosed_and_counted(
    name, ceiling, build, renderer, disclosure, last
):
    out = renderer(build(ceiling + 1))
    assert disclosure in out, f"{name}: no disclosure at ceiling+1"


@pytest.mark.parametrize("name,ceiling,build,renderer,disclosure,last", CASES)
def test_the_last_item_before_the_ceiling_still_renders(
    name, ceiling, build, renderer, disclosure, last
):
    """An off-by-one that drops the final item is a silent omission, not a disclosed one."""
    assert last in renderer(build(ceiling)), f"{name}: the item at the ceiling was dropped"


@pytest.mark.parametrize("name,ceiling,build,renderer,disclosure,last", CASES)
def test_a_collection_exactly_at_its_ceiling_discloses_nothing(
    name, ceiling, build, renderer, disclosure, last
):
    """"…and 1 more" on a complete list is a fabricated omission."""
    out = renderer(build(ceiling))
    assert disclosure not in out, f"{name}: claimed an omission that did not happen"


@pytest.mark.parametrize("name,ceiling,build,renderer,disclosure,last", CASES)
def test_two_items_past_the_ceiling_are_counted_as_two(
    name, ceiling, build, renderer, disclosure, last
):
    """The count in the notice is the count, not a constant."""
    out = renderer(build(ceiling + 2))
    assert disclosure.replace("1", "2", 1) in out, f"{name}: miscounted the omission"


# --------------------------------------------------------------------------
# `_section_lines`: the section ceiling the caller chooses.
# --------------------------------------------------------------------------


def test_a_section_one_item_past_its_limit_discloses_exactly_one():
    out = fmt.format_vulnerability(_section(4), sections=["references"], section_limit=3)
    assert "Showing 3 of 4." in out
    assert "- …1 more omitted." in out


def test_a_section_exactly_at_its_limit_discloses_nothing():
    out = fmt.format_vulnerability(_section(3), sections=["references"], section_limit=3)
    assert "Showing 3 of 3." in out
    assert "more omitted" not in out


# --------------------------------------------------------------------------
# `_total`: a real zero is an answer, and must not be replaced by a count of
# the items that happen to be in hand.
# --------------------------------------------------------------------------


def test_a_real_zero_total_is_kept_even_when_items_are_present():
    """`if total is not None` mutated to `if total` fabricates a count from `items`.

    A response of `{"total": 0, "items": [...]}` is contradictory, but the total is
    the field that states the corpus fact and the items are a page. Falling back to
    `len(items)` invents a corpus claim the API did not make.
    """
    assert fmt._total({"total": 0, "items": [{}, {}]}) == 0


def test_a_zero_total_with_items_renders_as_zero():
    data = {"identifier": "CVE-0000-0007", "references": {"total": 0, "items": [{}, {}]}}
    out = fmt.format_vulnerability(data, sections=["references"])
    assert "## References - 0 total" in out


def test_a_missing_total_still_falls_back_to_the_items_in_hand():
    assert fmt._total({"items": [{}, {}]}) == 2
    assert fmt._total({}) is None


# --------------------------------------------------------------------------
# `_render_series`: the window is labelled "most recent", so it must be the
# most recent. `points[-12:]` mutated to `points[:12]` renders the oldest
# twelve under a label saying the newest.
# --------------------------------------------------------------------------


def _points(count: int) -> dict:
    points = [{"period": f"2020-01-{n:02d}", "count": n} for n in range(1, count + 1)]
    return {"catalog_additions": [{"label": "s", "points": points}]}


def test_the_series_window_holds_the_most_recent_points_not_the_oldest():
    out = _statistics(_points(13))
    assert "2020-01-01" not in out, "the oldest point was rendered under a 'most recent' label"
    assert "2020-01-02" in out
    assert "2020-01-13" in out


def test_the_series_window_discloses_how_much_it_dropped():
    assert "most recent 12 of 13" in _statistics(_points(13))


def test_a_series_inside_the_window_discloses_no_window():
    out = _statistics(_points(12))
    assert "most recent" not in out
    assert "2020-01-01" in out


# `remaining = len(items) - _LINK_LIMIT` subtracted from what ARRIVED, not from
# what the corpus holds. On a record with 934 links and a 100-item page it printed
# "…90 more omitted." - understating by 824, in EIP's own voice, in the direction
# that makes a reader stop looking.
def test_the_linked_vulnerability_omission_counts_against_the_corpus_total():
    page = fmt._linked_vulnerability_lines(
        {
            "total": 934,
            "truncated": True,
            "items": [{"identifier": f"CVE-2021-{n:05d}"} for n in range(100)],
        }
    )
    text = "\n".join(page)
    assert "934" in text
    assert "924 more omitted" in text, text
    assert "90 more omitted" not in text


def test_no_omission_notice_when_everything_is_shown():
    page = fmt._linked_vulnerability_lines(
        {"total": 3, "items": [{"identifier": f"CVE-2021-{n:05d}"} for n in range(3)]}
    )
    assert not any("omitted" in line for line in page)


def test_the_omission_notice_names_no_tool_that_cannot_answer():
    """`search_exploits` takes no artifact id and returns PoC artifacts, not the
    CVEs linked to one artifact. Naming it was advice a reader cannot act on."""
    page = "\n".join(
        fmt._linked_vulnerability_lines(
            {"total": 934, "truncated": True,
             "items": [{"identifier": f"CVE-2021-{n:05d}"} for n in range(100)]}
        )
    )
    assert "924 more omitted" in page
    assert "search_exploits" not in page
    assert "no tool on this server pages this list" in page


def test_the_omission_notice_says_nothing_extra_when_all_items_arrived():
    page = "\n".join(
        fmt._linked_vulnerability_lines(
            {
                "total": 50,
                "items": [{"identifier": f"CVE-2021-{n:05d}"} for n in range(50)],
            }
        )
    )
    assert "40 more omitted" in page
    assert fmt._LINKS_UNREACHABLE not in page, (
        "all 50 were in the response; only the render limit hid them"
    )


# Two different reasons an item is missing, and only one is the caller's to fix.
# `total - len(items)` never arrived - the API says so with `truncated` - and no
# `section_limit` reaches those. Collapsing the two told a reader looking at a
# section reporting 130 with 100 in the payload to raise a knob that could not
# have helped, and never said the response had withheld anything.
def _references(total, present, limit):
    return fmt.format_vulnerability(
        {
            "identifier": "CVE-2026-1",
            "references": {
                "total": total,
                "truncated": present < total,
                "items": [{"url": f"https://example.test/{n}"} for n in range(present)],
            },
        },
        sections=["references"],
        section_limit=limit,
    )


def test_items_the_response_withheld_are_disclosed_separately():
    page = _references(total=130, present=100, limit=10)
    assert "120 more omitted" in page
    assert "30 are not in this response at all" in page
    assert "no `section_limit` reaches them" in page


def test_at_the_ceiling_the_knob_is_not_prescribed():
    page = _references(total=130, present=100, limit=fmt.SECTION_LIMIT_MAX)
    assert "already at its maximum" in page
    assert "to show more" not in page


def test_when_nothing_that_arrived_was_cut_the_knob_is_not_mentioned():
    """All 20 present items rendered; the missing 30 are purely the API's doing."""
    page = _references(total=50, present=20, limit=fmt.SECTION_LIMIT_MAX)
    assert "30 more omitted" in page
    assert "not in this response at all" in page
    assert "Raise `section_limit`" not in page


def test_a_complete_section_claims_no_omission():
    page = _references(total=5, present=5, limit=10)
    assert "omitted" not in page
    assert "not in this response" not in page


# `read_exploit_file` takes only `artifact_id` and `path` - no cursor, no offset -
# so a 499-file manifest showing 200 leaves 299 paths unreachable through this
# tool. "299 omitted" alone invited the reader to look for a knob that does not
# exist, and let a screening pass treat a partial manifest as the whole artifact.
def test_an_omitted_manifest_tail_says_it_cannot_be_paged():
    page = system_fmt.format_file_list(
        {"artifact_id": "a", "items": [{"path": f"f{n}.py", "size": 1} for n in range(499)]}
    )
    assert "299 omitted" in page
    assert system_fmt.MANIFEST_UNREACHABLE in page
    assert "has not seen them" in page


def test_a_complete_manifest_carries_no_such_warning():
    page = system_fmt.format_file_list(
        {"artifact_id": "a", "items": [{"path": "f.py", "size": 1}]}
    )
    assert "omitted" not in page
    assert system_fmt.MANIFEST_UNREACHABLE not in page


def test_the_manifest_notice_does_not_prescribe_a_parameter_that_cannot_help():
    """The failure mode being fixed is naming a knob the caller has no access to."""
    assert "cursor" in system_fmt.MANIFEST_UNREACHABLE
    assert "takes no cursor or offset" in system_fmt.MANIFEST_UNREACHABLE


# The withheld-only branch REPLACED the hint rather than appending it, so a
# section with its own tool pointer lost that pointer exactly when the response
# was shortest - the one case where the route out matters most.
def test_a_routed_section_keeps_its_pointer_when_the_response_withheld_items():
    page = fmt.format_vulnerability(
        {
            "identifier": "CVE-2026-1",
            "pocs": {
                "total": 50,
                "truncated": True,
                "items": [{"public_id": str(n)} for n in range(20)],
            },
        },
        sections=["pocs"],
        section_limit=fmt.SECTION_LIMIT_MAX,
    )
    assert "30 more omitted" in page
    assert fmt._SECTION_WITHHELD_ONLY in page
    assert "search_exploits" in page, (
        "the one actionable route was dropped exactly where the section is most "
        "incomplete"
    )


def test_an_unrouted_section_does_not_invent_a_pointer():
    page = fmt.format_vulnerability(
        {
            "identifier": "CVE-2026-1",
            "references": {
                "total": 50,
                "truncated": True,
                "items": [{"url": f"https://e.test/{n}"} for n in range(20)],
            },
        },
        sections=["references"],
        section_limit=fmt.SECTION_LIMIT_MAX,
    )
    assert fmt._SECTION_WITHHELD_ONLY in page
    assert "search_exploits" not in page


# `total` is corpus-controlled and `items` is what arrived; a response can
# disagree with itself, and `_section_lines` says so explicitly. Counting the
# omission only against `total` made a response that reported FEWER than it sent
# drop rows with no notice at all.
def test_a_response_reporting_fewer_links_than_it_sent_still_discloses_the_cut():
    page = "\n".join(
        fmt._linked_vulnerability_lines(
            {"total": 5, "items": [{"identifier": f"CVE-2021-{n:05d}"} for n in range(20)]}
        )
    )
    assert "10 more omitted" in page, page


def test_the_link_omission_uses_the_larger_of_the_two_counts():
    page = "\n".join(
        fmt._linked_vulnerability_lines(
            {"total": 40, "items": [{"identifier": f"CVE-2021-{n:05d}"} for n in range(20)]}
        )
    )
    assert "30 more omitted" in page, page
