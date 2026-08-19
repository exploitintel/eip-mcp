"""Guard against re-introducing EIPv2's synthesized exploit ranking.

The legacy EIPv2 MCP server computed an exploit score from Metasploit
reliability ranks, the ExploitDB `verified` flag, and GitHub star counts.
EIP v3 policy forbids all three as EIP judgments. These tests fail if that
behaviour ever returns.
"""

import inspect
import re
from functools import partial

import pytest
from markdown_it import MarkdownIt

from eip_mcp_v3 import format as fmt
from eip_mcp_v3 import (
    format_artifact,
    format_common,
    format_discovery,
    format_labs,
    format_stix,
    format_system,
)
from renderer_inventory import ALL_RENDERERS

FORMAT_MODULES = (
    fmt,
    format_artifact,
    format_common,
    format_discovery,
    format_labs,
    format_stix,
    format_system,
)


def _formatter_source() -> str:
    return "\n".join(inspect.getsource(module) for module in FORMAT_MODULES)


BANNED_SOURCE_TOKENS = (
    "github_stars",
    "exploit_rank",
    "_MSF_RANKS",
    "reliability",
    "_rank_exploit",
    "_risk_verdict",
    # The three upstream data fields the legacy score was actually built from.
    # Legacy *identifier* names alone were not enough, and this is not
    # hypothetical: a reviewer reintroduced the score under the fresh name
    # `_quality()`, computed from `item["verified"]` and `item["stars"]` and
    # rendered onto every PoC catalog line, and the whole suite still passed.
    # `stars` is a real field on every repository-inventory item and `verified`
    # is real ExploitDB metadata, so naming the fields is what closes the hole.
    # `rank` is matched only in its quoted dict-key forms, because the module
    # docstring uses the bare word to forbid ranking in the first place.
    "stars",
    "verified",
    '"rank"',
    "'rank'",
)

BANNED_OUTPUT_PHRASES = (
    "verified working",
    "confirmed working",
    "known working",
    "highly reliable",
    "safe to execute",
    "safe to run",
    "eip score",
    "eip confidence",
    "eip quality",
    "exploit rank",
    # A clearance asserted in EIP's own voice. The list above covered "safe to run"
    # and "verified working" but not "cleared", so mutating the benign backdoor-review
    # label from `backdoor review` to `backdoor review (cleared)` survived the whole
    # suite - EIP editorialising an all-clear on top of a model's verdict, which is
    # the one thing this server must never do. The model's verdict is the model's to
    # state; EIP prints it verbatim and adds no adjective.
    "cleared",
    "backdoor-free",
    "no backdoors",
    "malware-free",
    "vetted",
    "audited",
    "trustworthy",
    "passed review",
    "review passed",
    "deemed safe",
    "looks safe",
)


def _banned_tokens_in(source: str) -> list[str]:
    """Return every banned ranking input that appears in ``source``."""
    return [token for token in BANNED_SOURCE_TOKENS if token in source]


def test_formatter_source_has_no_ranking_inputs():
    found = _banned_tokens_in(_formatter_source())
    assert not found, f"formatter references banned ranking inputs {found}"


# The exact mutation that walked through the previous version of this guard: a
# fresh function name, so not one of the six legacy identifiers matched, and a
# fresh output phrase, so not one of the nine banned phrases matched either -
# but EIPv2's score all the same, rebuilt from the same two upstream fields.
_SCORE_REBUILT_UNDER_A_NEW_NAME = """
def _quality(item: dict[str, Any]) -> str:
    score = 500.0 if item["verified"] else 300.0
    score += item["stars"] * 1.5
    return f"[EIP quality {score:.0f}]"
"""


def test_the_guard_catches_a_score_rebuilt_under_a_new_name():
    """The guard has to bite on the data fields, not just on legacy spellings.

    Grepping for identifier names only ever catches a copy-paste of EIPv2. This
    pins the property that matters: source that reads `verified` or `stars` to
    manufacture a number is caught whatever the function and the label are called.
    """
    assert _banned_tokens_in(_SCORE_REBUILT_UNDER_A_NEW_NAME), (
        "the guard does not catch EIPv2's score rebuilt from `verified` and `stars` "
        "under an unrecognised name"
    )


def test_formatter_never_sorts_or_scores():
    source = _formatter_source()
    assert "sorted(" not in source, "formatter must preserve API ordering and never re-sort results"


@pytest.mark.parametrize("case", ALL_RENDERERS, ids=lambda case: case.name)
def test_rendered_output_makes_no_quality_claim(case, request):
    """Every renderer, not a sample of them: the guard is only as wide as its list."""
    data = request.getfixturevalue(case.payload) if isinstance(case.payload, str) else case.payload
    lowered = case.renderer(data).lower()
    # "cleared" is banned because EIP must never assert a clearance. "not cleared"
    # asserts the absence of one, which is the disclaimer the analysis legend
    # exists to make - the safe direction, and the opposite claim. Removing the
    # negated form first keeps the ban on the dangerous direction only.
    lowered = lowered.replace("not cleared", "")
    for phrase in BANNED_OUTPUT_PHRASES:
        assert phrase not in lowered, f"output contains banned claim {phrase!r}"


# The exact mutation that walked through the previous version of the phrase list:
# not a fabricated score, but an EIP-authored adjective placed on top of a model's
# verdict. The line still shows the verdict verbatim, which is why every other
# assertion in the suite stayed green.
_CLEARANCE_IN_EIPS_OWN_VOICE = (
    "[model-classified: ` exploit `; backdoor review (cleared): ` no_backdoor_observed `]"
)


def test_the_guard_catches_a_clearance_asserted_in_eips_own_voice():
    lowered = _CLEARANCE_IN_EIPS_OWN_VOICE.lower()
    assert any(phrase in lowered for phrase in BANNED_OUTPUT_PHRASES), (
        "the guard does not catch EIP editorialising an all-clear over a model verdict"
    )


# --------------------------------------------------------------------------
# Round 2, important 6: a heading a reader attributes to EIP must be EIP's.
#
# `f"## {heading}"` built the whole heading text out of a corpus identifier, so an
# artifact identified as `Stored analysis` rendered a genuine `##` heading whose
# text collides with this module's own section names. The code span made the value
# inert, which is a different property: an inert value can still occupy a whole
# heading line and be read as the renderer's own section.
# --------------------------------------------------------------------------

# Values chosen to collide with headings this module writes for itself.
COLLIDING = "Stored analysis"

HEADING_PAYLOADS = [
    (fmt.format_vulnerability, {"identifier": COLLIDING, "pocs": {"total": 2, "items": []}}),
    (fmt.format_search_page, {"items": [{"identifier": COLLIDING}]}),
    (fmt.format_poc_page, {"items": [{"public_id": COLLIDING, "source": "Exploitation context"}]}),
    (fmt.format_poc_detail, {"public_id": COLLIDING, "artifact_id": COLLIDING}),
    (fmt.format_code_search, {"items": [{"path": COLLIDING, "snippet": "x"}]}),
    (format_system.format_file_list, {"artifact_id": COLLIDING, "items": []}),
    (format_system.format_file_content, {"path": COLLIDING, "content": "x"}),
    (format_system.format_readiness, {"status": COLLIDING, "code_search_status": COLLIDING}),
    (
        partial(format_system.format_statistics, trends=None, series="none"),
        {"vulnerabilities": 1},
    ),
    (format_artifact.format_artifact, {"artifact_id": COLLIDING}),
    (
        format_labs.format_lab_page,
        {"items": [{"public_id": COLLIDING, "owner": {"title": COLLIDING}}]},
    ),
]


def _headings(out: str) -> list:
    """The inline token of every heading in ``out``."""
    parsed = MarkdownIt("commonmark").parse(out)
    return [parsed[i + 1] for i, token in enumerate(parsed) if token.type == "heading_open"]


@pytest.mark.parametrize("renderer,payload", HEADING_PAYLOADS)
def test_no_heading_is_written_by_the_corpus(renderer, payload):
    """Every heading opens with EIP's own words.

    That one assertion is the whole property, because the two voices are already
    distinguishable in the token stream: EIP writes plain text into a heading and
    every corpus value reaches output as a code span. A heading whose first child
    is a span is a heading the corpus owns - `## `Stored analysis`` - even though
    the span makes the value inert. Inert is not the same as attributable.
    """
    out = renderer(payload)
    headings = _headings(out)
    assert headings, "the renderer wrote no heading, so this proves nothing"
    for heading in headings:
        first = (heading.children or [None])[0]
        assert first is not None and first.type == "text", (
            f"heading opens with a {first and first.type!r} the corpus supplied: "
            f"{heading.content!r}"
        )
        assert first.content.strip(), f"heading opens with empty EIP text: {heading.content!r}"


@pytest.mark.parametrize(
    "renderer,payload",
    [entry for entry in HEADING_PAYLOADS if COLLIDING in str(entry[1])],
)
def test_a_corpus_value_kept_out_of_a_heading_is_still_disclosed(renderer, payload):
    """Containment, not deletion: the value the corpus sent is still on the page."""
    assert COLLIDING in renderer(payload)


@pytest.mark.parametrize("case", ALL_RENDERERS, ids=lambda case: case.name)
def test_no_heading_is_written_by_the_corpus_on_recorded_data(case, request):
    """The same property on real recorded responses rather than crafted ones."""
    data = request.getfixturevalue(case.payload) if isinstance(case.payload, str) else case.payload
    for heading in _headings(case.renderer(data)):
        first = (heading.children or [None])[0]
        assert first is not None and first.type == "text" and first.content.strip(), (
            f"heading not opened by EIP's own words: {heading.content!r}"
        )


@pytest.mark.parametrize("case", ALL_RENDERERS, ids=lambda case: case.name)
def test_hostile_payload_is_inert_across_every_renderer(case):
    rendered = case.renderer(case.hostile_payload)
    assert "PWNED" in rendered, f"{case.name} hostile fixture was discarded rather than contained"
    flat = []
    for token in MarkdownIt("commonmark").parse(rendered):
        flat.append(token)
        flat.extend(token.children or [])
    forbidden = {"link_open", "image", "html_inline", "html_block"}
    assert not ({token.type for token in flat} & forbidden)
    for heading in _headings(rendered):
        first = (heading.children or [None])[0]
        assert first is not None and first.type == "text" and first.content.strip()


# --------------------------------------------------------------------------
# Round 3: the two guards above are blocklists, and both were walked through.
#
#   * `test_formatter_source_has_no_ranking_inputs` greps six legacy identifiers
#     and two data fields, so a score synthesized from fields it does not name -
#     `Coverage score: n/5` from `file_count` and `vulnerability_count` - passed
#     the whole suite.
#   * `test_formatter_never_sorts_or_scores` greps the literal string `sorted(`,
#     so `items.sort(...)`, `heapq.nsmallest`, or `items[::-1]` re-ordered every
#     result page with nothing to stop them.
#
# Both are replaced below by properties of the rendered output. The greps stay:
# they cost nothing and they fail earlier and more legibly when someone really
# does paste EIPv2 back in.
# --------------------------------------------------------------------------

# A standalone number, not a digit run inside a word: `sha256:` and `CVE-2021` are
# names EIP or the corpus writes, not quantities EIP computed.
_NUMBER = re.compile(r"(?<![A-Za-z0-9.])\d+(?:\.\d+)?(?![A-Za-z0-9.])")

# Prose this module writes for itself that happens to contain a digit - the 1 MiB
# in the viewability policy, the maximum in the section-limit hint. Collected from
# the module rather than listed here, so a new sentence cannot silently widen the
# guard by being forgotten, and a new *number* in EIP prose has to be a constant
# someone deliberately wrote. Dunders are skipped: `__file__` is a path this process
# happens to have, not prose anyone wrote for a reader.
_EIP_PROSE = [
    value
    for module in FORMAT_MODULES
    for name, value in vars(module).items()
    if not name.startswith("__")
    and isinstance(value, str)
    and len(value) >= 8
    and any(char.isdigit() for char in value)
]


def _plain_text(markdown: str) -> str:
    """The text tokens of ``markdown``, joined - everything outside a span or fence.

    Corpus values reach output only inside a code span or a fence - that is the
    containment invariant the rest of this suite pins - so what survives here is
    exactly the renderer's own voice.
    """
    flat = []
    for token in MarkdownIt("commonmark").parse(markdown):
        flat.append(token)
        flat.extend(token.children or [])
    return " ".join(token.content for token in flat if token.type == "text")


# The scrub has to compare like with like. `_SECTION_MORE_DEFAULT` is
# "Raise `section_limit` (maximum 50) to show more.", and by the time that reaches
# the page the code span is a separate token, so the text stream reads
# "Raise   (maximum 50) to show more." - which the raw constant never matched.
# The 50 escaped the scrub for the whole of round 2 and traced only because
# `vuln_log4shell.json` happens to contain a 50.
_EIP_PROSE_TEXT = sorted(
    (text for prose in _EIP_PROSE if (text := _plain_text(prose).strip())),
    key=len,
    reverse=True,
)


def _numbers_eip_wrote(out: str) -> list[str]:
    """Every number on a rendered page that EIP itself put there.

    A number in EIP's own voice is a number this module chose to print, and it has
    to come from somewhere.
    """
    text = _plain_text(out)
    for prose in _EIP_PROSE_TEXT:
        text = text.replace(prose, " ")
    # EIP groups digits for readability; the payload does not.
    return _NUMBER.findall(text.replace(",", ""))


# The only two fields this module ever subtracts from that are not a collection
# size: `_section_lines` takes `total - len(shown)`, and `_cve_list_line` takes
# `vulnerability_count - len(listed)`. Every other subtraction has a cardinality on
# the left. Naming them is what keeps the lattice narrow - admitting *any* payload
# scalar as a minuend lets `19 - 2` and `29 - 12` account for a fabricated 17,
# where 19 and 29 are line numbers inside a citation.
_TOTAL_KEYS = ("total", "vulnerability_count")


def _scalars_and_lengths(payload) -> tuple[set, set[int], set[int]]:
    """Every number the API sent, every collection size, and every declared total.

    A dict counts as a collection: `_claim_data` renders a claim's free-form `data`
    object field by field and discloses how many it left out, so the number of keys
    in an object is a cardinality this module can legitimately count and subtract
    from, exactly as a list's length is.
    """
    ints: set = set()
    lengths: set[int] = set()
    totals: set[int] = set()

    def walk(node) -> None:
        if isinstance(node, dict):
            lengths.add(len(node))
            for key, value in node.items():
                if key in _TOTAL_KEYS and isinstance(value, int) and not isinstance(value, bool):
                    totals.add(value)
                walk(value)
        elif isinstance(node, list):
            lengths.add(len(node))
            for entry in node:
                walk(entry)
        elif isinstance(node, bool) or node is None:
            return
        elif isinstance(node, (int, float)):
            ints.add(node)

    walk(payload)
    return ints, lengths, totals


# The collection ceilings this module bounds by, named one at a time rather than
# swept out of `vars(fmt)`: a sweep would pull in the character ceilings too
# (`_POINTER_MAX`, `_CURSOR_MAX`, `_VERDICT_MAX`) and quietly widen the lattice of
# admissible differences by two orders of magnitude. Nothing is *counted* with those.
_COLLECTION_CEILINGS = frozenset(
    {
        fmt._ALIAS_LIMIT,
        fmt._CWE_LINE_LIMIT,
        fmt._CLAIM_FIELD_LIMIT,
        fmt._CLAIM_LIST_LIMIT,
        fmt._CVE_LIMIT,
        fmt._LINK_LIMIT,
        fmt._ASSOCIATION_LIMIT,
        fmt._CITATION_LIMIT,
        fmt._FINDING_LIMIT,
        fmt._OBSERVABLE_LIMIT,
        fmt._LIST_LIMIT,
        fmt._LIMITATION_LIMIT,
        format_common._SERIES_LIMIT,
        format_common._POINT_LIMIT,
        format_common._FILE_LIMIT,
        format_common._COVERAGE_LIMIT,
    }
)
# Protocol/version labels EIP writes literally rather than deriving from corpus
# values. STIX 2.1 is the export contract, not a score or measured quantity.
_FIXED_PROTOCOL_NUMBERS = {"2.1"}


def _untraceable_numbers(out: str, payload, *, limits=()) -> list[str]:
    """Numbers on the page that the payload and this module's ceilings cannot account for.

    A rendered number is legitimate when it is one of:

      * a value the API sent;
      * the size of a collection the API sent;
      * ``min(ceiling, size)`` - what a bounded collection showed, where the ceiling
        is one of this module's own or the ``section_limit`` the caller passed;
      * ``a - b`` where ``a`` is a collection size or a declared ``total`` and ``b``
        is one of the counts above or a ceiling - every "…410 more omitted",
        "…34 more listed", "…4 more finding(s) omitted" line on any page.

    That last shape is the one the previous version of this property did not admit.
    It allowed only ``rendered_number - size``, so ``459 total - section_limit 13``
    came out untraceable, and the suite passed at ``section_limit=3`` only because
    `vuln_log4shell.json` happens to contain a 3. Anything outside the lattice -
    a sum, a product, a scaled rank, a ratio - is manufactured.
    """
    ints, lengths, declared = _scalars_and_lengths(payload)
    ceilings = _COLLECTION_CEILINGS | {int(value) for value in limits}
    shown = {min(ceiling, size) for ceiling in ceilings for size in lengths}
    remainders = {
        total - taken
        for total in declared | lengths
        for taken in shown | lengths | ceilings
        if total - taken > 0
    }
    allowed = (
        _FIXED_PROTOCOL_NUMBERS
        | {str(value) for value in ints}
        | {str(value) for value in lengths | shown | remainders}
    )
    return sorted({number for number in _numbers_eip_wrote(out) if number not in allowed})


@pytest.mark.parametrize("case", ALL_RENDERERS, ids=lambda case: case.name)
def test_every_number_on_the_page_comes_from_the_payload(case, request):
    """A count may be counted or subtracted. A score is neither."""
    data = request.getfixturevalue(case.payload) if isinstance(case.payload, str) else case.payload
    untraceable = _untraceable_numbers(case.renderer(data), data)
    assert not untraceable, f"numbers with no source in the payload: {untraceable}"


# Section limits chosen so that none of the numbers they produce is already in
# `vuln_log4shell.json`. At `section_limit=3` the guard passed by coincidence: 3 is
# a collection size in that fixture, 50 is a value in it, and the remainders landed
# on values it holds. These do not, so a pass here is a pass for the right reason.
_LIMITS_ABSENT_FROM_THE_FIXTURE = (13, 17, 23)


@pytest.mark.parametrize("section", fmt.VULN_SECTIONS)
@pytest.mark.parametrize("section_limit", (3, *_LIMITS_ABSENT_FROM_THE_FIXTURE))
def test_every_number_in_an_expanded_section_comes_from_the_payload(
    log4shell, section, section_limit
):
    out = fmt.format_vulnerability(log4shell, sections=[section], section_limit=section_limit)
    untraceable = _untraceable_numbers(out, log4shell, limits=(section_limit,))
    assert not untraceable, f"numbers with no source in the payload: {untraceable}"


@pytest.mark.parametrize("section_limit", _LIMITS_ABSENT_FROM_THE_FIXTURE)
def test_the_guard_still_bites_at_a_limit_the_fixture_does_not_contain(log4shell, section_limit):
    """The pass above must not be another coincidence.

    A guard that admits everything passes everywhere. At each of these limits the
    fabricated number below is still caught, on the same page whose own counters
    are accepted - so the lattice widened for the module's arithmetic and not for
    a score.
    """
    out = fmt.format_vulnerability(
        log4shell, sections=list(fmt.VULN_SECTIONS), section_limit=section_limit
    )
    assert "8734" in _untraceable_numbers(
        f"{out}\nEIP priority 8734 of 10000", log4shell, limits=(section_limit,)
    )


def test_every_number_in_the_statistics_page_comes_from_the_payload(statistics, trends):
    out = format_system.format_statistics(statistics, trends, "all")
    untraceable = _untraceable_numbers(out, {"totals": statistics, "trends": trends})
    assert not untraceable, f"numbers with no source in the payload: {untraceable}"


def test_the_guard_catches_the_exact_score_the_blocklist_let_through(poc_trojan):
    """`Coverage score: n/5` from two fields the banned-token list does not name.

    16 files plus 1 linked CVE is 17, and 17 appears nowhere in this payload -
    which is the whole point: a sum of two counts is not a count, so it cannot be
    traced, so it is caught however it is spelled and whatever it is called.
    """
    score = poc_trojan["file_count"] + poc_trojan["vulnerability_count"]
    mutated = f"{fmt.format_poc_detail(poc_trojan)}\nCoverage score: {score}/5"
    assert _untraceable_numbers(mutated, poc_trojan) == [str(score)]


def test_the_guard_catches_a_score_of_any_magnitude(poc_trojan):
    """Not just sums: a weighted product, a percentage, a scaled rank."""
    mutated = f"{fmt.format_poc_detail(poc_trojan)}\nEIP priority 8734 of 10000"
    assert "8734" in _untraceable_numbers(mutated, poc_trojan)


def test_the_guard_does_not_object_to_a_disclosed_truncation_remainder(log4shell):
    """The one arithmetic this module is allowed: total minus what it showed."""
    out = fmt.format_vulnerability(log4shell, sections=["references"], section_limit=3)
    assert "…76 more omitted" in out
    assert not _untraceable_numbers(out, log4shell)


# --- ordering: the payload's order is the page's order -------------------------

_ORDER = ("m-40", "m-05", "m-90", "m-10", "m-70", "m-20")


def _positions(out: str) -> list[int]:
    found = [(out.index(marker), marker) for marker in _ORDER if marker in out]
    assert len(found) == len(_ORDER), f"only {len(found)} of {len(_ORDER)} markers rendered"
    return [marker for _, marker in sorted(found)]


ORDERING_CASES = [
    (
        fmt.format_search_page,
        {"items": [{"identifier": marker} for marker in _ORDER]},
    ),
    (
        fmt.format_poc_page,
        {"items": [{"public_id": 1, "title": marker} for marker in _ORDER]},
    ),
    (
        fmt.format_code_search,
        {"items": [{"path": marker, "snippet": "x"} for marker in _ORDER]},
    ),
    (
        format_system.format_file_list,
        {"artifact_id": "a", "items": [{"path": marker, "size": 1} for marker in _ORDER]},
    ),
    (
        fmt.format_poc_detail,
        {
            "public_id": 1,
            "vulnerabilities": {
                "total": len(_ORDER),
                "items": [{"identifier": marker} for marker in _ORDER],
            },
        },
    ),
    (
        # Every item carries the same (absent) catalog kind, so the `pocs` section
        # renders them as one group and the whole payload order has to survive. This
        # is the *within-group* half of the property; the between-group half is
        # `test_the_poc_section_is_grouped_in_the_documented_sequence` below.
        partial(fmt.format_vulnerability, sections=["pocs"], section_limit=len(_ORDER)),
        {
            "identifier": "CVE-0000-0300",
            "pocs": {
                "total": len(_ORDER),
                "items": [{"public_id": 1, "title": marker} for marker in _ORDER],
            },
        },
    ),
    (
        partial(fmt.format_vulnerability, sections=["references"], section_limit=len(_ORDER)),
        {
            "identifier": "CVE-0000-0301",
            "references": {
                "total": len(_ORDER),
                "items": [{"data": {"url": marker}} for marker in _ORDER],
            },
        },
    ),
    (
        partial(format_system.format_statistics, series="all"),
        {"vulnerabilities": 1},
    ),
]


@pytest.mark.parametrize("renderer,payload", ORDERING_CASES[:-1])
def test_rendered_order_is_the_payload_order(renderer, payload):
    """The markers are deliberately non-monotonic in every direction.

    `m-40, m-05, m-90, m-10, m-70, m-20` is neither ascending nor descending, so a
    re-sort by any mechanism - `sorted()`, `list.sort()`, `heapq`, a reversed
    slice, a key function - changes the rendered order and fails here. The old
    guard grepped the literal `sorted(` and saw none of the others.
    """
    assert _positions(renderer(payload)) == list(_ORDER)


# --- grouping: a partition is not a ranking, and this is what makes that true ----
#
# The `pocs` section groups its rows under the four catalog-kind headings the EIP web
# interface has used for this same collection since before this server existed. That
# reorders rows relative to the payload, which is exactly what the guard above exists
# to catch - so the guard is not relaxed for it, it is replaced by a strictly stronger
# statement of the same property:
#
#   * within a group, the rendered order is still the payload order, item for item;
#   * between groups, the order is `fmt.POC_GROUP_TITLES` - a constant of the module,
#     identical on every page, and influenced by no payload value.
#
# Together those two say a row's position is a function of its API-supplied
# `catalog_kind` and its API-supplied index, composed with one fixed permutation of
# four names. Nothing this server computed from the data can move a row. The old
# assertion - rendered order equals payload order - is the special case of this where
# every row shares a kind, and that case is still asserted above.
#
# The markers stay non-monotonic, and the kinds below deliberately interleave: the
# payload order is *not* the grouped order, so a renderer that quietly stopped
# grouping would fail here just as a renderer that re-sorted within a group would.
_INTERLEAVED = (
    ("m-40", "repository-candidate"),
    ("m-05", "exploitdb-exploit"),
    ("m-90", "repository-poc"),
    ("m-10", "metasploit-auxiliary"),
    ("m-70", "repository-candidate"),
    ("m-20", "a-kind-this-server-has-never-heard-of"),
)

_GROUPED_PAYLOAD = {
    "identifier": "CVE-0000-0302",
    "pocs": {
        "total": len(_INTERLEAVED),
        "items": [
            {"public_id": 1, "catalog_kind": kind, "title": marker} for marker, kind in _INTERLEAVED
        ],
    },
}

# What the two rules above require of `_GROUPED_PAYLOAD`, written out by hand rather
# than computed from the module: a test that derives its expectation from the code it
# is testing agrees with any grouping the code happens to implement.
_GROUPED_EXPECTED = [
    ("Catalogued exploits", ["m-05", "m-10"]),
    ("Curated repository PoCs", ["m-90"]),
    ("Repository PoC candidates", ["m-40", "m-70"]),
    ("Other PoC artifacts", ["m-20"]),
]


def _group_layout(out: str) -> list:
    """Every `### ` group heading on ``out``, with the markers rendered under it."""
    layout: list = []
    for line in out.splitlines():
        if line.startswith("### "):
            layout.append((line[4:], []))
        elif layout:
            layout[-1][1].extend(marker for marker in _ORDER if marker in line)
    return [(title, markers) for title, markers in layout if markers]


def _render_grouped(limit: int = len(_INTERLEAVED)) -> str:
    return fmt.format_vulnerability(_GROUPED_PAYLOAD, sections=["pocs"], section_limit=limit)


def test_the_poc_section_is_grouped_in_the_documented_sequence():
    """Group order is the module's constant, and every group heading is one of it."""
    layout = _group_layout(_render_grouped())
    assert [title for title, _ in layout] == list(fmt.POC_GROUP_TITLES)
    assert layout == _GROUPED_EXPECTED


def test_rendered_order_inside_each_poc_group_is_the_payload_order():
    """The old property, now scoped to where it still applies - and still bitten by
    the same non-monotonic markers a re-sort of any kind would disturb."""
    payload_order = {
        title: [marker for marker, kind in _INTERLEAVED if kind in kinds]
        for title, kinds in (
            ("Catalogued exploits", {"exploitdb-exploit", "metasploit-auxiliary"}),
            ("Curated repository PoCs", {"repository-poc"}),
            ("Repository PoC candidates", {"repository-candidate"}),
            ("Other PoC artifacts", {"a-kind-this-server-has-never-heard-of"}),
        )
    }
    assert dict(_group_layout(_render_grouped())) == payload_order


def test_the_grouping_guard_catches_a_reorder_inside_a_group():
    """A guard that admits every layout proves nothing about this one.

    Two rows of one group are swapped and nothing else moves, which is the smallest
    ranking a re-sort could impose and the one a heading-level check would miss.
    """
    out = _render_grouped()
    swapped = out.replace("m-40", "\0").replace("m-70", "m-40").replace("\0", "m-70")
    layout = dict(_group_layout(swapped))
    assert set(layout) == set(dict(_GROUPED_EXPECTED)), "the mutation broke the grouping itself"
    assert layout["Repository PoC candidates"] == ["m-70", "m-40"]
    assert _group_layout(swapped) != _GROUPED_EXPECTED


def test_the_grouping_guard_catches_a_group_order_that_is_not_the_documented_one():
    out = _render_grouped()
    swapped = out.replace("### Catalogued exploits", "### Repository PoC candidates", 1)
    titles = [title for title, _ in _group_layout(swapped)]
    assert len(titles) == len(fmt.POC_GROUP_TITLES), "the mutation dropped a group heading"
    assert titles != list(fmt.POC_GROUP_TITLES)


def test_every_documented_poc_group_title_is_reachable_from_a_catalog_kind():
    """A title no payload can produce is a heading no reader will ever see explained.

    The fallback group is reachable by construction - anything unmapped lands there -
    so this is really asserting that the three named groups are each spelled the way
    the kind map spells them.
    """
    reached = {title for title, _ in _group_layout(_render_grouped())}
    assert reached == set(fmt.POC_GROUP_TITLES)


def test_a_grouped_section_still_renders_every_number_from_the_payload():
    """Grouping adds headings, and it must not add arithmetic.

    Per-group counts would be the easy thing to print and the wrong one: a group size
    is a cardinality of a collection *this module* formed, so admitting it would widen
    the lattice below to every subset size of the payload.
    """
    out = _render_grouped()
    assert not _untraceable_numbers(out, _GROUPED_PAYLOAD, limits=(len(_INTERLEAVED),))


def test_a_truncated_group_absence_is_disclosed_rather_than_read_as_zero():
    """The API returns this collection already partitioned, so a cut falls on whole
    groups. A heading that is simply past the cut must not read as "none of these"."""
    out = _render_grouped(limit=2)
    assert "Curated repository PoCs" not in out
    assert fmt.POC_GROUP_OMISSION_NOTE in out


def test_an_untruncated_section_makes_no_claim_about_omitted_groups():
    out = _render_grouped()
    assert fmt.POC_GROUP_OMISSION_NOTE not in out


def test_the_grouping_rule_states_that_the_sequence_is_not_a_ranking():
    """The one thing a fixed sequence can be misread as, denied in EIP's own words."""
    out = _render_grouped()
    assert out.count(fmt.POC_GROUP_RULE) == 1
    lowered = fmt.POC_GROUP_RULE.lower()
    assert "catalog_kind" in lowered
    # The property is that the rule disclaims a ranking, not that it uses any
    # particular synonym for one. Pinning exact words made this fail against a
    # shorter rule saying the same thing.
    assert "not a ranking" in lowered or "no ranking" in lowered
    assert "presentation" in lowered
    # The group order runs catalogued -> curated -> candidates, which reads as
    # a vetted-to-unvetted quality ordering unless it is disclaimed. Trimming
    # this rule once narrowed it to "not ranking" alone; these pin the rest of
    # what it must deny, matching what CODE_SEARCH_NOTE denies of its order.
    for denied in ("quality", "preference", "works"):
        assert denied in lowered, f"the rule no longer disclaims {denied!r}"


def test_rendered_series_order_is_the_payload_order():
    trends = {
        "as_of": "2026-01-01T00:00:00Z",
        "catalog_additions": [{"label": marker, "points": []} for marker in _ORDER],
    }
    out = format_system.format_statistics({"vulnerabilities": 1}, trends, "catalog_additions")
    assert _positions(out) == list(_ORDER)


def test_rendered_point_order_is_the_payload_order():
    points = [{"period": f"2020-01-0{n}", "count": 1} for n in range(1, 7)]
    trends = {"catalog_additions": [{"label": "s", "points": points}]}
    out = format_system.format_statistics({"vulnerabilities": 1}, trends, "catalog_additions")
    rendered = next(line for line in out.splitlines() if "2020-01" in line)
    assert [point["period"] for point in points] == re.findall(r"2020-01-0\d", rendered)


# Every surface that prints a stored verdict must say whose verdict it is. The
# detail page carries ANALYSIS_LABEL; the catalog lines have no room for it, so
# the attribution has to be in the label itself. It was not: `model-classified`
# sat beside a bare `backdoor review` on the same line, attributing the safety
# claim to EIP on the two surfaces a reader sees most.
_VERDICT_SURFACES = [
    (
        "poc_page",
        lambda v: fmt.format_poc_page(
            {"items": [{"public_id": "1", "analysis": {"backdoor_review": {"verdict": v}}}]}
        ),
    ),
    (
        "poc_detail",
        lambda v: fmt.format_poc_detail(
            {"public_id": "1", "analysis": {"backdoor_review": {"verdict": v}}}
        ),
    ),
    (
        "code_search",
        lambda v: fmt.format_code_search(
            {"items": [{"path": "a.py", "analysis": {"backdoor_review": {"verdict": v}}}]}
        ),
    ),
]


@pytest.mark.parametrize("label,render", _VERDICT_SURFACES, ids=[s[0] for s in _VERDICT_SURFACES])
@pytest.mark.parametrize("verdict", ["no_backdoor_observed", "trojan", "not_a_real_verdict"])
def test_a_rendered_verdict_is_always_attributed_to_a_model(label, render, verdict):
    page = render(verdict)
    if verdict not in page:
        pytest.skip(f"{label} does not render a verdict for this shape")
    for line in page.splitlines():
        if verdict not in line:
            continue
        lowered = line.lower()
        assert "model" in lowered, (
            f"{label} printed a stored verdict with nothing naming it a model's: {line!r}"
        )


# A row with no stored analysis carried no flag at all, so on a 100-row catalog
# page an unanalysed artifact was visually identical to a reviewed-and-benign one
# and blank read as "not flagged". The detail page has always said this properly -
# "the absence of a finding, not a finding of absence" - while the list pages let
# silence do the asserting.
_ROW_STATES = {
    "unanalysed": {"public_id": "1"},
    "empty_analysis": {"public_id": "1", "analysis": {}},
    # Truthy but renders to nothing. These are the cases that distinguish a gate
    # on `.get("verdict")` from a gate on the RENDERED verdict: they passed the
    # first, rendered blank, and reinstated the unflagged row this flag exists to
    # prevent. `None` and `""` cannot tell the two gates apart.
    "whitespace_verdict": {"public_id": "1", "analysis": {"backdoor_review": {"verdict": "   "}}},
    "zero_width_verdict": {
        "public_id": "1",
        "analysis": {"backdoor_review": {"verdict": "\u200b"}},
    },
    "tab_verdict": {"public_id": "1", "analysis": {"backdoor_review": {"verdict": "\t"}}},
    "benign": {
        "public_id": "1",
        "analysis": {"backdoor_review": {"verdict": "no_backdoor_observed"}},
    },
    "classified_only": {"public_id": "1", "analysis": {"technical": {"classification": "exploit"}}},
}


@pytest.mark.parametrize(
    "state",
    ["unanalysed", "empty_analysis", "whitespace_verdict", "zero_width_verdict", "tab_verdict"],
)
def test_an_unanalysed_row_says_so_rather_than_staying_blank(state):
    page = fmt.format_poc_page({"items": [_ROW_STATES[state]]})
    assert f"[{fmt.NO_ANALYSIS_FLAG}]" in page


@pytest.mark.parametrize("state", ["benign", "classified_only"])
def test_an_analysed_row_does_not_claim_to_be_unanalysed(state):
    page = fmt.format_poc_page({"items": [_ROW_STATES[state]]})
    assert f"[{fmt.NO_ANALYSIS_FLAG}]" not in page


def test_the_unanalysed_flag_claims_neither_clean_nor_dirty():
    """EIP must not turn 'nobody looked' into either verdict.

    The disclaimer moved from the row to the section legend when the row marker
    was shortened, so the property is asserted over both - together they are what
    the reader actually sees, and the row alone would now under-state it.
    """
    legend = fmt.ANALYSIS_LEGEND.lower()
    assert "not been examined" in legend and "not cleared" in legend
    assert "absence of a finding, not a finding of absence" in legend
    # And neither half may carry a verdict of EIP's own.
    for text in (fmt.NO_ANALYSIS_FLAG.lower(), legend):
        for verdict in ("clean", "safe", "benign", "suspicious", "malicious", "trojan"):
            assert verdict not in text, f"{verdict!r} in {text!r}"


def test_an_unanalysed_and_an_analysed_row_are_distinguishable_on_one_page():
    page = fmt.format_poc_page({"items": [_ROW_STATES["unanalysed"], _ROW_STATES["benign"]]})
    flagged = [ln for ln in page.splitlines() if "[" in ln and "]" in ln]
    assert len(flagged) == 2, flagged
    assert flagged[0] != flagged[1]


def test_no_prompt_instructs_the_model_using_a_quality_adjective():
    """The renderers are guarded against derived judgment; the prompts were not,
    and one told the model to follow up "promising hits" - EIP's own adjective
    about corpus material it makes no quality claim over.

    Deliberately narrow. These same words appear all over `prompts.py` in the
    disclaimers that *forbid* the judgment ("Do not describe any exploit as
    working, verified, or reliable"), and a guard that fired on those would be
    weakened the first time it went off. So it looks only at the instruction
    prompts the tools actually emit, and only for the adjective attached to a
    corpus hit.
    """
    from eip_mcp_v3 import prompts

    emitted = " ".join(
        (
            prompts.triage_cve("CVE-2021-44228"),
            prompts.hunt_technique("deserialisation"),
            prompts.screen_exploit_safety("4b33f0e8-923e-55d9-91bc-39efd00e5268"),
            prompts.corpus_report("log4j"),
        )
    ).lower()
    for phrase in (
        "promising",
        "best ",
        "high-quality",
        "trustworthy",
        "most reliable",
        "worth trying",
    ):
        assert phrase not in emitted, f"a prompt instructs the model using {phrase!r}"


# The no-reordering rule was guarded by `assert "sorted(" not in source`, which a
# fresh spelling walks straight past: `json.dumps(..., sort_keys=True)` reorders
# real output and the scan cannot see it. Asserted behaviourally instead.
def test_nested_corpus_values_keep_the_order_the_api_sent():
    payload = {"zebra": 1, "alpha": 2, "middle": 3}
    rendered = fmt._flatten({"versions": [{"deep": {"deeper": {"deepest": payload}}}]})
    positions = [rendered.index(key) for key in ("zebra", "alpha", "middle")]
    assert positions == sorted(positions), (
        f"keys were reordered; the API sent zebra, alpha, middle: {rendered}"
    )


def test_a_value_deep_enough_to_be_dumped_as_json_also_keeps_its_order():
    """Past `_CLAIM_NESTED_DEPTH` the value is serialised, not flattened."""
    payload = {"zebra": 1, "alpha": 2, "middle": 3}
    nested = payload
    for _ in range(fmt._CLAIM_NESTED_DEPTH + 2):
        nested = {"wrap": nested}
    rendered = fmt._flatten(nested)
    positions = [rendered.index(key) for key in ("zebra", "alpha", "middle")]
    assert positions == sorted(positions), f"JSON fallback reordered keys: {rendered}"


def test_no_prompt_teaches_the_superseded_two_call_workflow():
    """`triage_cve` told the model to fetch a brief and then call again for PoCs.

    A default `get_vulnerability` now returns both, so following that prompt
    literally makes the redundant second call the default was changed to remove.
    The prompts are what a calling model reads to learn the tool, so leaving them
    describing the old shape quietly undoes the change.
    """
    from eip_mcp_v3 import prompts

    emitted = " ".join(
        (
            prompts.triage_cve("CVE-2021-44228"),
            prompts.hunt_technique("deserialisation"),
            prompts.screen_exploit_safety("4b33f0e8-923e-55d9-91bc-39efd00e5268"),
            prompts.corpus_report("log4j"),
            prompts.USAGE_GUIDE,
        )
    )
    for stale in ("no sections to get the bounded brief", "call get_vulnerability again"):
        assert stale not in emitted, f"a prompt still teaches: {stale!r}"


# Log4Shell's PoC list carried the long "not examined, not cleared" sentence on all
# ten rows. The row must still declare its own state - a group-level count would
# leave a reader unable to tell WHICH rows it covered - but the explanation, and
# the pointer to where the analysis actually lives, belong once per section.
def test_the_unanalysed_marker_is_short_and_still_on_every_row():
    page = fmt.format_poc_page({"items": [{"public_id": str(n)} for n in range(4)]})
    assert page.count(f"[{fmt.NO_ANALYSIS_FLAG}]") == 4
    assert "not examined, not cleared]" not in page, "the long form is back on the rows"


def test_the_legend_appears_once_and_names_where_the_analysis_is(log4shell):
    page = fmt.format_vulnerability(log4shell, sections=["pocs"], section_limit=10)
    assert page.count(fmt.ANALYSIS_LEGEND) == 1
    assert "get_exploit" in fmt.ANALYSIS_LEGEND, (
        "the flag says a verdict exists; the legend must say how to read it"
    )
    assert "absence of a finding, not a finding of absence" in fmt.ANALYSIS_LEGEND


def test_a_section_with_no_analysis_flags_gets_no_legend(log4shell):
    """Derived from what rendered, not from the section name."""
    page = fmt.format_vulnerability(log4shell, sections=["references"], section_limit=3)
    assert fmt.ANALYSIS_LEGEND not in page


def test_the_legend_follows_an_analysed_row_too():
    page = fmt.format_poc_page(
        {"items": [{"public_id": "1", "analysis": {"technical": {"classification": "exploit"}}}]}
    )
    assert f"[{fmt.NO_ANALYSIS_FLAG}]" not in page
    assert "model-classified" in page


# `_analysis_flags` has two callers: `_poc_item`, behind `get_vulnerability`'s
# sections, and `format_poc_page`, behind `search_exploits`. Wiring the legend to
# only the first left the catalog page showing the SHORTENED marker with nothing
# to explain it - strictly less than it said before the marker was shortened, on a
# live tool path. Both surfaces are asserted here so a third caller cannot be
# added without one.
@pytest.mark.parametrize(
    "label,render",
    [
        (
            "catalog page",
            lambda a: fmt.format_poc_page({"items": [{"public_id": "1", **a}]}),
        ),
        (
            "vulnerability section",
            lambda a: fmt.format_vulnerability(
                {
                    "identifier": "CVE-2026-1",
                    "pocs": {"total": 1, "items": [{"public_id": "1", **a}]},
                },
                sections=["pocs"],
                section_limit=5,
            ),
        ),
    ],
)
@pytest.mark.parametrize(
    "analysis",
    [
        {},
        {"analysis": {"technical": {"classification": "exploit"}}},
        {"analysis": {"backdoor_review": {"verdict": "trojan"}}},
    ],
    ids=["unanalysed", "classified", "verdict"],
)
def test_every_surface_carrying_a_flag_also_carries_the_legend(label, render, analysis):
    page = render(analysis)
    assert any(m in page for m in fmt._ANALYSIS_FLAG_MARKERS), f"{label} rendered no flag"
    assert fmt.ANALYSIS_LEGEND in page, f"{label} explains its flag nowhere"


def test_a_page_with_no_rows_carries_no_legend():
    assert fmt.ANALYSIS_LEGEND not in fmt.format_poc_page({"items": []})


def test_the_legend_helper_is_the_only_way_it_is_emitted():
    """Guards the wiring: both call sites must go through the shared helper, so a
    third surface cannot render a flag and silently skip the explanation."""
    import inspect

    source = inspect.getsource(fmt)
    # One definition, and every use is the helper - never a bare append.
    assert source.count("lines.append(ANALYSIS_LEGEND)") == 0
    assert source.count("_analysis_legend_lines(") >= 3  # def + two call sites
