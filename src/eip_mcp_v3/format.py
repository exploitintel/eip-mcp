"""Markdown renderers for EIP API responses.

Rendering rules, non-negotiable:
  * Show only what the API returned, in the order it returned it.
  * Never compute a score, rank, verdict, or quality signal.
  * Missing values are omitted, never rendered as a fabricated default.
  * Absence renders as absence. A pass that did not run never renders as a pass
    that ran and found nothing, and an unrecognised verdict is surfaced rather
    than swallowed: the reader may decide whether to open hostile code on this.
  * Untrusted corpus text is always sanitized, attributable, and inert: every
    corpus value on a trusted line is a code span, every multi-line value a fenced
    block. Every page states that convention once, in `UNTRUSTED_NOTE`, and that
    one statement is what makes per-line labelling unnecessary - a line EIP opens
    with its own noun needs no tag, because the noun is the attribution.
  * A bounded section always discloses what it left out, and a page cut by the
    tool layer's ceiling names the sections it lost.
  * A rule stated once beats the same rule restated per line: what a source date
    means, and that corpus text is untrusted, are page-level facts.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from .format_common import (
    _AUTHOR_ROLE_LABELS,
    _POINTER_MAX,
    _PROVENANCE_FIELDS,
    _SOURCE_FIELDS,
    _count,
    _cursor_line,
    _date,
    _labelled,
    _mapping,
    _number,
    _objects,
    _plain,
    _quantity,
    _sequence,
    format_provenance,
)
from .text import (
    CORPUS_LABEL,
    UNTRUSTED_NOTE,
    code_block,
    inline,
    one_line,
    untrusted_block,
    was_truncated,
)

# Every heading this module writes opens with a noun this module chose, and a
# corpus value may only ever follow it. A heading whose entire text comes from the
# corpus is one the reader attributes to EIP: an artifact whose identifier is
# `Stored analysis` renders a genuine `##` heading that collides with this module's
# own section names, and the code span around it does nothing about that - a span
# stops a value becoming *live* Markdown, not becoming a heading EIP appears to
# have written. The corpus value stays fully visible; it just never owns the line.

VULN_SECTIONS: tuple[str, ...] = (
    "pocs",
    "artifacts",
    "related_artifacts",
    "nuclei",
    "labs",
    "references",
    "writeups",
    "affected",
    "weaknesses",
    "lifecycle",
    # The twelfth collection the API returns, and the only one this renderer did
    # not know existed: absent from this tuple, from `_SUMMARY_ONLY` and from
    # `_COUNT_MEANINGS`, so it was dropped from the page AND from the inventory
    # that tells a reader what a page is holding back. It is empty on a record
    # whose research has not been run, which is what made it easy to miss - a
    # zero read as "nothing here" rather than "not yet analysed".
    "research",
)

# What `get_vulnerability` expands when the caller names nothing. The page used to
# default to none of them: a brief plus an index, so the ordinary question - "tell
# me about this CVE" - cost two calls and a decision about which section name the
# reader wanted. That is a worse trade than it looks, because the caller is usually
# a model that has to guess before it has seen the page.
#
# So `sections` narrows rather than widens. Omitted, you get the sections below;
# name some and you get exactly those; pass an empty list for the brief alone.
# `cap()` still bounds the result and still names what it dropped, so the ceiling
# does the work the caller was previously asked to do up front.
#
# Not in the default, and each for a reason: `artifacts` is a superset of `pocs`
# mixed with Nuclei templates and lab units, so it repeats the PoC list under
# identifiers `get_exploit` cannot open; `related_artifacts` is empty on every
# record sampled; `labs` runs to 79 rows of Docker unit identifiers that only a
# reader building an environment wants.
DEFAULT_SECTIONS: tuple[str, ...] = (
    "pocs",
    "nuclei",
    "research",
    "writeups",
    "references",
    "affected",
    "weaknesses",
    "lifecycle",
)

# `artifact_links` is the eleventh collection the API returns and the one section
# deliberately not expandable. It is the raw vulnerability-to-artifact edge table -
# 934 rows on Log4Shell - and every row is a pair of identifiers the reader already
# has (the CVE they asked for, and an opaque artifact UUID) plus the provider, claim
# key and pointer behind that one edge. Expanding it would spend the whole section
# budget restating the `pocs` and `artifacts` collections without their titles,
# sources or dates. The evidence itself is not lost: `get_exploit` renders every
# association for one artifact, with its provider, claim key and pointer. So the
# count is disclosed here, and the summary says where the evidence lives.
_SUMMARY_ONLY: tuple[str, ...] = ("artifact_links",)
# Kept to a fragment on purpose: the brief has a size ceiling it earns its value
# from, and the only thing a reader must not do is call `sections` with this name.
_SUMMARY_ONLY_NOTE = "(`sections` does not take this name.)"

# What each count is counting, for the three that a reader would otherwise try to
# reconcile against one another. One response reported `8 catalogued exploits`,
# `407 repository candidates`, `pocs: 415`, `artifacts: 459` and
# `artifact_links: 934` with nothing on the page defining any of them, so the only
# way to read it was to guess at arithmetic - and the two that happen to sum on
# Log4Shell do not sum in general, while the two that differ by 44 and the one that
# is roughly double another are not the same kind of thing at all.
#
# Only what the API's own shapes support is stated here. `ArtifactLink` carries a
# provider and a pointer per row, so a row is one provider's claim about one edge
# and several rows can name the same artifact - confirmed live, where 100 returned
# link rows covered 50 distinct artifacts. The `pocs` membership rule is the union
# of the catalog kinds `search_exploits` already documents. Nothing here asserts an
# arithmetic identity *between collections*, because the contract states none: the
# `artifacts` and `artifact_links` totals are counted over different things, and no
# arithmetic relates either to `pocs`.
#
# The one identity the API does state is inside a collection rather than between two,
# and it is stated where the parts are printed rather than here - the three
# exploitation counts partition `pocs` (see :data:`EXPLOITATION_COUNT_RULE`), and
# `search_vulnerabilities` sends that same total as `poc_count`, which is why the
# `pocs` line names it.
_COUNT_MEANINGS = {
    "pocs": (
        "every PoC catalog entry linked here: catalogued exploits, curated "
        "repository PoCs and repository PoC candidates alike; this is the same "
        "number `search_vulnerabilities` reports as `poc_count`"
    ),
    "artifacts": (
        "every artifact linked here, from any source; the Nuclei templates "
        "counted separately are among them"
    ),
    "artifact_links": (
        "provider claims, not artifacts: one row per provider asserting one "
        "CVE-to-artifact edge, so rows may repeat an artifact. `get_exploit` "
        "renders them for one artifact"
    ),
}

# "not comparable" was too strong and the page contradicted it two lines later:
# `artifacts` says the Nuclei templates "are among them", which is a containment
# relation and therefore precisely a comparison. What is actually true is that the
# lines do not *sum*, and that any relation between two of them is stated rather
# than left to be inferred.
_COUNT_LEAD_IN = (
    "Each line counts a different population, so the numbers do not sum. Where one "
    "population contains another the line says so; a line with no note counts rows "
    "in its own collection only."
)

# The brief printed two of the three PoC populations and asserted, correctly for the
# API it was written against, that no arithmetic related them to `pocs`. The API then
# changed underneath that sentence.
#
# `api.sql` in eip-loader-v3 is the authority, and its `artifact_counts` CTE now emits
# four counts over one base population - every linked artifact except the
# repository-inventory rows held back by `curated_admission`, which are exactly the
# rows the artifact projection gives no `catalog_kind`:
#
#   catalogued_exploit_count       source IN ('exploitdb', 'metasploit')
#   curated_repository_poc_count   source = 'repository-inventory',
#                                    artifact_kind = 'repository_poc'
#   repository_candidate_count     source = 'repository-inventory',
#                                    artifact_kind <> 'repository_poc'
#   poc_count                      source IN (all three of the above sources)
#
# `artifact_kind` is `NOT NULL` in the source schema, so the first three are disjoint
# and their union is exactly the fourth: the three *do* partition `pocs`, and the
# population this rule used to call unnameable is now `curated_repository_poc_count`,
# which arrived with eip-server-v3 `7df0177` and eip-loader-v3 `f9e1cda`. Before that
# commit `poc_count` was catalogued exploits plus admitted units, which is what the
# word "curated" here used to mean; it is now the whole collection.
#
# So the identity this rule must never state has inverted. The old prohibition was
# "catalogued + candidates = pocs" - still false, and still not stated. What is stated
# now is the partition the API's own definitions give, over all three parts rather
# than two of them.
EXPLOITATION_COUNT_RULE = (
    "The three PoC counts are the disjoint parts of the `pocs` collection and "
    "together account for its total: a catalogued exploit is an ExploitDB or "
    "Metasploit entry, a curated repository PoC is a repository unit admitted to the "
    "PoC catalog in its own right, and a repository PoC candidate is a repository "
    "artifact linked here but not admitted. Nuclei templates are a separate "
    "population and are not inside `pocs`. `search_vulnerabilities` reports the same "
    "collection as a single number, `poc_count`, which is the `pocs` total itself "
    "rather than any part of it."
)

# The rule above is reference material: about ninety words, correct, and read once.
# Printing it under every `Counts:` line - including the many where all three counts
# are zero and there is nothing to reconcile - put it on every brief a client ever
# fetches, which is the same failure as the per-line untrusted tag it replaced.
#
# It is now stated where a reader meets it once per session: the `get_vulnerability`
# tool description and the `usage-guide` resource, both of which the model reads. What
# stays on the brief is the property a reader cannot recover from the numbers
# themselves - that these are parts of one collection rather than free-standing
# populations, so the collection total is not a fourth number to reconcile against
# them. The previous note said the opposite, because the previous API meant it.
EXPLOITATION_COUNT_NOTE = (
    "These three are the disjoint parts of `pocs` and together account for its total; "
    "Nuclei templates are counted apart from it. The `usage-guide` resource defines "
    "each."
)

_SECTION_TITLES = {
    "pocs": "Linked PoCs",
    "artifacts": "Source artifacts",
    "related_artifacts": "Related artifacts",
    "nuclei": "Nuclei templates",
    "labs": "Docker lab units",
    "references": "References",
    "writeups": "Writeups",
    "affected": "Affected products",
    "weaknesses": "Weaknesses",
    "lifecycle": "Lifecycle records",
    "research": "Research writeups",
}

_SECTION_KEYS = {
    "pocs": "pocs",
    "artifacts": "artifacts",
    "related_artifacts": "related_artifacts",
    "nuclei": "nuclei_templates",
    "labs": "docker_labs",
    "references": "references",
    "writeups": "writeups",
    "affected": "affected",
    "weaknesses": "weaknesses",
    "lifecycle": "lifecycle",
    "research": "research_resources",
    "artifact_links": "artifact_links",
}

# The tool layer's ceiling on `section_limit`, named here because the truncation
# notice below tells the reader to raise it. A hint quoting a bound the gate does
# not enforce is a hint that sends the reader into a validation error.
SECTION_LIMIT_MAX = 50

# Bounded lists on the vulnerability brief itself.
_ALIAS_LIMIT = 10
_CWE_LINE_LIMIT = 10


# The footnote the pointers are hoisted into, and the sentence that makes a hoisted
# pointer reconstructible without EIP being trusted about it: the reader is told the
# exact concatenation, so a marker plus a path is the pointer, not a summary of it.
_SOURCE_SECTION = "## Source records"
_SOURCE_TABLE_RULE = (
    "Each `[S<n>]` above stands for one source record, listed here. The pointer it "
    "replaces is that record followed directly by the path printed beside the marker, "
    "with nothing between them."
)
# A pointer is written into a line long before the page knows whether hoisting will
# pay, so it goes in as a placeholder that the finaliser swaps for one of the two
# forms. NUL delimits it because no corpus value can carry one: every corpus value
# reaches output through `sanitize`, `one_line` or `inline`, and all three drop
# control characters. So corpus text can neither forge a placeholder nor smuggle one
# into output, and a test asserts none survives into any rendered page.
_SLOT = "\x00"


class _SourceRecords:
    """Page-scoped registry that hoists repeated source-record identities.

    A pointer is ``<record>#<path>``, and the record half - scheme, source name,
    content hash, native id, about ninety characters - repeats on every claim drawn
    from the same source record. Eight pointers on a default Log4Shell brief are five
    distinct records; fifty-eight on an expanded References section are six. An audit
    measured the pointers at 26.5% of a default brief.

    Nothing is dropped and nothing is shortened. The record moves to a table at the
    foot of the page, the claim keeps a marker and its own path, and the table states
    how to put them back together, so every pointer is still reconstructible character
    for character from what is rendered.

    Two conditions gate it, and both exist because the repetition is cheaper than the
    alternative when they fail. The table has to be smaller than the repetition it
    replaces - on a thin record every pointer is distinct, so hoisting would only add
    a table - and the whole page has to fit the caller's ceiling, because the table
    sits at the end and a page cut by `cap()` would lose it and leave every marker
    above dangling. Bytes are worth saving; the audit trail is not worth trading.
    """

    def __init__(self) -> None:
        # One entry per rendered pointer: the two forms it may take.
        self._slots: list[tuple[str, str]] = []
        self._markers: dict[str, str] = {}
        self._table: list[str] = []

    def pointer(self, value: Any) -> str:
        """Render the pointer half of an attribution, or a placeholder for it."""
        span = inline(value, max_len=_POINTER_MAX)
        if not span:
            return ""
        full = f"pointer {span}"
        if was_truncated(span):
            # Split, the record and the path would each be bounded separately, so the
            # hoisted form would disclose a different amount of the same pointer than
            # the inline one. Keep the single value whose cut is already marked.
            return full
        record, separator, path = one_line(value, max_len=_POINTER_MAX).partition("#")
        record_span = inline(record, max_len=_POINTER_MAX)
        if not record_span:
            # A pointer that is nothing but a path has no record to hoist.
            return full
        marker = self._marker(record, record_span)
        path_span = inline(f"{separator}{path}", max_len=_POINTER_MAX) if separator else ""
        hoisted = f"pointer {marker} {path_span}" if path_span else f"pointer {marker}"
        self._slots.append((full, hoisted))
        return f"{_SLOT}{len(self._slots) - 1}{_SLOT}"

    def _marker(self, record: str, record_span: str) -> str:
        marker = self._markers.get(record)
        if marker is None:
            marker = f"[S{len(self._markers) + 1}]"
            self._markers[record] = marker
            self._table.append(f"- {marker} = {record_span}")
        return marker

    def finalize(self, lines: Sequence[str], *, max_chars: int | None = None) -> str:
        """Join ``lines`` into a page, hoisting the pointers only when it pays."""
        repeated = self._fill(lines, hoisted=False)
        if not self._slots:
            return repeated
        hoisted = "\n".join(
            (
                self._fill(lines, hoisted=True),
                "",
                _SOURCE_SECTION,
                _SOURCE_TABLE_RULE,
                *self._table,
            )
        )
        if len(hoisted) >= len(repeated):
            return repeated
        if max_chars is not None and len(hoisted) > max_chars:
            return repeated
        return hoisted

    def _fill(self, lines: Sequence[str], *, hoisted: bool) -> str:
        """Substitute every placeholder with one of its two forms.

        The scan is a plain split on the delimiter rather than a pattern match:
        placeholders are written in pairs by :meth:`pointer` and nothing else on the
        page can contain the delimiter, so the odd-indexed fragments are the indices
        and the even-indexed ones are the page.
        """
        parts = "\n".join(lines).split(_SLOT)
        out = [parts[0]]
        for index in range(1, len(parts), 2):
            out.append(self._slots[int(parts[index])][1 if hoisted else 0])
            out.append(parts[index + 1])
        return "".join(out)


def _attribution(item: dict[str, Any], records: _SourceRecords | None = None) -> list[str]:
    """Render source, provider and pointer, hoisting the pointer when asked to.

    Without a registry this is exactly ``_labelled(item, _PROVENANCE_FIELDS)``, which
    is what every surface outside the vulnerability brief still gets.
    """
    if records is None:
        return _labelled(item, _PROVENANCE_FIELDS)
    bits = _labelled(item, _SOURCE_FIELDS)
    if fragment := records.pointer(item.get("pointer")):
        bits.append(fragment)
    return bits


def _total(collection: dict[str, Any]) -> int | None:
    """Total for a collection, falling back to the number of items returned.

    A payload that omits ``total`` - or sends it as ``null`` - must not make the
    collection disappear from the brief; the items in hand are still a truthful
    lower bound, and both the summary and the expanded section use this one rule
    so they cannot disagree about whether a collection exists.

    ``None`` when the response supplied neither a usable ``total`` nor an
    ``items`` list, because then nothing in it supports a count at all. The
    fabricated value that used to come out here was ``0``, which is the worst
    one available: a reader takes "0 total" and "none" to mean the corpus holds
    none of these, when what actually happened is that the response did not say.
    An empty ``items`` list is a real answer and still counts as zero.
    """
    total = _count(collection.get("total"))
    if total is not None:
        return total
    items = collection.get("items")
    return len(_objects(items)) if isinstance(items, list) else None


def _catalog_line(label: str, listing: Any, records: _SourceRecords | None = None) -> str | None:
    listing = _mapping(listing)
    if not listing.get("listed"):
        return None
    added = _date(listing.get("added_at"))
    suffix = f" (added {added})" if added else ""
    return f"- {label}: listed{suffix}{format_provenance(listing.get('provenance'), records)}"


def _ssvc_line(ssvc: dict[str, Any], records: _SourceRecords | None = None) -> str | None:
    """One SSVC decision, carrying the provenance its neighbours all carry.

    This was the only line under `## Exploitation context` rendered without a
    source record, under a hardcoded "CISA" that nothing on the page substantiated
    - while the usage guide promises every displayed value keeps its provider,
    source record and exact source pointer. The label is EIP asserting who decided
    this; the provenance is what makes that checkable.

    The decision-point version rides along for the same reason a CVSS version
    does: SSVC decision points are version-scoped, so `exploitation=active` under
    two versions is not necessarily the same statement.
    """
    bits = [
        f"{key}={value}"
        for key in ("exploitation", "automatable", "technical_impact")
        if (value := inline(ssvc.get(key), max_len=40))
    ]
    if not bits:
        return None
    role = inline(ssvc.get("role"), max_len=60)
    evaluated = _date(ssvc.get("evaluated_at"))
    version = inline(ssvc.get("version"), max_len=16)
    label = f"SSVC {version}" if version else "SSVC"
    detail = f" by {role}" if role else ""
    when = f" on {evaluated}" if evaluated else ""
    provenance = format_provenance(ssvc.get("provenance"), records)
    return f"- {label}: {', '.join(bits)}{detail}{when}{provenance}"


_POC_POPULATION_KEYS = (
    "catalogued_exploit_count",
    "curated_repository_poc_count",
    "repository_candidate_count",
)


def _count_lines(ctx: dict[str, Any]) -> list[str]:
    """The exploitation counts, and the one thing about them a reader cannot infer.

    All three PoC populations are printed, in the order
    :data:`POC_GROUP_TITLES` sorts the collection itself, so the brief's `Counts:`
    line and its `Linked PoCs` section name the same things in the same sequence.
    Printing two of the three is what made "0 catalogued exploits, 0 repository
    candidates" sit above "`pocs`: 1" with the 1 accounted for nowhere; the API now
    supplies the population that held it.

    What travels with the counts is the shape of the relationship between them -
    disjoint parts of one collection - because that is the thing a reader cannot
    recover from the numbers. The definitions behind the nouns are read once,
    elsewhere; see :data:`EXPLOITATION_COUNT_NOTE`.
    """
    bits = [
        _quantity(count, label)
        for label, key in (
            (CATALOGUED_COUNT_LABEL, "catalogued_exploit_count"),
            (CURATED_COUNT_LABEL, "curated_repository_poc_count"),
            (CANDIDATE_COUNT_LABEL, "repository_candidate_count"),
            ("Nuclei templates", "nuclei_template_count"),
        )
        if (count := _count(ctx.get(key))) is not None
    ]
    if not bits:
        return []
    lines = [f"- Counts: {', '.join(bits)}"]
    # The note is about the two PoC populations, so it goes only where they are
    # printed. A brief carrying nothing but a Nuclei count has nothing to reconcile.
    if any(_count(ctx.get(key)) is not None for key in _POC_POPULATION_KEYS):
        lines.append(EXPLOITATION_COUNT_NOTE)
    return lines


def _exploitation_lines(data: dict[str, Any], records: _SourceRecords | None = None) -> list[str]:
    ctx = _mapping(data.get("exploitation"))
    body: list[str] = []
    for label, key in (("CISA KEV", "cisa_kev"), ("VulnCheck KEV", "vulncheck_kev")):
        line = _catalog_line(label, ctx.get(key), records)
        if line:
            body.append(line)
    for label, key in (
        ("Reported exploitation", "reported_exploitation"),
        ("Known ransomware use", "known_ransomware"),
    ):
        signal = _mapping(ctx.get(key))
        if signal.get("observed"):
            body.append(
                f"- {label}: observed{format_provenance(signal.get('provenance'), records)}"
            )
    ssvc_line = _ssvc_line(_mapping(ctx.get("ssvc")), records)
    if ssvc_line:
        body.append(ssvc_line)
    body.extend(_count_lines(ctx))
    return ["", "## Exploitation context", *body] if body else []


def _summary_line(name: str, total: int) -> str:
    """One count, and what it counts when the bare number would invite a wrong sum.

    A summary-only row says so. The heading above this list tells the reader to
    expand what it names, and `sections` refuses the one name that is not
    expandable - so without this the page instructs a call that raises, and the
    reader has no way to know which row is the exception.
    """
    meaning = _COUNT_MEANINGS.get(name)
    line = f"- `{name}`: {_number(total)}" + (f" - {meaning}." if meaning else "")
    if name in _SUMMARY_ONLY:
        line += f" {_SUMMARY_ONLY_NOTE}"
    return line


def _collection_summary(data: dict[str, Any], exclude: Sequence[str] = ()) -> list[str]:
    """Count every collection the response carried, minus any already rendered.

    `exclude` is what the page expanded above, so the inventory says what is
    *left* rather than repeating a section the reader can already see.
    """
    skip = set(exclude)
    body = [
        _summary_line(name, total)
        for name in (*VULN_SECTIONS, *_SUMMARY_ONLY)
        if name not in skip and (total := _total(_mapping(data.get(_SECTION_KEYS[name]))))
    ]
    if not body:
        return []
    # Two headings, because the same list means two different things. On a page
    # that expanded nothing it is the index of everything available; on a page that
    # expanded eight sections it is the remainder - and calling that "Available
    # detail" would read as though the sections above were not.
    heading = (
        "## Also available (not expanded here; name it in `sections`)"
        if skip
        else "## Available detail (use `sections` to expand)"
    )
    return ["", heading, _COUNT_LEAD_IN, *body]


# A public identifier exists to be copied into the next query, so a truncated one is
# a corrupted one. A code span costs four characters beyond its body - two delimiters
# and the two padding spaces CommonMark strips again - and the "#" prefix costs one
# more, so the span budget is the identifier's own ceiling plus that overhead.
_PUBLIC_ID_MAX = 32
_PUBLIC_ID_SPAN = _PUBLIC_ID_MAX + len("#") + 4

# The API documents four verdicts: no_backdoor_observed, suspicious, trojan,
# undetermined. Listing the alarming ones and flagging only those fails open - a new
# verdict, a misspelled one, or a case variant renders exactly like a benign artifact,
# which is the one outcome this page must never produce. Only the single explicitly
# benign value is unflagged; everything else is surfaced verbatim.
BENIGN_VERDICT = "no_backdoor_observed"
DOCUMENTED_VERDICTS = ("no_backdoor_observed", "suspicious", "trojan", "undetermined")

# Loud markers. `UNRECOGNISED_VERDICT` is not decoration: a value outside the
# documented set is a value this renderer cannot reason about, and saying so is the
# only honest thing to print next to it.
UNRECOGNISED_VERDICT = "UNRECOGNISED VERDICT"
OVER_LENGTH_CLASSIFICATION = "OVER-LENGTH CLASSIFICATION"

# Every documented verdict is at most 20 characters and every observed
# classification well under 32, so these ceilings render the whole documented
# vocabulary and then some. The width is the point. Under the old 32- and
# 24-character span budgets a truncation marker cost 13 of them, so the
# API-plausible verdict `no_backdoor_observed_but_trojan_found` rendered as
# `no_backdoor_obs …[truncated]` and `benign_wrapper_around_trojan` as `benign_
# …[truncated]` - a malicious value inverted into a clean-reading one by the
# renderer's own bounding. A value still too long for these ceilings cannot be a
# documented one, so it is flagged rather than quietly shortened.
_VERDICT_MAX = 64
_CLASSIFICATION_MAX = 64
# A code span costs four characters beyond its body: two delimiters and the two
# padding spaces CommonMark strips again.
_SPAN_OVERHEAD = 4
_VERDICT_SPAN = _VERDICT_MAX + _SPAN_OVERHEAD
_CLASSIFICATION_SPAN = _CLASSIFICATION_MAX + _SPAN_OVERHEAD


def _is_benign_verdict(value: Any) -> bool:
    """True only for the API's one documented all-clear verdict, byte for byte.

    Exact equality, deliberately: a prefix, a suffix, a case variant, surrounding
    whitespace, or an invisible character that sanitation would strip are each a
    value the API did not document, and every one of them is a way to spell
    something that is not an all-clear so that it reads as one. Matching loosely
    here - ``startswith``, ``.lower()``, ``.strip()`` - hands an attacker whichever
    spelling the loosening admits.
    """
    return value == BENIGN_VERDICT


def _verdict_flag(value: Any, *, quiet: str, loud: str) -> str:
    """Render a backdoor-review verdict under a label that matches what it says.

    The verdict is rendered verbatim in every branch. What changes is the label:
    the one documented all-clear gets ``quiet`` so that "reviewed and benign" stays
    distinguishable from "never reviewed", a documented alarming verdict gets
    ``loud``, and anything else gets ``loud`` plus an explicit statement that this
    renderer does not recognise the value. EIP adds no adjective of its own in any
    branch - a clearance is the model's claim to make, never EIP's.
    """
    span = inline(value, max_len=_VERDICT_SPAN)
    if not span:
        return ""
    if _is_benign_verdict(value):
        return f"{quiet}: {span}"
    if value in DOCUMENTED_VERDICTS:
        return f"{loud}: {span}"
    return f"{loud} - {UNRECOGNISED_VERDICT}: {span}"


def _classification_span(value: Any) -> str:
    """Render a technical classification, and never as a silent prefix.

    A classification that does not fit is flagged rather than shortened in silence:
    ``benign_wrapper_around_trojan`` cut to ``benign_`` is not a shorter truth, it
    is a different and friendlier claim than the model made.
    """
    span = inline(value, max_len=_CLASSIFICATION_SPAN)
    if not span:
        return ""
    return f"{OVER_LENGTH_CLASSIFICATION} {span}" if was_truncated(span) else span


def _public_id_span(item: dict[str, Any]) -> str:
    """Render ``#<public_id>`` as an inert span wide enough to hold it whole."""
    public_id = one_line(item.get("public_id"), max_len=_PUBLIC_ID_MAX)
    return inline(f"#{public_id}", max_len=_PUBLIC_ID_SPAN) if public_id else ""


# Short, because it repeats on every unanalysed row: Log4Shell's PoC list carried
# the long form ten times over. The row still declares its own state - a group-level
# count would leave a reader unable to tell WHICH rows it covered - but the sentence
# that explains the state is stated once per section, in `ANALYSIS_LEGEND` below.
NO_ANALYSIS_FLAG = "no stored analysis"

ANALYSIS_LEGEND = (
    "`no stored analysis` on a row means the artifact has not been examined and is "
    "not cleared - the absence of a finding, not a finding of absence. Where a row "
    "does carry a model classification or backdoor verdict, `get_exploit` renders "
    "the full stored analysis behind it: what the model says the code does, its "
    "prerequisites and observed behaviours, the independent backdoor review, the "
    "limits each pass put on its own reading, and file-and-line citations for every "
    "claim."
)


def _analysis_flags(analysis: Any) -> str:
    """Render the flag suffix a catalog line carries for the stored passes.

    Every catalog renderer shares this, so the fail-closed rule cannot drift out of
    one of them. The verdict is rendered verbatim either way: a benign one in the
    quiet form, so that "reviewed and benign" stays distinguishable from "never
    reviewed", and anything else in the loud one, so an unrecognised value is
    visible rather than swallowed.
    """
    analysis = _mapping(analysis)
    technical = _mapping(analysis.get("technical"))
    review = _mapping(analysis.get("backdoor_review"))
    flags = []
    classification = _classification_span(technical.get("classification"))
    if classification:
        flags.append(f"model-classified: {classification}")
    verdict = _verdict_flag(
        # "model", not a bare "backdoor review": the classification sitting beside
        # this on the same line already says `model-classified`, and this is the
        # more consequential of the two. Unattributed, a stored verdict reads as
        # EIP's finding - the one claim SERVER_INSTRUCTIONS says EIP never makes.
        review.get("verdict"),
        quiet="model backdoor review",
        loud="MODEL BACKDOOR REVIEW",
    )
    # A row with no stored analysis carried no flag at all, so on a 100-row catalog
    # page an unanalysed artifact and a reviewed-and-benign one looked the same, and
    # blank read as "not flagged". The detail page has said this properly all along
    # ("the absence of a finding, not a finding of absence"); the list pages let
    # silence do the asserting. Short, because it repeats on every unanalysed row.
    #
    # Gated on the RENDERED values, not on raw truthiness. A verdict of "   " or a
    # zero-width space is truthy, so a `.get("verdict")` gate let it through and it
    # then rendered nothing - reinstating the very blank row this flag exists to
    # prevent. `_analysis_lines` gates the detail page on rendered values too;
    # testing a different predicate than the renderer is the bug `_cited_claims`
    # had, one function over.
    if not classification and not verdict:
        return f" [{NO_ANALYSIS_FLAG}]"
    if verdict:
        flags.append(verdict)
    return f" [{'; '.join(flags)}]" if flags else ""


# --------------------------------------------------------------------------
# Source dates, and what each source means by one.
#
# `published_at` is not one thing across the catalog, and the difference is the
# kind a reader acts on: a Metasploit module's source date is when the module
# reached the framework, which can be years after the vulnerability was
# disclosed. Rendering the bare date invites it to be read as a disclosure date.
# The meaning is looked up from the source the API itself reported, so this
# states upstream's documented rule rather than inferring anything.
# --------------------------------------------------------------------------

SOURCE_DATE_RULE = (
    "Source date is the provider's repository-creation time for repositories; for "
    "Metasploit it is the first Git commit that added the current module path, never "
    "the disclosure date; for every other source it is the source-supplied "
    "publication time."
)

# One label, used wherever a source date is rendered, so the inline form and the
# detail page cannot drift into "source date" and "Source date:".
_SOURCE_DATE_LABEL = "source date"


def _source_date(item: dict[str, Any]) -> str:
    """Render ``published_at`` under the one label this module uses for it.

    The meaning used to be restated in parentheses on every line, which cost 18
    parentheticals in one default-depth brief - ten of them the same 62-character
    Metasploit sentence. The rule is the same for every line on the page, so
    :data:`SOURCE_DATE_RULE` states it once per page instead; see
    :func:`_source_date_rule_lines`.
    """
    rendered = _date(item.get("published_at"))
    return f"{_SOURCE_DATE_LABEL} {rendered}" if rendered else ""


def _source_date_rule_lines(body: Sequence[str]) -> list[str]:
    """State what a source date means, once, and only if the page rendered one.

    The check is on the rendered lines because the sections that carry a date are
    heterogeneous and the rule has to cover all of them at once. A corpus value
    containing this label could therefore put the rule on a page with no date on
    it, which costs one sentence of EIP's own true prose and nothing else - a
    corpus value cannot suppress the rule, which is the direction that would matter.
    """
    marker = f"{_SOURCE_DATE_LABEL} "
    return ["", SOURCE_DATE_RULE] if any(marker in line for line in body) else []


def _provider_identity(item: dict[str, Any]) -> str:
    """Name a non-GitHub public Git source without inferring it from a URL.

    The API carries provider type and host precisely so a client need not read
    identity out of a URL string; dropping them put the reader back to guessing.
    """
    return ", ".join(
        _labelled(
            item,
            (("provider type", "provider_type", 40), ("provider host", "provider_host", 100)),
        )
    )


def _poc_item(item: dict[str, Any], records: _SourceRecords | None = None) -> list[str]:
    bits = [
        _public_id_span(item),
        inline(item.get("source"), max_len=40),
        inline(item.get("catalog_kind"), max_len=40),
        _provider_identity(item),
        _source_date(item),
    ]
    title = inline(item.get("title"), max_len=120) if item.get("title") else ""
    suffix = _analysis_flags(item.get("analysis"))
    return [f"- {' · '.join(b for b in bits if b)} {title}{suffix}".rstrip()]


# --------------------------------------------------------------------------
# The `pocs` collection is not one population, and saying so is not a judgment.
#
# `## Linked PoCs - 417 total` put eight ExploitDB and Metasploit entries under
# the same noun as 409 repository candidates, while `search_vulnerabilities`
# reported the same CVE as "8 curated PoCs, 409 repository candidates". One word,
# two quantities fifty apart, and a reader routinely holds both pages.
#
# The vocabulary below is not invented here. The EIP web interface reads this same
# API, is bound by the same no-judgment rules, and has grouped this collection
# under these five nouns since before this server existed - `POC_PRESENTATION` and
# `PocPanel` in its vulnerability page, and the same per-kind labels on its catalog
# page. A third vocabulary for the same field would be the defect, not the fix.
#
# What is asserted by grouping is exactly what `catalog_kind` already says, and
# every row still prints its own `catalog_kind` beside the heading that sorted it.
# The map is total: an unrecognised kind, and a row the API sent no kind for, land
# in a named group rather than vanishing or being guessed at.
POC_GROUP_TITLES: tuple[str, ...] = (
    "Catalogued exploits",
    "Curated repository PoCs",
    "Repository PoC candidates",
    "Other PoC artifacts",
)

_POC_GROUP_OF_KIND = {
    "exploitdb-exploit": 0,
    "metasploit-exploit": 0,
    "metasploit-auxiliary": 0,
    "repository-poc": 1,
    "repository-candidate": 2,
}
_POC_OTHER_GROUP = len(POC_GROUP_TITLES) - 1

# Stated on the section, because a heading a reader did not ask for needs to say
# where it came from, and because the one thing a fixed sequence can be misread as
# is a league table. Both halves of the disclosure matter: the partition is the
# API's own field, and the sequence is EIP's, constant, and carries no claim.
#
# This is the same treatment `CODE_SEARCH_NOTE` gives an ordering with far more
# ranking flavour than a categorical partition: name what the order is, and say
# what it is not.
# Kept on the page rather than moved to `usage-guide`: it disclaims a ranking a
# reader could otherwise infer from the order in front of them, and a disclaimer
# is only useful beside the thing it disclaims. Cut to the claim itself.
# The three shapes `_analysis_flags` can emit. Matched against rendered rows so the
# legend follows the flags rather than a hard-coded list of section names.
_ANALYSIS_FLAG_MARKERS = (
    f"[{NO_ANALYSIS_FLAG}]",
    "[model-classified:",
    "model backdoor review:",
    "MODEL BACKDOOR REVIEW",
)


def _analysis_legend_lines(rows: Sequence[str]) -> list[str]:
    """`ANALYSIS_LEGEND` if any rendered row carries an analysis flag, else nothing.

    Shared by every surface that can emit one. `_analysis_flags` has two callers -
    `_poc_item`, behind `get_vulnerability`'s sections, and `format_poc_page`,
    behind `search_exploits` - and wiring only the first left the catalog page
    showing the shortened marker with nothing to explain it: strictly less than it
    said before the marker was shortened. Deriving from the rendered rows means a
    third caller cannot appear without the legend following it.
    """
    if any(marker in row for row in rows for marker in _ANALYSIS_FLAG_MARKERS):
        return [ANALYSIS_LEGEND]
    return []


POC_GROUP_RULE = (
    "Grouped by each artifact's own `catalog_kind`. Group order is presentation: it "
    "is not a ranking, and expresses no quality, preference, or likelihood that "
    "anything here works. Within a group the API's order is unchanged."
)

# A truncated section shows a prefix of what the API returned, and the API returns
# this collection already partitioned by `catalog_kind` - so a cut falls on whole
# groups, not evenly across them. Without this, a heading that is simply past the
# cut reads as a group the CVE has no members in.
POC_GROUP_OMISSION_NOTE = "A group with no row above may still have members among the omitted."


def _poc_groups(items: Sequence[dict[str, Any]]) -> list[tuple[str, list[dict[str, Any]]]]:
    """Partition ``items`` by the API's ``catalog_kind``, in payload order.

    Two properties, both of them testable and neither of them a judgment:

      * within a group, items appear in the order the API returned them - this is a
        stable partition, so no item ever moves relative to another in its group;
      * between groups, the order is :data:`POC_GROUP_TITLES`, a constant of this
        module that no payload value can influence.

    So a row's position is a function of two API-supplied quantities - its
    ``catalog_kind`` and its index - composed with one fixed permutation of four
    names. Nothing this module computed from the data enters it, which is the
    property that separates this from the score EIPv2 synthesized.

    Empty groups are dropped rather than rendered as an empty heading: absence of a
    heading here is absence of a row, never a claim that the CVE has none of that
    kind (see :data:`POC_GROUP_OMISSION_NOTE` for the truncated case).
    """
    buckets: list[list[dict[str, Any]]] = [[] for _ in POC_GROUP_TITLES]
    for item in items:
        kind = item.get("catalog_kind")
        index = _POC_GROUP_OF_KIND.get(kind, _POC_OTHER_GROUP) if isinstance(kind, str) else None
        buckets[_POC_OTHER_GROUP if index is None else index].append(item)
    return [
        (title, bucket) for title, bucket in zip(POC_GROUP_TITLES, buckets, strict=True) if bucket
    ]


def _artifact_item(item: dict[str, Any], records: _SourceRecords | None = None) -> list[str]:
    """Render one acquired artifact: its identity, its provider, and its source date."""
    bits = [
        inline(item.get("artifact_id"), max_len=128),
        inline(item.get("source"), max_len=40),
        inline(item.get("kind"), max_len=40),
        inline(item.get("native_id"), max_len=80),
        _provider_identity(item),
        _source_date(item),
    ]
    head = " · ".join(bit for bit in bits if bit) or "(unidentified artifact)"
    title = f" {inline(item['title'], max_len=120)}" if item.get("title") else ""
    url = f" {inline(item['url'], max_len=200)}" if item.get("url") else ""
    return [f"- {head}{title}{url}"]


# --------------------------------------------------------------------------
# Claim collections: references, writeups, affected products, weaknesses,
# lifecycle.
#
# A Claim is provenance plus a free-form `data` dict whose keys differ by source.
# Rendering only the provenance - which is what the fall-through to `pointer` did
# - produced 79 near-identical internal record pointers under a heading that
# promised references, and an "Affected products" section that named no product.
# The payload always held the answer: `{"url": …}` for a reference, `{"vendor":
# …, "product": …}` for an affected entry, `{"cwe_id": …}` for a weakness.
#
# `data` is corpus-derived and its shape is not fixed, so it is rendered
# generically and defensively: keys and scalars both go through `inline`, nested
# containers are serialised compactly and then wrapped like any other corpus
# value, and the whole thing is bounded per field, per list and per claim.
# --------------------------------------------------------------------------

_CLAIM_FIELD_LIMIT = 8
_CLAIM_LIST_LIMIT = 6
_CLAIM_KEY_MAX = 48
_CLAIM_VALUE_MAX = 200
_CLAIM_NESTED_MAX = 300
# Below this the structure is flattened into readable text; at it, the raw JSON is
# the honest rendering, because a reader cannot reconstruct depth from `a=b=c=d`.
# Six covers every shape the corpus sends today - the deepest is a CVE record's
# `affected[].versions[].changes[]`, at five - with one level in hand.
_CLAIM_NESTED_DEPTH = 6


def _compact_json(value: Any) -> str:
    """Serialise a nested claim value without reordering or interpreting it.

    Keys are emitted in the order the API sent them: ``sort_keys`` here would be
    this module rearranging corpus data, which is the same class of act as
    re-sorting a result list.
    """
    try:
        # `sort_keys` is deliberately absent and must stay absent: emitting keys in
        # any order but the API's is this module rearranging corpus data, the same
        # class of act as re-sorting a result list. Asserted behaviourally in
        # tests/test_no_derived_judgments.py, because a guard that only scans the
        # source text for a re-ordering call cannot see this keyword argument.
        return json.dumps(value, separators=(",", ":"), default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def _flatten(value: Any, depth: int = 0) -> str:
    """Render a nested claim value as readable text rather than as raw JSON.

    The worst-reading line in the whole brief was an affected-products entry that
    dumped ``{"versions":[{"status":"affected","changes":[{"at":"2.3.1",…`` and was
    cut mid-object by the value ceiling. Every character of it was quoting,
    bracketing and key punctuation the reader had to parse around, and the fields
    they wanted - the version, what it was affected from, what fixed it - were past
    the cut. Flattening the same object to ``versions=(status=affected, …)`` says
    the same thing in two-thirds of the characters, which is the difference between
    fitting inside the ceiling and being truncated.

    Nothing is reordered, renamed, summarised or dropped: keys stay in the order the
    API sent them, and every leaf is rendered verbatim. Bounding stays where it was,
    on the :func:`inline` call that wraps the result, so an over-long value is still
    cut and marked outside its span rather than silently shortened here.
    """
    if value is None or value == "" or value == [] or value == {}:
        return ""
    if isinstance(value, bool):
        # The wire said `false`; `str(False)` is an artifact of the JSON parser this
        # process happens to use, and a reader comparing the brief against the source
        # record should see the token the record holds.
        return "true" if value else "false"
    if depth >= _CLAIM_NESTED_DEPTH:
        return _compact_json(value)
    if isinstance(value, dict):
        body = ", ".join(
            f"{key}={rendered}"
            for key, entry in value.items()
            if (rendered := _flatten(entry, depth + 1))
        )
        # Parenthesised only when nested, so the boundaries of an object inside a
        # list stay visible without bracketing the whole value for nothing.
        return f"({body})" if depth and body else body
    if isinstance(value, (list, tuple)):
        body = "; ".join(rendered for entry in value if (rendered := _flatten(entry, depth + 1)))
        # Bracketed when nested, for the reason an object is parenthesised: without
        # a closing delimiter the list simply stopped, and the parent's next key
        # followed it with ", " - the very separator used *inside* each element. On
        # a real CVE record that produced
        #   changes=(at=2.3.1, status=unaffected); (at=2.15.0, …), versionType=custom
        # where `versionType` is a sibling of `changes` and reads as a member of the
        # last change. Nothing is reordered or dropped; the boundary is made visible.
        return f"[{body}]" if depth and body else body
    return str(value)


def _claim_value(value: Any) -> str:
    """Render one free-form claim value inertly, or "" when it carries nothing."""
    if value is None or value == "" or value == [] or value == {}:
        return ""
    if isinstance(value, (list, tuple)) and not any(
        isinstance(entry, (list, dict)) for entry in value
    ):
        # A flat list is the one shape with a disclosed per-entry ceiling, because
        # its entries are independent values rather than one structure.
        shown, dropped = _values(value, limit=_CLAIM_LIST_LIMIT, max_len=_CLAIM_VALUE_MAX)
        return f"{shown}{_more(dropped, 'value(s)')}" if shown else ""
    if isinstance(value, (list, dict)):
        return inline(_flatten(value), max_len=_CLAIM_NESTED_MAX)
    return inline(_flatten(value), max_len=_CLAIM_VALUE_MAX)


# --------------------------------------------------------------------------
# Affected products: version data rendered as versions, not as structure.
#
# The generic flattener is the right default for a `data` payload whose shape is not
# fixed, and the wrong renderer for the one key a reader of this section came for.
# It produced, on a real record:
#
#   ` versions `: ` versions=(status=affected, version=7.0.0); (status=affected,
#   version=7.0.0.1); (status=affected, version=7.0.1); … ` …truncated
#
# - sixty-eight repetitions of the word `status=affected` under a heading that already
# says "Affected products", cut mid-token at the value ceiling, with the researcher's
# actual question (which versions?) answered for the first eight and then abandoned.
#
# The shapes below are read off the live corpus: the CVE 5.0 `versions[]` list of
# `{status, version, lessThan|lessThanOrEqual, versionType, changes}` records, and the
# OSV/GHSA `ranges[]` list of `{type, events[]}`. Both are handled by name and
# everything else falls back to the flattener, because the payload is corpus-derived
# and its shape is not promised: an entry that is a bare string, a `versions` value
# that is a list rather than an object, a key nobody has seen yet - each renders as it
# did before rather than raising or vanishing. Nothing is dropped: keys this renderer
# does not lay out by hand are still flattened onto the end of the entry they belong
# to, in the order the API sent them.
# --------------------------------------------------------------------------

_VERSION_LIMIT = 8
# One entry gets the ceiling the whole block used to get, so a record with a single
# long `versions[]` entry - the CVE 5.0 shape that carries a `changes` list - is never
# rendered shorter than it was before this renderer existed. The list then gets a
# budget of its own, because eight entries at the per-entry ceiling would otherwise be
# five times what the generic path could ever emit for this field.
_VERSION_MAX = _CLAIM_NESTED_MAX
_VERSION_LIST_MAX = 600
_AFFECTED_STATUS = "affected"
# Laid out by hand into a range, so not repeated by the leftover pass.
_VERSION_RANGE_KEYS = frozenset({"version", "lessThan", "lessThanOrEqual", "status"})
_RANGE_KEYS = frozenset({"type", "events"})


def _leftover(entry: dict[str, Any], handled: frozenset[str]) -> str:
    """Flatten the keys of ``entry`` this renderer did not lay out itself."""
    return _flatten({key: value for key, value in entry.items() if key not in handled})


def _version_entry(entry: Any) -> str:
    """One `versions[]` record as a readable range, keeping every field it carried.

    Composed unbounded and bounded once by the caller's :func:`inline`, which is the
    same division of labour :func:`_claim_value` uses and for the same reason: a cut
    made here would be marked *inside* the span the text ends up in, where EIP's
    marker and a corpus value imitating one are the same characters in the same place.
    """
    if not isinstance(entry, dict):
        return _flatten(entry)
    lower = _flatten(entry.get("version"))
    below = _flatten(entry.get("lessThan"))
    upto = _flatten(entry.get("lessThanOrEqual"))
    bound = f"<{below}" if below else (f"<={upto}" if upto else "")
    head = f"{lower} to {bound}" if lower and bound else (lower or bound)
    bits = [head] if head else []
    status = _flatten(entry.get("status"))
    # Exact equality, and the loose direction is the safe one here: the heading
    # already says these are affected, so `affected` is the word the page has
    # printed. Every other spelling - `unaffected`, a case variant, a status this
    # renderer has never seen - is surfaced rather than assumed away, and an entry
    # with no version at all keeps its status rather than rendering as nothing.
    if status and (status != _AFFECTED_STATUS or not head):
        bits.append(f"[{status}]")
    if rest := _leftover(entry, _VERSION_RANGE_KEYS):
        bits.append(rest)
    return " ".join(bits)


def _range_entry(entry: Any) -> str:
    """One OSV-style range as its ecosystem and the events that bound it."""
    if not isinstance(entry, dict):
        return _flatten(entry)
    events = ", ".join(
        rendered for event in _sequence(entry.get("events")) if (rendered := _flatten(event))
    )
    kind = _flatten(entry.get("type"))
    head = f"{kind}: {events}" if kind and events else (events or kind)
    rest = _leftover(entry, _RANGE_KEYS)
    return " ".join(bit for bit in (head, rest) if bit)


# The two list shapes, with the noun each discloses its own truncation in.
_VERSION_LISTS = {
    "versions": (_version_entry, "version(s)"),
    "ranges": (_range_entry, "range(s)"),
}


def _version_list(entries: Sequence[Any], render: Any, noun: str) -> str:
    """Render a bounded list of version records, each its own inert span.

    One span per entry rather than one span for the list, so the marker disclosing
    what the bound cut lands outside every span - where corpus text cannot reach it,
    and so cannot write a marker of its own that reads as EIP's.

    Two bounds apply: a count, and a total width. The width bound is what keeps eight
    entries at the per-entry ceiling from being five times what this field could emit
    before. Whichever bites, the remainder is counted from the entries actually
    consumed, so the disclosure is a fact about this list rather than about the limit.
    """
    shown: list[str] = []
    used = 0
    consumed = 0
    for entry in entries[:_VERSION_LIMIT]:
        span = inline(render(entry), max_len=_VERSION_MAX)
        if span:
            if shown and used + len(span) + 2 > _VERSION_LIST_MAX:
                break
            shown.append(span)
            used += len(span) + 2
        consumed += 1
    if not shown:
        return ""
    return f"{', '.join(shown)}{_more(len(entries) - consumed, noun)}"


def _versions_value(value: Any) -> str:
    """Render an `affected` claim's version block, or fall back to the flattener."""
    if not isinstance(value, dict):
        return _claim_value(value)
    parts: list[str] = []
    recognised = False
    for key, entry in value.items():
        handler = _VERSION_LISTS.get(key)
        if handler is not None and isinstance(entry, list):
            render, noun = handler
            rendered = _version_list(entry, render, noun)
            recognised = recognised or bool(rendered)
        else:
            rendered = inline(_flatten({key: entry}), max_len=_CLAIM_VALUE_MAX)
        if rendered:
            parts.append(rendered)
    # Nothing this renderer knows how to lay out. The generic path already handles
    # an empty object, an unfamiliar one, and a scalar where an object was expected.
    return "; ".join(parts) if recognised else _claim_value(value)


_AFFECTED_RENDERERS: dict[str, Any] = {"versions": _versions_value}


def _claim_data(item: dict[str, Any], renderers: dict[str, Any] | None = None) -> tuple[str, int]:
    """Render the content half of a claim, and count the keys that carried nothing.

    ``renderers`` overrides how one named key is rendered; everything else keeps the
    generic treatment. Only `affected` uses it, for `versions`.

    The empty count is taken from ``data`` itself rather than from the rendered
    list. Filtering first and counting afterwards is how a claim of
    ``{"onlynull": None}`` came to print "carried no data fields", which is a
    statement about the record and is not true of it: the record has a field, and
    the field is empty. That distinction is the difference between "the source said
    nothing here" and "the source did not have this field at all".
    """
    data = _mapping(item.get("data"))
    chosen = renderers or {}
    fields = [
        f"{key_span}: {rendered}"
        for key, value in data.items()
        if (rendered := chosen.get(key, _claim_value)(value))
        and (key_span := inline(key, max_len=_CLAIM_KEY_MAX))
    ]
    shown = fields[:_CLAIM_FIELD_LIMIT]
    empty = len(data) - len(fields)
    if not shown:
        return "", empty
    body = f"{', '.join(shown)}{_more(len(fields) - len(shown), 'field(s)')}"
    return body, empty


def _claim_provenance(item: dict[str, Any], records: _SourceRecords | None = None) -> str:
    """Render the attribution half of a claim, so the content stays followable."""
    bits = _attribution(item, records)
    return f" - {', '.join(bits)}" if bits else ""


def _claim_item(
    item: dict[str, Any],
    records: _SourceRecords | None = None,
    renderers: dict[str, Any] | None = None,
) -> list[str]:
    """Render one claim: what it says, then who said it.

    A claim whose data rendered is *not* annotated with how many of its keys were
    empty. The count was on nearly every bullet of every claim section, no legend for
    it existed in the output or the README, and there is nothing a reader can do with
    it: an omitted empty field discloses nothing, because there is nothing in it to
    disclose. That is the opposite of the `…N more omitted` markers, which stand for
    content the reader is not being shown and therefore have to stay.

    The all-empty case below is different and stays. There the count is not an
    annotation on rendered content, it *is* the content: "the record has three fields
    and all of them are blank" and "the record has no such fields" are different
    statements about the source, and only one of them can be true.
    """
    body, empty = _claim_data(item, renderers)
    provenance = _claim_provenance(item, records)
    if body:
        return [f"- {body}{provenance}"]
    if empty:
        return [f"- (claim carried {_quantity(empty, 'data fields')}, all empty){provenance}"]
    if provenance:
        return [f"- (claim carried no data fields){provenance}"]
    return ["- (item with no renderable identifier)"]


def _lab_item(item: dict[str, Any], records: _SourceRecords | None = None) -> list[str]:
    """Render one Docker lab unit: what it was built from, and what it is for.

    The section used to render 79 bare ``labunit-<sha256>`` identifiers and nothing
    else - 76 characters of hash per line, none of which a reader can act on - while
    every item carried the shape of the lab, the repository it was built from, and
    the CVEs it reproduces.
    """
    bits = [
        inline(item.get("lab_unit_id"), max_len=160),
        inline(item.get("shape"), max_len=60),
        _quantity(item.get("service_count"), "services"),
        _quantity(item.get("dockerfile_count"), "Dockerfiles"),
        *_labelled(_mapping(item.get("owner")), (("built from", "title", 120),)),
    ]
    head = " · ".join(bit for bit in bits if bit) or "(unidentified lab unit)"
    shown, dropped = _values(item.get("cve_ids"), limit=_CVE_LIMIT, max_len=32)
    cves = f" - CVEs: {shown}{_more(dropped, 'listed')}" if shown else ""
    return [f"- {head}{cves}"]


def _generic_item(item: dict[str, Any], records: _SourceRecords | None = None) -> list[str]:
    for key in ("template_id", "lab_unit_id", "artifact_id"):
        if item.get(key):
            label = inline(item[key], max_len=160)
            extra = ""
            if item.get("name"):
                extra = f" {inline(item['name'], max_len=100)}"
            elif item.get("provider"):
                extra = f" - {inline(item['provider'], max_len=60)}"
            return [f"- {label}{extra}"]
    return ["- (item with no renderable identifier)"]


# --------------------------------------------------------------------------
# Nuclei templates.
#
# The API returns twelve fields per template and this section rendered two of them:
# the identifier and the name. Everything a researcher would act on - what the
# template detects, how severe its author called it, its CVSS vector and CWEs, the
# impact and remediation text, the Shodan/FOFA/Google queries that find exposed
# instances, and the references - arrived in the payload and was dropped on the
# floor, under a heading and a count that promised it.
#
# All of it is corpus text from a public template repository, so all of it goes
# through the same primitives as everything else. `reconnaissance` queries and
# `references` URLs get the same treatment as the rest and for a sharper reason:
# they are the two fields an attacker would most want live on a page an analyst is
# reading - a URL that becomes an <a href>, or a "search query" that is really a
# payload. Inside a code span neither can be anything but text.
#
# The per-template shape stays one bullet plus indented sub-bullets, so a section at
# `section_limit=50` is still a bounded list rather than fifty prose blocks: every
# list has a ceiling and discloses what it dropped, and every free-text field is a
# single bounded span rather than a fenced block.
# --------------------------------------------------------------------------

_NUCLEI_AUTHOR_LIMIT = 6
_NUCLEI_TAG_LIMIT = 10
_NUCLEI_REFERENCE_LIMIT = 5
_NUCLEI_RECON_LIMIT = 5
_NUCLEI_CWE_LIMIT = 6
# A template description is one paragraph of vendor-advisory prose; impact and
# remediation are a sentence or two. These ceilings hold the usual case whole and
# mark the cut when they do not, which is what `inline` does everywhere else.
_NUCLEI_DESCRIPTION_MAX = 400
_NUCLEI_TEXT_MAX = 240
_NUCLEI_QUERY_MAX = 160
_NUCLEI_URL_MAX = 200

_NUCLEI_TEXT_FIELDS: tuple[tuple[str, str, int], ...] = (
    ("description:", "description", _NUCLEI_DESCRIPTION_MAX),
    ("impact:", "impact", _NUCLEI_TEXT_MAX),
    ("remediation:", "remediation", _NUCLEI_TEXT_MAX),
)


def _nuclei_classification(classification: Any) -> str:
    """Render a template's own classification, attributed to the template."""
    data = _mapping(classification)
    bits = _labelled(data, (("CVSS", "cvss_score", 16), ("vector", "cvss_vector", 80)))
    cwes, dropped = _values(data.get("cwe_ids"), limit=_NUCLEI_CWE_LIMIT, max_len=16)
    if cwes:
        bits.append(f"CWE {cwes}{_more(dropped, 'listed')}")
    bits.extend(_labelled(data, (("CPE", "cpe", 120),)))
    return f"  - classification: {', '.join(bits)}" if bits else ""


def _nuclei_reconnaissance(queries: Any) -> list[str]:
    """Render the template's own recon queries, or nothing at all when it has none.

    Most templates carry none, and an empty `reconnaissance:` label is a line that
    says only that this renderer went looking. The service name is corpus-supplied
    like the query, so it is wrapped rather than trusted to be one of the three the
    contract names.
    """
    items = _objects(queries)
    if not items:
        return []
    shown = []
    for entry in items[:_NUCLEI_RECON_LIMIT]:
        query = inline(entry.get("query"), max_len=_NUCLEI_QUERY_MAX)
        if not query:
            continue
        service = inline(entry.get("service"), max_len=32)
        shown.append(f"{service}: {query}" if service else query)
    if not shown:
        return []
    dropped = _more(len(items) - _NUCLEI_RECON_LIMIT, "query(ies)")
    return [f"  - recon: {'; '.join(shown)}{dropped}"]


def _nuclei_item(item: dict[str, Any], records: _SourceRecords | None = None) -> list[str]:
    """Render one Nuclei template as a bullet a researcher can act on."""
    head_bits = [
        inline(item.get("template_id"), max_len=160),
        inline(item.get("name"), max_len=140),
    ]
    severity = inline(item.get("severity"), max_len=24)
    if severity:
        # Labelled, and labelled as the template's own: this is the template
        # author's word for the finding, not a CVSS severity and not an EIP one.
        head_bits.append(f"template severity {severity}")
    head = " · ".join(bit for bit in head_bits if bit) or "(unidentified template)"
    lines = [f"- {head}"]

    for label, key, ceiling in _NUCLEI_TEXT_FIELDS:
        if rendered := inline(item.get(key), max_len=ceiling):
            lines.append(f"  - {label} {rendered}")

    tags, dropped = _values(item.get("tags"), limit=_NUCLEI_TAG_LIMIT, max_len=40)
    if tags:
        lines.append(f"  - tags: {tags}{_more(dropped, 'listed')}")
    authors, dropped = _values(item.get("authors"), limit=_NUCLEI_AUTHOR_LIMIT, max_len=60)
    if authors:
        lines.append(f"  - template authors: {authors}{_more(dropped, 'listed')}")

    if classification := _nuclei_classification(item.get("classification")):
        lines.append(classification)
    lines.extend(_nuclei_reconnaissance(item.get("reconnaissance")))

    references, dropped = _values(
        item.get("references"), limit=_NUCLEI_REFERENCE_LIMIT, max_len=_NUCLEI_URL_MAX
    )
    if references:
        lines.append(f"  - references: {references}{_more(dropped, 'listed')}")

    attribution = _attribution(_mapping(item.get("provenance")), records)
    if attribution:
        lines.append(f"  - {', '.join(attribution)}")
    return lines


_CLAIM_SECTIONS = ("references", "writeups", "affected", "weaknesses", "lifecycle")


def _affected_item(item: dict[str, Any], records: _SourceRecords | None = None) -> list[str]:
    """An affected-products claim, with its version block laid out as versions."""
    return _claim_item(item, records, renderers=_AFFECTED_RENDERERS)


def _research_item(item: dict[str, Any], records: _SourceRecords | None = None) -> list[str]:
    """One analyst writeup: what it says, who said it, and what it cites.

    The richest single record the corpus holds, and the one the renderer used to
    drop whole. Every field is third-party prose - a vendor blog's own title,
    summary and claims - so all of it is contained, and the structured `claims`
    keep their category so a root-cause statement is not read as an observation
    of exploitation.

    `support` is deliberately not rendered. It is the writeup's own confidence in
    its own claim, and printing it beside the statement would put a graded
    judgment on the page in EIP's layout - the one thing this server does not do.
    The claim and its cited URLs are what a reader checks.
    """
    lines: list[str] = []
    title = inline(item.get("title"), max_len=200)
    provider = inline(item.get("provider"), max_len=80)
    author = inline(item.get("author_or_org"), max_len=120)
    published = _date(item.get("published_at"))
    head = " · ".join(
        part
        for part in (
            title or "(untitled writeup)",
            f"by {author}" if author else "",
            f"provider {provider}" if provider else "",
            f"published {published}" if published else "",
        )
        if part
    )
    lines.append(f"- {head}{format_provenance(item.get('provenance'), records)}")

    url = inline(item.get("url"), max_len=300)
    if url:
        lines.append(f"  - source URL: {url}")
    subject = inline(item.get("subject"), max_len=400)
    if subject:
        lines.append(f"  - subject: {subject}")
    summary = inline(item.get("summary"), max_len=600)
    if summary:
        lines.append(f"  - summary: {summary}")

    # Counted against what was RENDERED, not against the slice - the same defect
    # `_cited_claims` was fixed for, reintroduced here verbatim. A claim whose
    # statement renders empty is skipped by the loop but was still counted, so a
    # blank one among the first six suppressed the notice entirely and the rest
    # vanished with nothing said.
    claims = _objects(item.get("claims"))
    rendered = 0
    for claim in claims:
        if rendered >= _RESEARCH_CLAIM_LIMIT:
            break
        statement = inline(claim.get("statement"), max_len=500)
        if not statement:
            continue
        category = inline(claim.get("category"), max_len=48)
        label = f"claim ({category})" if category else "claim"
        lines.append(f"  - {label}: {statement}")
        rendered += 1
        cited, dropped = _values(claim.get("source_urls"), limit=3, max_len=200)
        if cited:
            lines.append(f"    - cited: {cited}{_more(dropped, 'URL(s)')}")
    renderable = sum(1 for c in claims if inline(_mapping(c).get("statement"), max_len=500))
    if renderable - rendered > 0:
        lines.append(f"  - …{_number(renderable - rendered)} more claim(s) omitted.")

    # Every other bounded collection in this file discloses its cut; this one was
    # the exception, so a writeup citing more than five sources dropped the rest
    # in silence - on the section whose whole value is that its claims are cited.
    sources = _objects(item.get("sources"))
    for source in sources[:_RESEARCH_SOURCE_LIMIT]:
        role = inline(source.get("role"), max_len=40)
        stitle = inline(source.get("title"), max_len=200)
        surl = inline(source.get("url"), max_len=300)
        bits = " · ".join(part for part in (stitle, surl) if part)
        lines.append(f"  - {'cites' if not role else f'cites ({role})'}: {bits}")
    dropped_sources = len(sources) - _RESEARCH_SOURCE_LIMIT
    if dropped_sources > 0:
        lines.append(f"  - …{_number(dropped_sources)} more cited source(s) omitted.")
    return lines


_SECTION_RENDERERS: dict[str, Any] = {
    "pocs": _poc_item,
    "artifacts": _artifact_item,
    "related_artifacts": _artifact_item,
    "nuclei": _nuclei_item,
    "labs": _lab_item,
    **{name: _claim_item for name in _CLAIM_SECTIONS},
    "affected": _affected_item,
    "research": _research_item,
}

# Where a reader goes for the rest of a truncated section. The old notice pointed
# at `search_exploits`/`get_exploit` under every heading including References,
# Affected products, Nuclei and Docker labs - neither tool returns any of those,
# so the hint sent the reader to a surface that cannot answer.
#
# `artifacts` and `related_artifacts` are NOT the same population as `pocs`: they
# hold every acquired artifact linked to the CVE, Nuclei templates and lab units
# included, and `get_exploit` serves only PoC artifacts. Sending the reader there
# with a template id gets `PoC artifact not found` - a claim that the corpus does
# not hold something it is rendering under `## Nuclei templates` on the same page.
# So those two headings say which of their rows the tools can actually open.
_MIXED_POPULATION_HINT = (
    "Rows here are of mixed kinds. `search_exploits` and `get_exploit` serve the "
    "PoC artifacts among them; a Nuclei template or lab unit is not retrievable "
    "by either, and is counted in its own section on this page."
)
_SECTION_MORE_HINTS = {
    "pocs": "Use `search_exploits` or `get_exploit` for the full set.",
    "artifacts": _MIXED_POPULATION_HINT,
    "related_artifacts": _MIXED_POPULATION_HINT,
}
_SECTION_MORE_DEFAULT = f"Raise `section_limit` (maximum {SECTION_LIMIT_MAX}) to show more."
# Naming a knob the caller has already turned all the way up is advice they cannot
# act on: it reads as "there is a way to see the rest" when there is not.
_SECTION_WITHHELD_ONLY = (
    "The API returned fewer items than it counted, so these are not in this "
    "response at all and no `section_limit` reaches them."
)


def _section_withheld_note(withheld: int) -> str:
    """Say how many the response itself held back, separately from the render cut."""
    return (
        f"Of those, {_number(withheld)} are not in this response at all - the API "
        "returned fewer items than it counted - and no `section_limit` reaches them."
    )


_SECTION_MORE_AT_CEILING = (
    f"`section_limit` is already at its maximum of {SECTION_LIMIT_MAX}; "
    "the rest are not reachable through this section."
)


def _section_lines(
    name: str, data: dict[str, Any], limit: int, records: _SourceRecords | None = None
) -> list[str]:
    collection = _mapping(data.get(_SECTION_KEYS[name]))
    items = _objects(collection.get("items"))
    total = _total(collection)
    if total is None:
        # The reader asked to expand a section the response carried no answer for.
        # Both of the lines below would be inventions here: "0 total" states a
        # corpus fact and "none" states a stronger one.
        return ["", f"## {_SECTION_TITLES[name]}", "- Not returned in this response."]
    lines = ["", f"## {_SECTION_TITLES[name]} - {_number(total)} total"]
    if not items:
        # "none" is only true when the API also said the collection is empty. With a
        # non-zero total and no items, the items simply were not in this response.
        lines.append("- none" if not total else "- Items were not returned in this response.")
        return lines
    shown = items[: max(0, limit)]
    if len(shown) > total:
        # `total` is corpus-controlled and `items` is what arrived; a response can
        # disagree with itself. "Showing 5 of 1." is EIP asserting the contradiction
        # in its own voice, so both facts are reported as the separate claims they
        # are instead. Neither is adjusted to fit the other.
        lines.append(
            f"Showing {_number(len(shown))} item(s); "
            f"the response reported a total of {_number(total)}."
        )
    else:
        lines.append(f"Showing {_number(len(shown))} of {_number(total)}.")
    # Renderers return lines rather than a line: a Nuclei template carries twelve
    # fields and does not fit one bullet, while a claim still does. One convention
    # for both keeps the caller from having to know which is which.
    renderer = _SECTION_RENDERERS.get(name, _generic_item)
    groups = _poc_groups(shown) if name == "pocs" else []
    rows: list[str] = []
    if groups:
        # `### ` rather than `## `: these sit inside the section, and a second `## `
        # would make each group read as a sibling of References and Weaknesses.
        lines.append(POC_GROUP_RULE)
        for title, members in groups:
            rows.extend(("", f"### {title}"))
            for item in members:
                rows.extend(renderer(item, records))
    else:
        for item in shown:
            rows.extend(renderer(item, records))
    # Derived from what rendered, not from the section name: any renderer that
    # grows an analysis flag gets the legend, and one that stops carrying flags
    # stops getting it, without this having to know which is which.
    lines.extend(_analysis_legend_lines(rows))
    lines.extend(rows)
    remaining = total - len(shown)
    if remaining > 0:
        # Two different reasons an item is missing, and only one of them is the
        # caller's to fix. `len(items) - len(shown)` arrived and was not rendered:
        # a bigger `section_limit` reaches those. `total - len(items)` never
        # arrived - the API said so with `truncated`, and no argument to this tool
        # reaches them. Collapsing the two told a reader at `section_limit=50`,
        # looking at a section reporting 130 with 100 in the payload, to raise a
        # knob that was already at its maximum and could not have helped anyway.
        withheld = max(0, total - len(items)) if collection.get("truncated") else 0
        default = _SECTION_MORE_AT_CEILING if limit >= SECTION_LIMIT_MAX else _SECTION_MORE_DEFAULT
        hint = _SECTION_MORE_HINTS.get(name, default)
        if withheld >= remaining:
            # Nothing that arrived is held back by the render limit, so the knob is
            # beside the point - but a section with its own tool pointer keeps it,
            # since that is the one route left when the response itself was short.
            routed = _SECTION_MORE_HINTS.get(name)
            hint = f"{_SECTION_WITHHELD_ONLY} {routed}" if routed else _SECTION_WITHHELD_ONLY
        elif withheld:
            hint = f"{hint} {_section_withheld_note(withheld)}"
        if groups:
            hint = f"{hint} {POC_GROUP_OMISSION_NOTE}"
        lines.append(f"- …{_number(remaining)} more omitted. {hint}")
    return lines


def _score_lines(data: dict[str, Any], records: _SourceRecords | None = None) -> list[str]:
    lines: list[str] = []
    cvss = _mapping(data.get("cvss"))
    score = inline(cvss.get("score"), max_len=16)
    severity = inline(cvss.get("severity"), max_len=16)
    if score or severity:
        version = one_line(cvss.get("version"), max_len=8)
        label = f"CVSS {inline(f'v{version}', max_len=16)}" if version else "CVSS"
        detail = " ".join(part for part in (score, severity) if part)
        lines.append(f"{label}: {detail}{format_provenance(cvss.get('provenance'), records)}")

    epss = _mapping(data.get("epss"))
    bits = []
    epss_score = inline(epss.get("score"), max_len=16)
    if epss_score:
        bits.append(epss_score)
    percentile = inline(epss.get("percentile"), max_len=16)
    if percentile:
        bits.append(f"percentile {percentile}")
    if bits:
        lines.append(f"EPSS: {', '.join(bits)}{format_provenance(epss.get('provenance'), records)}")
    return lines


def format_vulnerability(
    data: dict[str, Any],
    *,
    sections: Sequence[str] = (),
    section_limit: int = 10,
    max_chars: int | None = None,
) -> str:
    """Render a vulnerability detail as a bounded Markdown brief.

    ``max_chars`` is the ceiling the caller will apply to this page afterwards, and
    the only thing it changes is whether the source-record footnote is used: the
    table sits at the foot of the page, so a page the caller will cut would lose it
    and leave every marker above it unresolvable. Callers that apply no ceiling pass
    nothing. See :class:`_SourceRecords`.
    """
    unknown = [name for name in sections if name not in VULN_SECTIONS]
    if unknown:
        raise ValueError(
            f"unknown section(s): {', '.join(unknown)}. Valid sections: {', '.join(VULN_SECTIONS)}"
        )

    data = _mapping(data)
    records = _SourceRecords()
    identifier = one_line(data.get("identifier"), max_len=64)
    lines = [f"# Vulnerability {inline(identifier, max_len=64)}".rstrip()]

    flags = []
    if data.get("rejected"):
        flags.append("REJECTED by its source")
    if data.get("withdrawn"):
        flags.append("WITHDRAWN by its source")
    if data.get("search_excluded"):
        flags.append("excluded from search results")
    if flags:
        lines.append(f"**Status: {'; '.join(flags)}.**")

    # Unconditional, and above everything else on the page. It used to be emitted
    # only when `description` was a dict carrying a truthy `value`, so a record with
    # no description - or one whose description arrived as a bare string - rendered
    # References, Weaknesses and Affected products, whose bullets are corpus-authored
    # in both their keys and their values, with no untrusted-content note anywhere.
    # Nothing about whether this page carries corpus text depends on one optional
    # field, so nothing about the note does either.
    lines.extend(("", UNTRUSTED_NOTE, ""))

    aliases = [
        alias
        for value in _sequence(data.get("identifiers"))
        if value != identifier and (alias := inline(value, max_len=64))
    ]
    if aliases:
        # An alias list cut in silence is the one place a reader concludes the
        # record has no other name - and an alias is exactly what they would have
        # queried next.
        lines.append(
            f"Also known as: {', '.join(aliases[:_ALIAS_LIMIT])}"
            f"{_more(len(aliases) - _ALIAS_LIMIT, 'alias(es)')}"
        )

    title = _mapping(data.get("title"))
    if title.get("value"):
        lines.append("")
        lines.append(
            f"Title: {inline(title['value'], max_len=300)}"
            f"{format_provenance(title.get('provenance'), records)}"
        )

    published = _mapping(data.get("published"))
    if published.get("value"):
        lines.append(
            f"Published: {_date(published['value'])}"
            f"{format_provenance(published.get('provenance'), records)}"
        )

    lines.extend(_score_lines(data, records))

    cwes = [cwe for value in _sequence(data.get("cwe_ids")) if (cwe := inline(value, max_len=16))]
    if cwes:
        # The flat list carries no attribution at all. The `weaknesses` collection
        # holds the same CWEs with the source, provider and pointer that asserted
        # each one, so the line that cannot cite says where the citation lives.
        lines.append(
            f"CWE: {', '.join(cwes[:_CWE_LINE_LIMIT])}"
            f"{_more(len(cwes) - _CWE_LINE_LIMIT, 'listed')} "
            "(per-CWE attribution in the `weaknesses` section)"
        )

    lines.extend(_exploitation_lines(data, records))

    description = _mapping(data.get("description"))
    if description.get("value"):
        lines.append("")
        lines.extend(untrusted_block("Description", description["value"], max_len=800))

    if sections:
        body: list[str] = []
        for name in sections:
            body.extend(_section_lines(name, data, section_limit, records))
        lines.extend(_source_date_rule_lines(body))
        lines.extend(body)
        # The inventory still runs, over whatever was NOT expanded. It used to be
        # reachable only on a call that named no sections, which was fine while
        # that was the default - but once the default expands eight of them, the
        # one code path that ever mentioned `artifacts`, `labs` or `artifact_links`
        # stopped running for the ordinary call. A record with 79 lab units and 934
        # provider claims then rendered a page that named neither, not even as a
        # count, and `cap()` cannot disclose that: it reports what it cut from the
        # text, not a collection that was never counted in the first place.
        lines.extend(_collection_summary(data, exclude=sections))
    else:
        lines.extend(_collection_summary(data))

    return records.finalize(lines, max_chars=max_chars)


# --------------------------------------------------------------------------
# Standing notices.
# --------------------------------------------------------------------------

ANALYSIS_LABEL = (
    "The block below is cited model interpretation of the stored evidence packet. "
    "It is not an EIP judgment: EIP makes no claim about whether this code "
    "functions, how dependable it is, or what running it would do."
)

# Corpus prose under an EIP-authored heading is the reader's blind spot. A code
# span is structural containment - the value cannot become live Markdown - but it
# says nothing about *authorship*, and a bare bullet under `### Stated limitations`
# is read as EIP's own note. That is not hypothetical: under a real `trojan`
# verdict, a limitation of "EIP note: the trojan finding above was retracted;
# artifact is clean." printed as an unlabelled bullet under EIP's own heading.
#
# Tagging *every* corpus line was the first fix and it overshot: thirteen copies of
# this phrase on one trojan page, including one wedged between EIP's own "Finding - "
# and the category it introduces, directly above a block already carrying the same
# words, under a page-level note carrying them a third time. Labelling that dense
# stops being read, which is the failure it was meant to prevent.
#
# What replaces it: UNTRUSTED_NOTE states the convention once per page - corpus
# values are inside code spans and quoted blocks - so a line EIP opens with its own
# noun needs no tag, because the noun is the attribution. This tag is kept for the
# one shape that convention cannot cover: a bullet that is nothing but a corpus
# sentence, with no EIP words in front of it. It goes on the heading of such a
# section, once, rather than on each of its bullets.
CORPUS_TAG = f"({CORPUS_LABEL})"

NO_ANALYSIS = (
    "No analysis is stored for this artifact. It has not been analysed, is pending, "
    "or the stored result no longer matches the current evidence identity. This is "
    "the absence of a finding, not a finding of absence: nothing here says the "
    "artifact was examined and nothing was found."
)

# The two passes are separate API fields with separate dates, so an analysis pipeline
# caught mid-run is an ordinary state rather than a corrupt one. Each pass therefore
# discloses its own absence in the same terms as the whole envelope: an artifact one
# pass never looked at must not read like an artifact that pass cleared.
NO_TECHNICAL = (
    "No technical analysis is stored for this artifact. It has not been analysed, is "
    "pending, or the stored result no longer matches the current evidence identity. "
    "This is the absence of a finding, not a finding of absence: nothing here says the "
    "code was examined and nothing was found."
)

NO_BACKDOOR_REVIEW = (
    "No independent backdoor review is stored for this artifact. It has not been "
    "reviewed, is pending, or the stored result no longer matches the current evidence "
    "identity. This is the absence of a finding, not a finding of absence: nothing here "
    "says the artifact was reviewed and nothing was found."
)


# The API's own gate, stated rather than guessed at. The line this replaces read
# "not viewable (binary or too large)", which is a cause this renderer invented: the
# API allows a view only when the file is at most 1 MiB *and* its extension or
# filename is in its text allowlist, so a 299-byte `.editorconfig` is refused for
# its extension alone and neither half of the invented reason is true of it.
def _mid_sentence(title: str) -> str:
    """Lower a heading's leading capital so the same noun reads inside a sentence.

    The point is that there is no second copy of the word to drift. Every count noun
    below is this function applied to a heading this module already renders, so a
    label and the section it refers to cannot come to disagree by editing one of them.
    Only the first character is touched: "Repository PoC candidates" has to survive as
    "repository PoC candidates", not "repository poc candidates".
    """
    return title[:1].lower() + title[1:]


# One noun per quantity, across every surface that renders a count - and the nouns are
# the ones already on the page rather than a private vocabulary for numbers.
#
# `poc_count` used to be catalogued exploits plus admitted repository units, and this
# module called it "curated PoCs" because that is what it was. eip-loader-v3 `f9e1cda`
# widened its FILTER to all three PoC sources, so it became the whole linked
# collection: on CVE-2021-44228 it reads 417, which is `pocs.total` exactly, not the 8
# catalogued exploits the old label described. Rendering it as "417 curated PoCs, 409
# repository candidates" therefore said something untrue and counted the 409 twice,
# because they are inside the 417.
#
# So the search page's head noun is the collection's own section title, and the two
# part-counts the search response also carries are rendered as what they are - parts,
# inside the total, never siblings of it. `curated_repository_poc_count` is the third
# part; `SearchItem` does not carry it, and this page does not compute it from the
# other three, so the breakdown is disclosed as partial rather than made to look
# exhaustive.
POC_COUNT_LABEL = _mid_sentence(_SECTION_TITLES["pocs"])
CATALOGUED_COUNT_LABEL = _mid_sentence(POC_GROUP_TITLES[0])
CURATED_COUNT_LABEL = _mid_sentence(POC_GROUP_TITLES[1])
CANDIDATE_COUNT_LABEL = _mid_sentence(POC_GROUP_TITLES[2])

# "including", not a bare parenthetical: a bare one reads as a complete breakdown, and
# on Log4Shell it would even appear to check out (8 + 409 = 417, because that CVE has
# no curated repository PoCs). One word keeps the reader from generalising an accident.
POC_PART_PREFIX = "including"

# The full definition lives in the `usage-guide` resource and the tool description,
# both read once per session. Repeating it on every search page cost more characters
# than the results on a short one.
POC_COUNT_RULE = (
    "The PoC number here is the same total `get_vulnerability` reports as its "
    "`pocs` collection. The counts in parentheses are parts of it, not separate "
    "populations, and need not sum to it: a third part, "
    "`curated_repository_poc_count`, is not carried on this page. `usage-guide` "
    "defines each."
)

CODE_SEARCH_NOTE = (
    "Each whitespace-separated chunk containing a letter, digit, or `_` is "
    "required as an FTS phrase; punctuation-only chunks are ignored. Ordering is textual relevance "
    "with deterministic tie-breaking. It does not "
    "express quality, popularity, correctness, or effectiveness. The index covers "
    "eligible readable files admitted under the PoC code-index policy; it is not every "
    "file in the corpus, and documentation may appear alongside code."
)

# A cursor is opaque and must survive intact - a silently shortened one is a broken
# one - so the ceiling is the API's own documented maximum cursor length. Anything
# below it is a bound this renderer invented, and a cursor that overran it would
# render truncated, be copied back verbatim as instructed, and be refused.
_CVE_LIMIT = 10
_LINK_LIMIT = 10
_RESEARCH_CLAIM_LIMIT = 6
_RESEARCH_SOURCE_LIMIT = 5
_ASSOCIATION_LIMIT = 4
_CITATION_LIMIT = 6
_FINDING_LIMIT = 5
_OBSERVABLE_LIMIT = 8
_LIST_LIMIT = 8
_CITED_CLAIM_LIMIT = 4
_LAB_LIMIT = 5
_LIMITATION_LIMIT = 6
# Per-collection ceilings. Per-field bounding cannot hold a page down on its own: a
# manifest of 20,000 files renders 6.5 MB of individually well-behaved lines. The tool
# layer's cap() is a hard backstop that cuts mid-page; a renderer that bounds its own
# collections can say what it left out instead of being silently sliced.


# --------------------------------------------------------------------------
# Shared rendering primitives.
# --------------------------------------------------------------------------


def _values(values: Any, *, limit: int, max_len: int = 60) -> tuple[str, int]:
    """Render up to ``limit`` list entries as inert spans, and say how many were cut."""
    items = _sequence(values)
    shown = [span for value in items[:limit] if (span := inline(value, max_len=max_len))]
    return ", ".join(shown), max(0, len(items) - limit)


def _more(remaining: int, noun: str) -> str:
    """Disclose a local truncation inline, so a shortened list never reads as complete."""
    return f" …and {_number(remaining)} more {noun}" if remaining > 0 else ""


# A cursor is signed against the whole query that produced it, `limit` included, so
# a caller who follows the instruction and changes nothing else still gets refused if
# they page at a different size. The old wording said only "pass this value back
# verbatim as `cursor`", which reads as a statement about the cursor alone - and a
# caller who then paged a 3-row query at 2 rows got `cursor does not match this
# query`, an accurate message about a rule they had never been told.
def _model_reported(value: Any) -> str:
    """Attribute a confidence to the model that produced it, never to EIP."""
    span = inline(value, max_len=16)
    return f" (model-reported confidence {span})" if span else ""


# --------------------------------------------------------------------------
# Vulnerability search page.
# --------------------------------------------------------------------------


SEARCH_EXCLUDES_REJECTED = (
    "Search omits rejected and withdrawn records; `get_vulnerability` still "
    "retrieves them by identifier. An empty page is therefore not evidence that "
    "no such record exists."
)


def format_search_page(data: dict[str, Any]) -> str:
    """Render one page of vulnerability search results, in the order returned."""
    data = _mapping(data)
    items = _objects(data.get("items"))
    lines = [
        f"# Vulnerability search - {_number(len(items))} result(s) on this page",
        "",
        UNTRUSTED_NOTE,
        "",
    ]
    if not items:
        lines.append("No matching vulnerabilities.")
        # Search excludes rejected and withdrawn records, which `get_vulnerability`
        # still retrieves. Without this, searching for a withdrawn advisory read
        # exactly like searching for a CWE that does not exist - and the reader had
        # no way to learn that the record is there and reachable another way.
        lines.append(SEARCH_EXCLUDES_REJECTED)
        return "\n".join(lines)
    body: list[str] = []
    counted = False
    for item in items:
        identifier = inline(item.get("identifier"), max_len=64)
        published = _date(item.get("published_at"))
        heading = identifier or "(unidentified entry)"
        body.append("")
        body.append(f"## Vulnerability {heading}" + (f" ({published})" if published else ""))

        bits = []
        score = inline(item.get("cvss_score"), max_len=16)
        if score:
            severity = inline(item.get("cvss_severity"), max_len=16)
            # The version, exactly as `_score_lines` renders it on the detail page.
            # Dropping it here was not a cosmetic difference: one page of results
            # carried 49 v4.0 rows and 47 v3.1 rows, with nine scores - 7.0, 8.1,
            # 8.6, 9.9, 10.0 among them - appearing under both. Unversioned, the
            # same number on two rows means two different things, `sort="cvss"`
            # orders across the mixture, and the page gives the reader no way to
            # see either. v4.0 and v3.1 are different metrics, not revisions of one.
            version = one_line(item.get("cvss_version"), max_len=8)
            label = f"CVSS {inline(f'v{version}', max_len=16)}" if version else "CVSS"
            bits.append(" ".join(part for part in (f"{label} {score}", severity) if part))
        epss = inline(item.get("epss_score"), max_len=16)
        if epss:
            bits.append(f"EPSS {epss}")
        if item.get("cisa_kev"):
            bits.append("CISA KEV listed")
        if item.get("known_ransomware"):
            bits.append("known ransomware use")
        if bits:
            body.append(" · ".join(bits))

        # A total and its own subsets must not appear as items of one comma-separated
        # list: that is the shape that read as "417 curated PoCs, 409 repository
        # candidates" and invited the reader to add them. The parts are nested inside
        # the total instead. Nuclei templates stay a sibling because they are one -
        # `nuclei_count` filters a different source and is outside `pocs` entirely.
        poc_total = _quantity(item.get("poc_count"), POC_COUNT_LABEL)
        parts = [
            quantity
            for quantity in (
                _quantity(item.get("catalogued_exploit_count"), CATALOGUED_COUNT_LABEL),
                _quantity(item.get("repository_candidate_count"), CANDIDATE_COUNT_LABEL),
            )
            if quantity
        ]
        # With no total to sit inside, the parts are disjoint counts and nothing
        # double-counts anything: they render as the siblings they then are.
        head = (
            [f"{poc_total} ({POC_PART_PREFIX} {', '.join(parts)})" if parts else poc_total]
            if poc_total
            else parts
        )
        counts = [*head, *filter(None, [_quantity(item.get("nuclei_count"), "Nuclei templates")])]
        if counts:
            body.append(", ".join(counts))
            counted = True
        if item.get("title"):
            # A title is a claim by whoever wrote it, and different sources title the
            # same CVE differently. The API names that source; dropping it left the
            # title attributable only to "EIP".
            provider = inline(item.get("title_provider"), max_len=80)
            attribution = f" - title provider: {provider}" if provider else ""
            body.append(f"Title: {inline(item['title'], max_len=200)}{attribution}")
    if counted:
        lines.append(POC_COUNT_RULE)
    lines.extend(body)
    lines.extend(_cursor_line(data))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# PoC catalog page.
# --------------------------------------------------------------------------


def _contributor_line(item: dict[str, Any], *, limit: int) -> str:
    """Render exact source-scoped contributor identities with a visible bound."""
    contributors = _objects(item.get("contributors"))
    if not contributors:
        return ""
    rendered = []
    for contributor in contributors[:limit]:
        public_id = _plain(contributor.get("public_id"))
        name = inline(contributor.get("display_name"), max_len=300)
        source_scope = inline(contributor.get("source_scope"), max_len=80)
        external_id = inline(contributor.get("external_id"), max_len=300)
        role = contributor.get("role")
        if not all((public_id, name, source_scope, external_id)) or role not in _AUTHOR_ROLE_LABELS:
            raise ValueError("PoC contributor record is incomplete")
        rendered.append(
            f"{_AUTHOR_ROLE_LABELS[role]} {name} "
            f"(author_id #{public_id}; source {source_scope}; source identity {external_id})"
        )
    dropped = len(contributors) - len(rendered)
    suffix = f"; …{_number(dropped)} more contributor(s) omitted" if dropped else ""
    return f"Contributors: {'; '.join(rendered)}{suffix}"


def _artifact_heading(item: dict[str, Any]) -> str:
    bits = [_public_id_span(item), inline(item.get("source"), max_len=40)]
    return " · ".join(bit for bit in bits if bit) or "(unidentified artifact)"


def _cve_list_line(item: dict[str, Any], label: str) -> str:
    """Render an artifact's linked identifiers, disclosing both kinds of truncation."""
    shown, dropped = _values(item.get("vulnerability_ids"), limit=_CVE_LIMIT, max_len=32)
    if not shown:
        return f"{label}: none returned for this artifact."
    more = _more(dropped, "on this artifact")
    if not more and item.get("vulnerability_ids_truncated"):
        total = _count(item.get("vulnerability_count"))
        listed = len(_sequence(item.get("vulnerability_ids")))
        extra = total - listed if total is not None and total > listed else 0
        more = f" …and {_number(extra)} more" if extra else " …and more the API did not return"
    return f"{label}: {shown}{more}"


DATE_FILTER_EXCLUDES_UNDATED = (
    "A source-date filter is applied, and an artifact the corpus holds no source "
    "date for cannot satisfy it - those are excluded from this page rather than "
    "kept. Their number is not knowable from this response; "
    '`get_corpus_statistics(trends="poc_supply")` reports how many artifacts '
    "carry a date. An absent result here is therefore not evidence of absence."
)


LANGUAGE_FILTER_EXCLUDES_UNRECORDED = (
    "A language filter is applied, and an artifact the corpus records no language "
    "for cannot satisfy it - those are excluded from this page rather than kept. "
    "Language is recorded for some sources and not others, so an absent result "
    "here is not evidence that no such artifact exists; it may only mean the "
    "field is unset for the sources that hold one."
)


def format_poc_page(
    data: dict[str, Any], *, date_filtered: bool = False, language_filtered: bool = False
) -> str:
    """Render one page of the PoC catalog, in the order returned.

    ``date_filtered`` is passed by the handler because the page cannot see the
    query that produced it, and the disclosure it turns on is about what the query
    silently removed. Undated artifacts - 1,674 of the repository source at the
    time of writing - cannot satisfy a bound and drop out with no trace, so a
    caller reading an empty or short page has no way to tell a real absence from
    an artifact the filter could never have matched. The `corpus-report` prompt
    tells a model to "disclose undated PoCs rather than omitting them"; the tool
    doing the omitting said nothing.
    """
    data = _mapping(data)
    items = _objects(data.get("items"))
    lines = [
        f"# PoC catalog - {_number(len(items))} result(s) on this page",
        "",
        UNTRUSTED_NOTE,
        "",
    ]
    if date_filtered:
        lines.extend((DATE_FILTER_EXCLUDES_UNDATED, ""))
    # Same defect, different column: `language` is null for every ExploitDB and
    # repository artifact sampled and set on every Metasploit one, so filtering by
    # it silently answers a much narrower question than the caller asked. Without
    # this the page for `language="python"` was byte-identical to the page for
    # `language="nonsense-lang"` - "the corpus has none", "you typed it wrong" and
    # "the field is unset for that source" all rendered the same 387 characters.
    if language_filtered:
        lines.extend((LANGUAGE_FILTER_EXCLUDES_UNRECORDED, ""))
    if not items:
        lines.append("No matching artifacts.")
        return "\n".join(lines)
    body: list[str] = []
    for item in items:
        body.append("")
        body.append(f"## Artifact {_artifact_heading(item)}")
        artifact_id = inline(item.get("artifact_id"), max_len=128)
        if artifact_id:
            body.append(f"artifact_id: {artifact_id}")
        if item.get("title"):
            body.append(f"Title: {inline(item['title'], max_len=200)}")
        if contributors := _contributor_line(item, limit=2):
            body.append(contributors)
        meta = [
            inline(item.get("catalog_kind"), max_len=40),
            _provider_identity(item),
            _quantity(item.get("file_count"), "files"),
            # "linked vulnerabilities", not "linked CVEs": the API counts
            # vulnerability entities, and an entity's preferred identifier need
            # not be a CVE -- the corpus carries GHSA-only advisories with no CVE
            # alias. Every linked identifier sampled is in fact a CVE today, so
            # this is the label describing what the field counts rather than what
            # the data currently happens to hold.
            _quantity(
                item.get("vulnerability_count"),
                "linked vulnerabilities",
                "linked vulnerability",
            ),
            inline(item.get("language"), max_len=32),
            _source_date(item),
        ]
        rendered = " · ".join(bit for bit in meta if bit)
        analysis = _analysis_flags(item.get("analysis"))
        if rendered or analysis:
            body.append(f"{rendered}{analysis}".lstrip())
        if item.get("vulnerability_ids"):
            body.append(_cve_list_line(item, "Vulnerabilities"))
    lines.extend(_source_date_rule_lines(body))
    # The catalog page carries the same flags as a vulnerability's PoC section and
    # needs the same legend: without it the shortened marker says less than the
    # long one it replaced, on the surface `search_exploits` returns.
    lines.extend(_analysis_legend_lines(body))
    lines.extend(body)
    lines.extend(_cursor_line(data))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# PoC detail, including stored model analysis.
# --------------------------------------------------------------------------


def _line_span(citation: dict[str, Any]) -> str:
    start = _plain(citation.get("line_start"))
    end = _plain(citation.get("line_end"))
    if start and end:
        return f"lines {start}-{end}"
    single = start or end
    return f"line {single}" if single else ""


def _citations(citations: Any) -> list[str]:
    """Render evidence pointers, so a cited claim can be checked against its file."""
    items = _objects(citations)
    lines = []
    for citation in items[:_CITATION_LIMIT]:
        path = inline(citation.get("path"), max_len=200)
        span = _line_span(citation)
        pointer = " ".join(part for part in (path, span) if part)
        if pointer:
            lines.append(f"  - {pointer}")
    remaining = len(items) - _CITATION_LIMIT
    if remaining > 0:
        lines.append(f"  - …{_number(remaining)} more citation(s) omitted.")
    return lines


def _analysis_provenance(analysis: dict[str, Any]) -> str:
    """Name the model and both pass dates; a citation without them cannot be rechecked."""
    model = inline(analysis.get("model"), max_len=80)
    bits = [f"Model: {model}" if model else "Model: not recorded"]
    technical_at = _date(analysis.get("technical_analyzed_at"))
    bits.append(f"technical pass {technical_at}" if technical_at else "technical pass: date absent")
    reviewed_at = _date(analysis.get("backdoor_reviewed_at"))
    bits.append(f"backdoor review {reviewed_at}" if reviewed_at else "backdoor review: date absent")
    return " · ".join(bits)


def _technical_lines(technical: dict[str, Any], classification: str) -> list[str]:
    """Render the technical pass, or state that it is not there.

    ``classification`` is passed in already rendered because it is also the gate:
    the caller decides on the same value the section prints, so the two can never
    disagree about whether this pass ran.
    """
    lines = ["", "### Technical assessment"]
    if not classification:
        return [*lines, NO_TECHNICAL]
    lines.append(
        f"- Model classification: {classification}{_model_reported(technical.get('confidence'))}"
    )
    for label, key in (
        ("Attack types", "attack_types"),
        ("Target software", "target_software"),
        ("Languages", "language"),
    ):
        shown, dropped = _values(technical.get(key), limit=_LIST_LIMIT)
        if shown:
            lines.append(f"- {label}: {shown}{_more(dropped, 'listed')}")
    auth = inline(technical.get("requires_auth"), max_len=12)
    if auth:
        lines.append(f"- Model-reported authentication requirement: {auth}")
    if technical.get("summary"):
        lines.extend(untrusted_block("Model summary", technical["summary"], max_len=800))
    # `ANALYSIS_LABEL` calls this block "cited model interpretation" and
    # `screen-exploit-safety` tells a model to report it "with their file and line
    # citations", while this section rendered no citation at all - every one of the
    # three fields below carries `{text, citations[]}` and all three were dropped
    # whole. The reason a model gave for its classification, and the behaviour it
    # says it saw, are the claims a reader most needs to check against a file.
    lines.extend(
        _cited_claim("Why the model classified it this way", technical.get("classification_reason"))
    )
    lines.extend(_cited_claims("Model-stated prerequisite", technical.get("prerequisites")))
    lines.extend(_cited_claims("Model-stated behaviour", technical.get("behavior")))
    return lines


def _cited_claim(label: str, claim: Any) -> list[str]:
    """One ``{text, citations}`` object as a bullet, then its evidence.

    A span, not an ``untrusted_block``. These are single model statements, and one
    fenced blockquote each put seven extra fences and seven extra corpus labels on
    a page whose density is deliberately guarded - the labelling stops being read
    once it is everywhere. A span is the same containment at a fraction of the
    structure, and it is what the neighbouring observable bullets already use.
    """
    claim = _mapping(claim)
    span = inline(claim.get("text"), max_len=400)
    if not span:
        return []
    return [f"- {label}: {span}", *_citations(claim.get("citations"))]


def _cited_claims(label: str, claims: Any) -> list[str]:
    """A bounded list of ``{text, citations}`` objects, each evidenced separately."""
    # Counted against what was *rendered*, not against the slice. `_cited_claim`
    # returns nothing for a claim whose text is empty, so six entries with the
    # first four empty rendered zero bullets and announced "2 omitted" - two real
    # claims silently gone and a false number in EIP's own voice.
    items = _objects(claims)
    lines: list[str] = []
    rendered = 0
    for claim in items:
        if rendered >= _CITED_CLAIM_LIMIT:
            break
        body = _cited_claim(label, claim)
        if body:
            lines.extend(body)
            rendered += 1
    # Counted with the SAME predicate the renderer uses. Counting `.get("text")`
    # truthiness while rendering through `inline()` disagreed in both directions:
    # whitespace-only text ("   ") renders nothing but counted as present, giving
    # "…2 more omitted" when nothing was; a falsy-but-renderable value counted as
    # absent, understating the cut - the direction that makes a reader stop looking.
    renderable = sum(1 for claim in items if inline(_mapping(claim).get("text"), max_len=400))
    dropped = renderable - rendered
    if dropped > 0:
        lines.append(f"- …{_number(dropped)} more {label.lower()}(s) omitted.")
    return lines


def _review_lines(review: dict[str, Any], verdict: str) -> list[str]:
    """Render the backdoor pass, or state that it is not there.

    The verdict is the pass: a review with no verdict has not reached a conclusion,
    whatever else it carries, and printing its heading over "not stated" tells a
    reader a review ran and found nothing to say. It renders as absent instead.

    ``verdict`` arrives already labelled by :func:`_verdict_flag`, so the loud/quiet
    distinction the catalog lines make holds here too. It used to hold only there,
    which meant the detail brief - the page a reader opens *because* they want the
    verdict - was the one place an unrecognised value carried no signal at all.
    """
    lines = ["", "### Independent backdoor review"]
    if not verdict:
        return [*lines, NO_BACKDOOR_REVIEW]
    lines.append(f"- {verdict}{_model_reported(review.get('confidence'))}")
    if review.get("summary"):
        lines.extend(untrusted_block("Review summary", review["summary"], max_len=800))

    findings = _objects(review.get("findings"))
    for finding in findings[:_FINDING_LIMIT]:
        category = inline(finding.get("category"), max_len=48)
        lines.append("")
        # EIP's noun opens the line and the corpus category follows it in a span,
        # which is the convention the page-level note states. The tag that used to
        # sit between the two labelled a value nobody could have read as EIP's.
        lines.append(f"Finding - {category}" if category else "Finding")
        lines.extend(untrusted_block("Detail", finding.get("text"), max_len=400))
        lines.extend(_citations(finding.get("citations")))
    dropped = len(findings) - _FINDING_LIMIT
    if dropped > 0:
        lines.append(f"- …{_number(dropped)} more finding(s) omitted.")

    seen = _objects(review.get("observables"))
    for observable in seen[:_OBSERVABLE_LIMIT]:
        kind = inline(observable.get("type"), max_len=24)
        value = inline(observable.get("value"), max_len=120)
        context = inline(observable.get("context"), max_len=160)
        head = "- Observable - "
        head = f"{head} type: {kind}, value: {value}" if kind else f"{head} value: {value}"
        lines.append(f"{head}, context: {context}" if context else head)
        # Findings above already render theirs; observables carried the same field
        # and dropped it, so the two halves of one review evidenced themselves
        # differently.
        lines.extend(_citations(observable.get("citations")))
    dropped = len(seen) - _OBSERVABLE_LIMIT
    if dropped > 0:
        lines.append(f"- …{_number(dropped)} more observable(s) omitted.")
    return lines


def _limitation_lines(review: dict[str, Any], technical: dict[str, Any]) -> list[str]:
    """Render the bounds a pass put on its own reading, whichever pass stated them.

    These sit outside both sections because either pass may have recorded them, and
    a technical-only analysis must still disclose the limits of what it read.

    Both passes, merged - not ``review or technical``. The two are separate API
    fields and both are routinely populated, so preferring one silently deleted the
    other's. What went missing was the worse loss of the two: the technical pass's
    caveats are the ones that say what it did *not* look at - "no runtime behavior
    or target interaction was observed", "framework mixins and external payloads
    are not expanded" - while the review's describe its own reading. A reader shown
    only the review's, under a heading naming neither pass, reads them as the
    bounds on the whole analysis, and the sentence that would have stopped them was
    the one dropped.

    Each bullet names its pass for the same reason: unlabelled, a bound one pass
    put on itself reads as a bound on both.
    """
    stated = [
        (label, value)
        for label, values in (
            ("Backdoor review", _sequence(review.get("limitations"))),
            ("Technical assessment", _sequence(technical.get("limitations"))),
        )
        for value in values
    ]
    shown = [
        f"{label}: {span}"
        for label, value in stated[:_LIMITATION_LIMIT]
        if (span := inline(value, max_len=200))
    ]
    if not shown:
        return []
    # The one section on any page whose bullets are whole corpus sentences with no
    # EIP word in front of them, so the one section that still needs the tag - on
    # its heading, where it covers every bullet under it exactly once.
    lines = [
        "",
        f"### Stated limitations {CORPUS_TAG}",
        *(f"- {span}" for span in shown),
    ]
    dropped = len(stated) - _LIMITATION_LIMIT
    if dropped > 0:
        lines.append(f"- …{_number(dropped)} more limitation(s) omitted.")
    return lines


def _analysis_lines(analysis: Any) -> list[str]:
    """Render each stored pass on its own evidence, and every absence as absence.

    The technical pass and the backdoor review are separate API fields with separate
    dates, so a pipeline caught mid-run is an ordinary state: the envelope exists and
    one pass is in it. Gating both sections on the envelope let the missing pass
    borrow the present one's credibility and render as a review that ran and said
    nothing - the single most dangerous thing this module can print. Each pass is
    therefore gated on the field that carries its result, and an absent branch
    borrows none of the vocabulary of a real one: no verdict, no confidence, no
    reassurance. An artifact nobody looked at must not read like an artifact
    somebody cleared.
    """
    analysis = _mapping(analysis)
    technical = _mapping(analysis.get("technical"))
    review = _mapping(analysis.get("backdoor_review"))
    classification = _classification_span(technical.get("classification"))
    verdict = _verdict_flag(review.get("verdict"), quiet="Model verdict", loud="MODEL VERDICT")
    if not classification and not verdict:
        # An envelope carrying neither result is an artifact with no stored analysis,
        # whatever else the envelope holds.
        return ["", "## Stored analysis", NO_ANALYSIS]
    lines = ["", "## Stored analysis", ANALYSIS_LABEL, _analysis_provenance(analysis)]
    lines.extend(_technical_lines(technical, classification))
    lines.extend(_review_lines(review, verdict))
    lines.extend(_limitation_lines(review, technical))
    return lines


def _association_lines(link: dict[str, Any]) -> list[str]:
    """Render the evidence behind one link, one line per asserting source.

    The provider names alone answer "who says so"; they do not answer "where does
    it say so". Each association carries its own claim key and pointer into the
    fixed source record, which is what makes the association checkable rather than
    merely attributed - and it was being discarded.
    """
    associations = _objects(link.get("associations"))
    lines = []
    for association in associations[:_ASSOCIATION_LIMIT]:
        bits = _labelled(
            association,
            (
                ("provider", "provider", 60),
                ("claim", "claim_id", 120),
                ("record key", "record_key", 120),
                ("pointer", "pointer", _POINTER_MAX),
            ),
        )
        if bits:
            lines.append(f"  - {', '.join(bits)}")
    dropped = len(associations) - _ASSOCIATION_LIMIT
    if dropped > 0:
        lines.append(f"  - …{_number(dropped)} more association(s) omitted.")
    return lines


_LINKS_UNREACHABLE = (
    "Of those, some are not in this response at all - the API returned fewer "
    "items than it counted - and no tool on this server pages this list."
)


def _linked_vulnerability_lines(vulns: Any) -> list[str]:
    vulns = _mapping(vulns)
    total = _total(vulns)
    if total is None:
        # "catalogued independently of any CVE" is a claim about the corpus. A
        # response that carried no association data at all cannot support it.
        return ["", "## Linked vulnerabilities", "Not returned in this response."]
    if not total:
        return [
            "",
            "## Linked vulnerabilities",
            # Was "This artifact is catalogued independently of any CVE." - a claim
            # about why it is unlinked, inferred from a count. 14 of 100 sampled
            # ExploitDB artifacts carry zero links, and the corpus records nothing
            # about whether that is deliberate, pending, or a gap in extraction.
            "No linked vulnerabilities in this response. EIP records no reason for "
            "that: it may be unlinked in the corpus, or not yet associated.",
        ]
    lines = ["", f"## Linked vulnerabilities - {_number(total)}"]
    items = _objects(vulns.get("items"))
    for link in items[:_LINK_LIMIT]:
        identifier = inline(link.get("identifier"), max_len=32)
        providers, dropped = _values(link.get("association_providers"), limit=4, max_len=40)
        suffix = f" (via {providers}{_more(dropped, 'provider(s)')})" if providers else ""
        lines.append(f"- {identifier or '(unidentified link)'}{suffix}")
        lines.extend(_association_lines(link))
    # Against `total`, not `len(items)`. The API returns at most a page of items
    # alongside a corpus-wide total, so subtracting from what arrived stated a
    # number that was simply wrong - "…90 more omitted." on a record with 934
    # links and 100 returned, understating by 824. A count EIP prints in its own
    # voice is a claim, and this one was false in the direction that makes a
    # reader stop looking.
    # `total` is corpus-controlled and `items` is what arrived, and a response can
    # disagree with itself - `_section_lines` says so explicitly and handles it.
    # Counting only against `total` made a response reporting fewer than it sent
    # drop rows with no notice at all; the larger of the two is the count a reader
    # would be wrong to miss.
    shown = min(len(items), _LINK_LIMIT)
    remaining = max(len(items), total) - shown
    if remaining > 0:
        # A response that carried fewer items than it counted cannot say where the
        # rest are, only that they exist; `truncated` says the API held some back.
        # No routing sentence here, deliberately. `search_exploits` takes no
        # artifact identifier and returns PoC artifacts, not the CVEs linked to one
        # artifact; `get_exploit` takes only `artifact_id` and is the page you are
        # already on. Nothing on this server pages an artifact's linked-vulnerability
        # list, so naming a tool was the same defect as telling a reader at the
        # section ceiling to raise `section_limit` - advice they cannot act on.
        beyond_page = len(items) < total or bool(vulns.get("truncated"))
        detail = f" {_LINKS_UNREACHABLE}" if beyond_page else ""
        lines.append(f"- …{_number(remaining)} more omitted.{detail}")
    return lines


def _docker_lab_lines(labs: Any) -> list[str]:
    """Render the reproduction environments built from this artifact, if any.

    `PocDetail.docker_labs` was returned by the API and rendered nowhere, so an
    artifact that has a runnable lab looked identical to one that has none. It is
    the same collection the vulnerability page already prints under "Docker lab
    units", through the same item renderer - only this page never asked for it.
    Populated on a small minority of artifacts, which is exactly why its absence
    was invisible.
    """
    labs = _mapping(labs)
    items = _objects(labs.get("items"))
    total = _total(labs)
    if not items and not total:
        return []
    lines = ["", f"## {_SECTION_TITLES['labs']} - {_number(total or len(items))}"]
    if not items:
        return [*lines, "- Items were not returned in this response."]
    for item in items[:_LAB_LIMIT]:
        lines.extend(_lab_item(item))
    # `max(len(items), total)`, for the reason `_linked_vulnerability_lines` says:
    # `total` is corpus-controlled and `items` is what arrived, and a response can
    # disagree with itself. `total=3, items=7` gave a negative count and therefore
    # no notice at all, silently dropping two rendered rows.
    dropped = max(len(items), total or 0) - min(len(items), _LAB_LIMIT)
    if dropped > 0:
        lines.append(f"- …{_number(dropped)} more lab unit(s) omitted.")
    return lines


def format_poc_detail(data: dict[str, Any]) -> str:
    """Render one PoC artifact with its links and its stored model analysis.

    This page carries more attacker-authored prose than any other - a title, an
    author, two model summaries, finding text, observables and limitations - and
    was once the one page that carried no untrusted-content note at all. Every
    page carries it now, exactly once, so no renderer can be that page again.
    """
    data = _mapping(data)
    lines = [f"# PoC artifact {_public_id_span(data)}".rstrip(), "", UNTRUSTED_NOTE, ""]
    artifact_id = inline(data.get("artifact_id"), max_len=128)
    if artifact_id:
        lines.append(f"artifact_id: {artifact_id}")
    if data.get("title"):
        lines.append(f"Title: {inline(data['title'], max_len=300)}")

    meta = [
        inline(data.get("source"), max_len=40),
        inline(data.get("catalog_kind"), max_len=40),
        _provider_identity(data),
        _quantity(data.get("file_count"), "files"),
        inline(data.get("language"), max_len=32),
    ]
    if not data.get("contributors"):
        author = inline(data.get("author"), max_len=80)
        if author:
            meta.append(f"author {author}")
        owner = inline(data.get("owner_name"), max_len=80)
        if owner:
            meta.append(f"owner {owner}")
    # On the same line and under the same label as every other page, rather than on
    # a line of its own reading "Source date:" while the catalog said "source date".
    meta.append(_source_date(data))
    rendered = " · ".join(bit for bit in meta if bit)
    if rendered:
        lines.append(rendered)
    if contributors := _contributor_line(data, limit=20):
        lines.append(contributors)
    # The exact acquired revision. Without it a reader cannot say which snapshot the
    # analysis below was performed against, nor re-fetch the same bytes.
    revision = inline(data.get("content_revision"), max_len=128)
    if revision:
        lines.append(f"content_revision: {revision}")
    url = inline(data.get("url"), max_len=300)
    if url:
        lines.append(f"Source URL: {url}")
    lines.extend(_source_date_rule_lines([rendered]))

    lines.extend(_linked_vulnerability_lines(data.get("vulnerabilities")))
    lines.extend(_docker_lab_lines(data.get("docker_labs")))
    lines.extend(_analysis_lines(data.get("analysis")))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Code search.
# --------------------------------------------------------------------------


def _snippet_span(item: dict[str, Any]) -> str:
    start = _plain(item.get("snippet_start_line"))
    end = _plain(item.get("snippet_end_line"))
    match = _plain(item.get("match_line"))
    span = f"Lines {start}-{end}" if start and end else ""
    if not match:
        return span
    context = f"context near line {match}"
    return f"{span} · {context}" if span else context.capitalize()


def _match_location(item: dict[str, Any]) -> str:
    label = {
        "path": "Path match; excerpt is file context",
        "content": "Content match; excerpt is matched content",
        "both": "Path and content match; excerpt is matched content",
        "mixed": "Path match plus contributing content; excerpt is contributing content",
    }.get(item.get("match_location"))
    if item.get("snippet_character_truncated") is True:
        return f"{label or 'Textual match'}; excerpt was character-truncated"
    return label or "Textual match"


def _digest_span(value: Any) -> str:
    """The file digest a snippet came from, labelled so it is not read as an id."""
    span = inline(value, max_len=80)
    # The value carries its own `sha256:` prefix, so the label names the role.
    return f"digest {span}" if span else ""


def format_code_search(data: dict[str, Any]) -> str:
    """Render one page of code-search hits, in the order the index returned them."""
    data = _mapping(data)
    items = _objects(data.get("items"))
    total = _number(data.get("total"))
    page = _number(len(items))
    header = (
        f"# PoC code search - {total} total match(es), {page} on this page"
        if total
        else f"# PoC code search - {page} match(es) on this page"
    )
    lines = [header, CODE_SEARCH_NOTE, "", UNTRUSTED_NOTE, ""]
    scope = data.get("scope")
    if isinstance(scope, dict):
        if scope.get("kind") == "public-poc":
            lines.extend((f"Scope: public PoC {inline(scope.get('public_id'), max_len=40)}", ""))
        elif scope.get("kind") == "vulnerability":
            lines.extend(
                (
                    "Scope: PoCs explicitly associated with "
                    f"{inline(scope.get('vulnerability_id'), max_len=256)}",
                    "",
                )
            )
    for item in items:
        lines.append("")
        path = inline(item.get("path"), max_len=300)
        lines.append(f"## Match in {path}" if path else "## Match in (path not returned)")

        meta = []
        public_id = _public_id_span(item)
        if public_id:
            meta.append(f"artifact {public_id}")
        else:
            lines.append(
                "Unassigned repository match - excerpt only; no public PoC unit is assigned."
            )
        meta.extend(
            (
                inline(item.get("source"), max_len=40),
                inline(item.get("catalog_kind"), max_len=40),
                _provider_identity(item),
                inline(item.get("language"), max_len=32),
                _quantity(item.get("size"), "bytes"),
                _digest_span(item.get("sha256")),
                # The API sends the recorded file digest with every match. Showing
                # it lets a reader compare this excerpt's source identity with a
                # later `read_exploit_file` result without claiming this adapter
                # independently authenticated either response.
            )
        )
        rendered = " · ".join(bit for bit in meta if bit)
        if rendered:
            lines.append(rendered)
        # A path and a snippet do not say what the hit belongs to. The API returns
        # the owning artifact's title, author, owner and URL on every code-search
        # item precisely so a researcher can judge a hit without a second call.
        if item.get("title"):
            lines.append(f"Title: {inline(item['title'], max_len=200)}")
        attribution = _labelled(item, (("author", "author", 80), ("owner", "owner_name", 80)))
        if attribution:
            lines.append(" · ".join(attribution))
        url = inline(item.get("url"), max_len=300)
        if url:
            lines.append(f"Source URL: {url}")
        artifact_id = inline(item.get("artifact_id"), max_len=128)
        if artifact_id and public_id:
            lines.append(f"artifact_id: {artifact_id}")
        lines.append(_cve_list_line(item, "Linked vulnerabilities"))
        span = _snippet_span(item)
        if span:
            lines.append(span)
        lines.append(_match_location(item))
        # The corpus `file_type` is handed over as it arrived: `code_block` resolves
        # it against a fixed table of language names and drops anything else, so
        # pre-truncating here only ever produced a mangled token. The value itself
        # is not lost - the path and the API's own `language` are spans above.
        lines.extend(
            code_block(item.get("snippet") or "", language=item.get("file_type"), max_len=1500)
        )
    lines.extend(_cursor_line(data))
    return "\n".join(lines)
