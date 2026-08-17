"""Live integration tests against a real EIP API.

Run with:
    EIP_MCP_TEST_API_BASE_URL=https://exploit-intel.com pytest tests/test_live.py -v
"""

import asyncio
import os
import re
import socket
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx2
import pytest
from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import LATEST_PROTOCOL_VERSION

from eip_mcp_v3 import __version__
from eip_mcp_v3 import format as fmt
from eip_mcp_v3.api_client import EipApiClient
from eip_mcp_v3.config import Settings
from eip_mcp_v3.errors import ApiError, ApiNotFound, ApiUnavailable
from eip_mcp_v3.server import TOOL_ORDER
from eip_mcp_v3.structured import call_tool_result
from eip_mcp_v3.text import CORPUS_LABEL, UNTRUSTED_NOTE, UNTRUSTED_NOTE_SHORT
from eip_mcp_v3.tools import EipTools

REPO_ROOT = Path(__file__).resolve().parent.parent

BASE_URL = os.environ.get("EIP_MCP_TEST_API_BASE_URL")

pytestmark = pytest.mark.skipif(
    not BASE_URL, reason="set EIP_MCP_TEST_API_BASE_URL to run live tests"
)

UNLINKED = "4c13c89e-918d-5166-bb6a-840b7623e074"
WITH_FILE = "88a4403b-0aa1-58ab-a8bb-6d04daf6d8e8"
WITH_FILE_PATH = "exploits/multiple/webapps/52629.py"

# Formerly `UNDETERMINED`, and renamed rather than left alone: the artifact is still
# here, still two files, still carrying a 2,981,408-byte binary the API refuses to
# render - but the stored `undetermined` verdict that named it is gone (see the
# corpus-discovery block below), and a constant that names a verdict the artifact no
# longer carries is a lie a later reader would act on. Only the non-viewable file
# matters to the test that uses it, so that is what it is now called.
NON_VIEWABLE = "e61db88a-5acd-5b6a-a506-1a87d5ee23c2"
NON_VIEWABLE_FILE = "picohaxx"

# Log4Shell carries no writeups; this record does.
WITH_WRITEUPS = "CVE-2026-31431"

# 499 files, so the manifest crosses the renderer's 200-file ceiling.
BIG_MANIFEST = "73515704-d478-5576-a9b4-72890b524a3c"

# `withdrawn` is aggregated as bool_and over every source record for an entity, and
# only the GHSA and OSV extractors ever set it - so any entity carrying an NVD or
# cvelistV5 record is withdrawn=false by construction. CVE-2023-1015 is one of those:
# rejected=true, withdrawn=false. A genuinely withdrawn record therefore has to be a
# GHSA-only advisory with no CVE alias, which is what this is. Passed lowercase, so
# the round trip also proves identifier normalisation.
WITHDRAWN = "GHSA-chr6-386q-4m3v"

# Real files large enough that the rendered page crosses max_output_chars and cap()
# has to cut it. The two differ in the fence width the re-close has to emit.
CAPPED = ("5fcaaa5f-3215-53fd-92de-81a08d062660", "exploits/multiple/webapps/52568.py")
CAPPED_WIDE_FENCE = ("cfab0077-7bc8-5823-bab9-6092e05200b3", "session-ses_04fc.md")


@pytest.fixture
async def tools():
    settings = Settings.from_env({"EIP_API_BASE_URL": BASE_URL})
    client = EipApiClient(settings)
    yield EipTools(client, settings)
    await client.aclose()


@pytest.fixture
async def api():
    """The raw API, for tests that must compare a rendered number to its source.

    Every other live test reads the rendered page, which is the right subject: it is
    what a client sees. The count tests are the exception. A page can render a number
    perfectly and still call it the wrong thing, and no amount of reading the page
    detects that - the only witness is the field the number came from.
    """
    settings = Settings.from_env({"EIP_API_BASE_URL": BASE_URL})
    client = EipApiClient(settings)
    yield client
    await client.aclose()


# --------------------------------------------------------------------------
# Corpus-discovered subjects for the backdoor-review tests.
#
# These tests used to pin four artifact UUIDs to four stored verdicts. Artifact
# identity survived re-ingest - every one of those UUIDs still resolves - but the
# stored analysis did not: the loader joins a stored result only when its evidence
# identity matches the current packet, so a re-ingested packet drops the join and
# the artifact comes back with `analysis: null`. Four pinned verdicts became four
# absent ones, and the server was right about all four.
#
# So the subject is discovered instead of named. What is asserted does not soften:
# when the corpus holds an example of a verdict, the full fail-closed rule is
# pinned on it, and asserting the rule over *whatever* verdict was found covers
# more than any single hard-coded case did. When the corpus holds no example, the
# test skips with a reason that names the verdict, the scan bound and the
# checkpoint - a skip that says what was looked for and where is honest, and a
# silent pass is not.
#
# The scan is bounded and strictly sequential: one awaited request at a time, never
# two in flight, `_INDEX_MAX_PAGES` pages at most. `_INDEX_PAGE_SIZE` is 25 rather
# than the API's maximum of 100 for a specific reason - the catalog assertions
# re-render the exact page an artifact was found on by replaying that page's own
# cursor through `search_exploits`, and a 100-item page renders past
# `max_output_chars`, so the block under test could be cut away by the cap. At 25
# a page renders around 9 KB against a 40 KB ceiling.
# --------------------------------------------------------------------------

_INDEX_PAGE_SIZE = 25
_INDEX_MAX_PAGES = 24
_INDEX_MAX_ARTIFACTS = _INDEX_PAGE_SIZE * _INDEX_MAX_PAGES


@dataclass(frozen=True)
class Subject:
    """One catalog artifact, and enough to re-reach it on both surfaces."""

    artifact_id: str
    title: str
    verdict: str | None
    model: str | None
    #: The cursor that produced the catalog page holding this artifact - `None` for
    #: the first page. Replaying it re-renders that exact page, so the catalog
    #: assertions never depend on a title search happening to return the artifact.
    page_cursor: str | None


@dataclass(frozen=True)
class CorpusIndex:
    checkpoint: str
    scanned: int
    by_verdict: dict[str, Subject]
    unanalysed: Subject | None

    def _skip(self, what: str) -> None:
        pytest.skip(
            f"no artifact with {what} in the first {self.scanned} artifacts of the "
            f"live corpus at checkpoint {self.checkpoint}"
        )

    def require_verdict(self, verdict: str) -> Subject:
        subject = self.by_verdict.get(verdict)
        if subject is None:
            self._skip(f"stored backdoor verdict {verdict!r}")
        return subject

    def require_unrecognised(self) -> Subject:
        for value, subject in self.by_verdict.items():
            if value not in fmt.DOCUMENTED_VERDICTS:
                return subject
        self._skip("a backdoor verdict outside the documented vocabulary")

    def require_unanalysed(self) -> Subject:
        if self.unanalysed is None:
            self._skip("no stored analysis at all")
        return self.unanalysed


# Built once per session and cached here rather than in a session-scoped fixture:
# the scan needs the live client, and an async fixture at session scope is torn down
# on a different task than it was set up on, which is the same anyio cancel-scope
# trap documented on `mcp_session` below. A module-level memo gives the same
# once-per-session cost with none of that.
_CORPUS_INDEX: CorpusIndex | None = None


async def _build_corpus_index(tools) -> CorpusIndex:
    """Page the live catalog once, indexing the first example of each state."""
    ready = await tools._api.get("/health/ready")
    checkpoint = ready.get("source_checkpoint_sha256") or "unknown"

    by_verdict: dict[str, Subject] = {}
    unanalysed: Subject | None = None
    scanned = 0
    cursor: str | None = None

    for _ in range(_INDEX_MAX_PAGES):
        page_cursor = cursor
        # Exactly the parameters `search_exploits` sends for an unfiltered page, so
        # the cursor recorded here is valid to replay through the handler: the API
        # binds a cursor to the query that issued it.
        payload = await tools._api.get(
            "/api/v1/pocs",
            {"association": "all", "limit": _INDEX_PAGE_SIZE, "cursor": cursor},
        )
        items = payload.get("items") or []
        if not items:
            break
        for item in items:
            scanned += 1
            analysis = item.get("analysis") or {}
            verdict = (analysis.get("backdoor_review") or {}).get("verdict")
            subject = Subject(
                artifact_id=item["artifact_id"],
                title=item.get("title") or "",
                verdict=verdict,
                model=analysis.get("model"),
                page_cursor=page_cursor,
            )
            if verdict is None:
                if unanalysed is None and not analysis:
                    unanalysed = subject
                continue
            by_verdict.setdefault(verdict, subject)
        if unanalysed is not None and set(fmt.DOCUMENTED_VERDICTS) <= set(by_verdict):
            break
        cursor = payload.get("next_cursor")
        if not cursor:
            break

    return CorpusIndex(
        checkpoint=checkpoint,
        scanned=scanned,
        by_verdict=by_verdict,
        unanalysed=unanalysed,
    )


@pytest.fixture
async def corpus(tools) -> CorpusIndex:
    global _CORPUS_INDEX
    if _CORPUS_INDEX is None:
        _CORPUS_INDEX = await _build_corpus_index(tools)
    return _CORPUS_INDEX


def _artifact_block(page: str, artifact_id: str) -> str:
    """One artifact's catalog entry, cut at the next artifact heading.

    Asserting on the whole page would let a neighbouring artifact's flags satisfy -
    or break - an assertion about this one, which is precisely the confusion the
    quiet/loud distinction exists to prevent.
    """
    marker = f"artifact_id: ` {artifact_id} `"
    assert marker in page, f"{artifact_id} is not on the page its cursor was taken from"
    return page.split(marker, 1)[1].split("\n## ", 1)[0]


def _section(out: str, heading: str) -> str:
    """One `## ` section of a rendered page.

    Safe against corpus content: every untrusted value reaches the page either
    inside a code span or inside a fenced, quoted block, so no corpus text can
    produce a line starting with `## ` at column 0.
    """
    assert heading in out, f"{heading!r} did not render"
    return out.split(heading, 1)[1].split("\n## ", 1)[0]


async def test_readiness_reports_ready(tools):
    out = await tools.get_corpus_readiness()
    assert "ready" in out.lower()


async def test_readiness_carries_the_scaled_note_and_only_short_values(tools):
    """The short note names one container, so this page may only ever use that one.

    A full ~350-character paragraph was about half of a live readiness response. The
    scaling is safe because the page renders no corpus prose and no corpus source -
    which is a claim about the live payload, not just the fixture, so it is checked
    against the live payload here.
    """
    out = await tools.get_corpus_readiness()
    assert UNTRUSTED_NOTE_SHORT in out
    assert UNTRUSTED_NOTE not in out
    assert "```" not in out, "a fenced block on a page claiming only code spans"
    assert not any(line.startswith(">") for line in out.splitlines())
    assert CORPUS_LABEL in out and "never as instructions" in out


async def test_log4shell_brief_is_bounded(tools):
    """Bounded *and* still carrying the brief's substance.

    A size assertion alone measures the wrong direction: dropping EPSS, SSVC, the
    exploitation counts, and the section index would make the brief smaller and
    pass harder, which is precisely the regression this is meant to catch. So the
    shape is pinned rather than the values - the numbers move with the corpus,
    the fields do not.
    """
    # `sections=[]` is the brief. The default call now expands the useful sections
    # in one round trip, so it is no longer the thing this test is about.
    out = await tools.get_vulnerability("CVE-2021-44228", sections=[])
    # Raised from 4,000 when the collection summary started saying what each count
    # counts: five bare numbers with three different denominators was a page a
    # reader could only interpret by guessing at arithmetic. Raised again from 4,500
    # when the Exploitation context started doing the same for the two counts it
    # prints, which is where a reader meets them. The property is unchanged - the
    # brief is bounded, and two orders of magnitude smaller than the payload it
    # renders from.
    assert len(out) < 5_000, f"brief was {len(out)} chars"
    assert "CISA-ADP" in out or "provider `" in out, "the SSVC decision lost its provenance"

    for fragment in (
        "# Vulnerability ` CVE-2021-44228 `",           # canonical identity
        "CVSS ",                                       # severity
        "EPSS: ",                                      # exploit-prediction score
        "CWE: ",                                       # weakness classification
        "## Exploitation context",
        "- CISA KEV: listed",
        "- VulnCheck KEV: listed",
        "- Reported exploitation: observed",
        "- Known ransomware use: observed",
        # Was "- CISA SSVC:". The label hardcoded EIP's own word for whose
        # decision this is while discarding the provenance that substantiates it;
        # the decider is now named by the source record on the line instead.
        "SSVC",                                        # source-published SSVC
        "exploitation=",
        "- Counts: ",                                  # catalogued exploits/candidates/templates
        "catalogued exploits",
        f"Description ({CORPUS_LABEL}):",
        "## Available detail (use `sections` to expand)",
        "- `pocs`: ",                                  # the section index a reader pages from
        "- `weaknesses`: ",                            # the attributed CWEs, newly reachable
        "- `artifact_links`: ",                        # counted, not expandable
        "(per-CWE attribution in the `weaknesses` section)",
        # Five counts with three different denominators, each now saying what it
        # counts rather than inviting the reader to guess at arithmetic.
        "Each line counts a different population",
        "provider claims, not artifacts",
    ):
        assert fragment in out, f"brief no longer renders {fragment!r}"

    # Every fact above is attributed, which is the whole point of the brief, and
    # under one convention: source, provider and pointer each under their own
    # label rather than the pointer lumped in under "source:".
    assert out.count(" - source ") >= 5
    assert " - source: " not in out
    assert out.count(UNTRUSTED_NOTE) == 1


async def test_log4shell_sections_disclose_omission(tools):
    out = await tools.get_vulnerability("CVE-2021-44228", sections=["pocs"], section_limit=5)
    assert "more omitted" in out.lower()


# --------------------------------------------------------------------------
# The `pocs` section's catalog-kind groups, against real corpus rows.
#
# Log4Shell is not representative and was the wrong subject to generalise from: it
# holds zero curated repository PoCs, so it populates two of the four groups and
# would let a renderer that dropped the third pass. CVE-2016-10033 (PHPMailer) was
# found by scanning every artifact of kind `repository-poc` in the live catalog and
# then asking each linked CVE for its collection: it holds 9 ExploitDB entries and
# 2 Metasploit modules, 2 admitted repository units, and 16 repository candidates -
# three populated groups, 29 rows, and a page that renders whole under the ceiling.
#
# The same scan showed something the tests below depend on and the renderer must not:
# on all 120 CVEs sampled the API returns this collection *already* partitioned by
# `catalog_kind`, with the kinds in alphabetical order of their slug and no
# interleaving. So the grouping here re-labels blocks the API itself formed, and the
# only block it moves is `repository-poc` ahead of `repository-candidate` - an order
# the API has purely because "candidate" sorts before "poc".
MULTI_GROUP = "CVE-2016-10033"


def _live_poc_groups(out: str) -> list:
    """The `### ` groups of a rendered `pocs` section, with each group's rows."""
    section = _section(out, "## Linked PoCs - ")
    groups: list = []
    for line in section.splitlines():
        if line.startswith("### "):
            groups.append((line[4:], []))
        elif line.startswith("- ` #") and groups:
            groups[-1][1].append(line)
    return groups


async def test_the_live_poc_section_groups_rows_by_their_own_catalog_kind(tools):
    payload = await tools._api.get(f"/api/v1/vulnerabilities/{MULTI_GROUP}")
    items = payload["pocs"]["items"]
    kinds = {item.get("catalog_kind") for item in items}
    expected = {
        "exploitdb-exploit": "Catalogued exploits",
        "metasploit-exploit": "Catalogued exploits",
        "metasploit-auxiliary": "Catalogued exploits",
        "repository-poc": "Curated repository PoCs",
        "repository-candidate": "Repository PoC candidates",
    }
    populated = {expected.get(kind, "Other PoC artifacts") for kind in kinds}
    if len(populated) < 3:
        pytest.skip(
            f"{MULTI_GROUP} no longer populates three PoC groups in the live corpus: "
            f"kinds {sorted(str(kind) for kind in kinds)}"
        )

    out = await tools.get_vulnerability(MULTI_GROUP, sections=["pocs"], section_limit=50)
    groups = _live_poc_groups(out)

    # Group order is the module's constant, restricted to what this record populates.
    assert [title for title, _ in groups] == [
        title for title in fmt.POC_GROUP_TITLES if title in populated
    ]
    # And every row really carries the kind its heading claims - read off the same
    # rendered line, so this cannot be satisfied by a heading with the wrong rows.
    for title, rows in groups:
        assert rows, f"group {title} rendered no row"
        for row in rows:
            kind = next(kind for kind in expected if f"` {kind} `" in row)
            assert expected[kind] == title, f"{kind} rendered under {title}"
    assert sum(len(rows) for _, rows in groups) == len(items)


async def test_the_live_grouping_preserves_the_apis_order_inside_each_group(tools):
    """The guard's within-group half, on corpus rows rather than a crafted payload."""
    payload = await tools._api.get(f"/api/v1/vulnerabilities/{MULTI_GROUP}")
    out = await tools.get_vulnerability(MULTI_GROUP, sections=["pocs"], section_limit=50)

    rendered = [
        int(re.search(r"` #(\d+) `", row).group(1))
        for _, rows in _live_poc_groups(out)
        for row in rows
    ]
    groups = {
        "exploitdb-exploit": 0,
        "metasploit-exploit": 0,
        "metasploit-auxiliary": 0,
        "repository-poc": 1,
        "repository-candidate": 2,
    }
    order = {public_id: index for index, public_id in enumerate(rendered)}
    for group in set(groups.values()):
        payload_order = [
            item["public_id"]
            for item in payload["pocs"]["items"]
            if groups.get(item.get("catalog_kind"), 3) == group
        ]
        positions = [order[public_id] for public_id in payload_order]
        assert positions == sorted(positions), (
            f"group {group} rendered its rows out of the API's order"
        )


async def test_a_truncated_live_poc_section_says_a_group_may_be_past_the_cut(tools):
    """The API returns this collection catalogued-first, so a small limit shows one
    group of the three this record has - and the page must not let the two headings
    that fell past the cut read as "this CVE has none of those"."""
    out = await tools.get_vulnerability(MULTI_GROUP, sections=["pocs"], section_limit=3)
    groups = _live_poc_groups(out)
    assert [title for title, _ in groups] == ["Catalogued exploits"]
    assert "Repository PoC candidates" not in out
    assert fmt.POC_GROUP_OMISSION_NOTE in out


async def test_the_live_poc_groups_use_the_web_interfaces_nouns(tools):
    """The collision this fixes: `search_vulnerabilities` and the brief now name the
    same populations with the same words, and neither invents a third vocabulary."""
    out = await tools.get_vulnerability(MULTI_GROUP, sections=["pocs"], section_limit=50)
    assert "### Catalogued exploits" in out
    assert "### Curated repository PoCs" in out
    assert "### Repository PoC candidates" in out
    assert fmt.POC_GROUP_RULE in out
    for title in fmt.POC_GROUP_TITLES:
        assert out.count(f"### {title}") <= 1, f"{title} rendered more than once"


async def test_alternate_identifier_resolves(tools):
    out = await tools.get_vulnerability("cve-2025-0282")
    assert "CVE-2025-0282" in out


async def test_alias_scheme_resolves_to_the_canonical_record(tools):
    """A different identifier *scheme*, not just a different case, must resolve.

    The test above only proves case folding: `cve-2025-0282` and `CVE-2025-0282`
    are the same identifier. This asks for the same record by its GHSA alias, which
    is the resolution the corpus actually has to perform, and pins that the answer
    comes back under its canonical CVE identity with the alias disclosed.
    """
    out = await tools.get_vulnerability("GHSA-rf94-f4r9-6gxh")
    assert out.splitlines()[0] == "# Vulnerability ` CVE-2025-0282 `"
    assert "Also known as: ` GHSA-RF94-F4R9-6GXH `" in out


async def test_rejected_cve_still_resolves(tools):
    out = await tools.get_vulnerability("CVE-2023-1015")
    assert "REJECTED" in out.upper()


async def test_withdrawn_record_is_flagged_as_withdrawn(tools):
    """`rejected` and `withdrawn` are separate flags, and only one had real coverage.

    `test_rejected_cve_still_resolves` cannot reach this: its record is
    withdrawn=false, so the WITHDRAWN branch of the status line had never been
    rendered from real data. Asserting the whole line rather than the one word
    keeps a record that merely renders "REJECTED" from passing this test.
    """
    out = await tools.get_vulnerability(WITHDRAWN)
    assert (
        "**Status: REJECTED by its source; WITHDRAWN by its source; "
        "excluded from search results.**"
    ) in out
    assert "GHSA-CHR6-386Q-4M3V" in out, "identifier should come back normalised"


async def test_unknown_cve_raises_not_found(tools):
    with pytest.raises(ApiNotFound):
        await tools.get_vulnerability("CVE-1999-99999")


def rendered_cursor(page: str) -> str:
    """Pull the next_cursor exactly as a model reading the raw output would copy it.

    The cursor is rendered through `inline()`, which pads the code-span body with
    one space at each end, so the copied value carries that padding: a CommonMark
    *renderer* strips it, but a model reads the raw text. Returning the padded form
    is the point - it is the value the round trip actually has to survive.
    """
    return page.split("`")[-2]


async def test_search_pages_with_cursor(tools):
    """Unconditional, like the two tools below it.

    This used to guard the round trip behind `if "next_cursor" in first`, which
    passed either way: a server that stopped emitting a cursor at all - the
    failure that breaks paging - took the branch that asserts nothing.
    """
    first = await tools.search_vulnerabilities(cisa_kev=True, limit=5)
    assert "next_cursor" in first
    second = await tools.search_vulnerabilities(
        cisa_kev=True, limit=5, cursor=rendered_cursor(first)
    )
    assert second != first


async def test_exploit_search_pages_with_cursor(tools):
    first = await tools.search_exploits(limit=5)
    assert "next_cursor" in first
    second = await tools.search_exploits(limit=5, cursor=rendered_cursor(first))
    assert second != first


async def test_code_search_pages_with_cursor(tools):
    first = await tools.search_exploit_code("jndi ldap", limit=3)
    assert "next_cursor" in first
    second = await tools.search_exploit_code("jndi ldap", limit=3, cursor=rendered_cursor(first))
    assert second != first


async def test_cursor_survives_the_padding_it_is_rendered_with(tools):
    """A cursor copied verbatim from the rendered span must page, padding and all.

    The live API answers a whitespace-padded cursor with 422 "invalid cursor
    encoding", so without the handler's strip this round trip is unreachable by
    doing exactly what the output instructs. Both forms must reach the same page.
    """
    first = await tools.search_vulnerabilities(cisa_kev=True, limit=5)
    padded = rendered_cursor(first)
    assert padded != padded.strip(), "expected the rendered span to be padded"
    from_padded = await tools.search_vulnerabilities(cisa_kev=True, limit=5, cursor=padded)
    from_stripped = await tools.search_vulnerabilities(
        cisa_kev=True, limit=5, cursor=padded.strip()
    )
    assert from_padded == from_stripped
    assert from_padded != first


async def test_code_search_finds_jndi(tools):
    out = await tools.search_exploit_code("jndi ldap", limit=3)
    assert "CVE-" in out
    assert "````" in out


async def test_code_search_states_relevance_caveat(tools):
    out = await tools.search_exploit_code("deserialization", limit=2)
    assert "textual relevance" in out.lower()


async def test_unlinked_artifact_has_no_cves(tools):
    """Left pinned deliberately.

    Artifact identity is stable across re-ingest - this UUID resolved before the
    corpus moved and resolves now - and whether an artifact carries linked CVEs is
    a property of the catalog record, not of the stored-analysis join that broke.
    Only the constants that depended on that join were discovered instead.
    """
    out = await tools.get_exploit(UNLINKED)
    assert "no linked" in out.lower()


async def test_absent_analysis_never_reads_as_a_clean_result(tools, corpus):
    """The corpus's common case, and the single most important thing this renders.

    Sampling the live catalog finds the overwhelming majority of artifacts carrying
    no stored analysis at all, so this is not an edge case - it is what a reader
    meets. Both surfaces are checked, because an artifact nobody examined must read
    as unexamined on the catalog line as well as on the detail page, and it is the
    catalog line a reader scans first.

    Asserted against the `Stored analysis` section rather than the whole page on
    purpose: titles and descriptions are corpus prose, and a plugin called
    "CleanTalk" would fail a page-wide search for "clean" while proving nothing.
    """
    subject = corpus.require_unanalysed()

    out = await tools.get_exploit(subject.artifact_id)
    analysis = _section(out, "## Stored analysis")
    assert fmt.NO_ANALYSIS in analysis
    # Nothing in that section may borrow the vocabulary of a review that ran.
    for reassurance in ("clean", "benign", "backdoor review:", "verdict"):
        assert reassurance not in analysis.lower(), (
            f"absent analysis rendered {reassurance!r}"
        )

    page = await tools.search_exploits(limit=_INDEX_PAGE_SIZE, cursor=subject.page_cursor)
    block = _artifact_block(page, subject.artifact_id)
    lowered = block.lower()
    assert "backdoor review" not in lowered, "an unreviewed artifact carried a review flag"
    assert "model-classified" not in lowered


async def test_file_listing_then_read(tools):
    listing = await tools.read_exploit_file(WITH_FILE)
    assert WITH_FILE_PATH in listing
    content = await tools.read_exploit_file(WITH_FILE, path=WITH_FILE_PATH)
    assert "Exploit Title" in content


async def test_token_never_leaks_into_output(tools):
    """Capture the real issued token and prove it never reaches the output.

    Asserting on the literal word "token" would be wrong: PoC source is included
    verbatim in file content and may legitimately contain it.
    """
    issued: list[str] = []
    original = tools._issue_token

    async def spy(artifact_id: str) -> str:
        token = await original(artifact_id)
        issued.append(token)
        return token

    tools._issue_token = spy
    listing = await tools.read_exploit_file(WITH_FILE)
    content = await tools.read_exploit_file(WITH_FILE, path=WITH_FILE_PATH)

    assert len(issued) == 2, "each call must mint its own short-lived token"
    for token in issued:
        assert len(token) > 20
        assert token not in listing
        assert token not in content


async def test_unknown_file_path_is_refused(tools):
    from eip_mcp_v3.errors import ApiError

    with pytest.raises(ApiError):
        await tools.read_exploit_file(WITH_FILE, path="does/not/exist.py")


async def test_statistics_and_trends(tools):
    totals = await tools.get_corpus_statistics()
    assert "Vulnerabilities" in totals
    trends = await tools.get_corpus_statistics(trends="poc_supply")
    assert "coverage" in trends.lower()


# --------------------------------------------------------------------------
# End to end: a real MCP client, over real stdio, against the real corpus.
#
# Every other test in this file calls EipTools directly, which proves the
# handlers but never the protocol layer: tool registration, schema generation,
# the stdio framing, and version negotiation are all skipped. An earlier
# hand-rolled JSON-RPC probe silently negotiated the older 2025-11-25 envelope,
# so the 2026-07-28 path this server actually ships on had never been exercised.
# Driving the installed SDK's client is the only way to find that out.
# --------------------------------------------------------------------------


@asynccontextmanager
async def mcp_session():
    """Spawn the real server and drive it with the SDK's own client.

    Deliberately not a pytest fixture. The stdio transport holds an anyio task
    group, and an async-generator fixture is resumed for cleanup in a different
    task than it was started in, which trips anyio's "exit cancel scope in a
    different task" guard before any assertion runs. Entering and leaving inside
    the test body keeps both ends on one task.
    """
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "eip_mcp_v3"],
        # A bare {"EIP_API_BASE_URL": ...} would strip PATH and the venv from the
        # child, so the interpreter could not import its own dependencies.
        env={**os.environ, "EIP_API_BASE_URL": BASE_URL},
        cwd=str(REPO_ROOT),
    )
    async with Client(stdio_client(params), raise_exceptions=True) as client:
        yield client


async def test_stdio_session_negotiates_the_current_protocol():
    """The negotiated version must be the SDK's current one, not a legacy fallback.

    Pinned to LATEST_PROTOCOL_VERSION rather than a literal: a hard-coded date
    would go stale silently on the next SDK bump, which is the failure mode that
    let the older envelope go unnoticed in the first place. The literal is
    asserted too, so an SDK that quietly moved is visible rather than tautological.
    """
    async with mcp_session() as client:
        assert client.protocol_version == LATEST_PROTOCOL_VERSION
        assert client.protocol_version == "2026-07-28"
        assert client.server_info.name == "eip-research"
        assert client.server_info.version == __version__


async def test_stdio_lists_every_tool_with_schemas():
    async with mcp_session() as client:
        listed = await client.list_tools()
    names = [tool.name for tool in listed.tools]
    assert names == list(TOOL_ORDER)
    by_name = {tool.name: tool for tool in listed.tools}
    for tool in listed.tools:
        assert tool.description, f"{tool.name} advertises no description"
        assert tool.input_schema.get("type") == "object"
        assert tool.output_schema is not None
        assert tool.output_schema["properties"]["schema_version"]["const"] == (
            "eip-mcp-result-v1"
        )
        assert tool.annotations is not None and tool.annotations.read_only_hint is True
    # The schema the model actually receives, not the Python signature behind it.
    assert "identifier" in by_name["get_vulnerability"].input_schema["required"]


async def test_stdio_readiness_returns_the_live_checkpoint(tools):
    """The tool result must carry this corpus's real checkpoint, not a canned one."""
    async with mcp_session() as client:
        result = await client.call_tool("get_corpus_readiness", {})
    assert result.is_error in (False, None)
    rendered = result.content[0].text
    assert "EIP corpus readiness" in rendered
    assert "ready" in rendered.lower()

    # Tie the protocol result to the API's own answer, so a stub could not pass.
    live = await tools._api.get("/health/ready")
    assert live["source_checkpoint_sha256"] in rendered
    assert live["read_model_version"] in rendered
    assert result.structured_content["kind"] == "corpus_readiness"
    assert result.structured_content["data"]["source_checkpoint_sha256"] == (
        live["source_checkpoint_sha256"]
    )
    assert live["api_policy_revision"] in rendered


async def test_stdio_code_search_returns_real_corpus_matches():
    async with mcp_session() as client:
        result = await client.call_tool(
            "search_exploit_code", {"query": "jndi ldap", "limit": 3}
        )
    assert result.is_error in (False, None)
    rendered = result.content[0].text
    assert "PoC code search" in rendered
    assert "total match(es)" in rendered
    assert "textual relevance" in rendered.lower()
    assert "artifact" in rendered
    assert "````" in rendered, "expected fenced snippet bodies"


async def test_stdio_surfaces_prompts_and_the_usage_guide():
    async with mcp_session() as client:
        listed = await client.list_prompts()
        resources = await client.list_resources()
        guide = await client.read_resource("eip://research/usage-guide")
    assert {prompt.name for prompt in listed.prompts} == {
        "triage-cve",
        "hunt-technique",
        "screen-exploit-safety",
        "corpus-report",
    }
    uris = [str(resource.uri) for resource in resources.resources]
    assert "eip://research/usage-guide" in uris
    assert "EIP" in guide.contents[0].text


async def test_stdio_reports_a_bad_argument_without_killing_the_session():
    """A rejected call must come back as a tool error, and the session must survive."""
    async with mcp_session() as client:
        result = await client.call_tool("get_vulnerability", {"identifier": "not a cve"})
        assert result.is_error is True

        followup = await client.call_tool("get_corpus_readiness", {})
    assert followup.is_error in (False, None)
    assert "readiness" in followup.content[0].text.lower()


# --------------------------------------------------------------------------
# States the brief does not name, found by scanning the live corpus.
# --------------------------------------------------------------------------


async def test_every_documented_section_renders(tools):
    """Every section must render against real payloads, not just the ones in fixtures."""
    for section in fmt.VULN_SECTIONS:
        out = await tools.get_vulnerability(
            "CVE-2021-44228", sections=[section], section_limit=3
        )
        assert fmt._SECTION_TITLES[section] in out, f"{section} rendered no heading"


async def test_writeups_section_renders_where_the_corpus_has_them(tools):
    """Log4Shell has zero writeups, so the brief never exercised a populated one."""
    out = await tools.get_vulnerability(WITH_WRITEUPS, sections=["writeups"], section_limit=5)
    assert "Writeups - 3 total" in out


@pytest.mark.parametrize("verdict", fmt.DOCUMENTED_VERDICTS)
async def test_a_catalog_line_labels_a_stored_verdict_by_what_it_says(tools, corpus, verdict):
    """Fail-closed, on the surface a reader scans first.

    Only an exact `no_backdoor_observed` earns the quiet label, so that "reviewed
    and benign" stays distinguishable from "never reviewed". Every other documented
    verdict - including `undetermined`, the one that matters most, where the
    reviewer looked and could not tell - takes the loud one and must never render
    like an all-clear. The verdict is verbatim in both branches; only the label
    moves.
    """
    subject = corpus.require_verdict(verdict)
    page = await tools.search_exploits(limit=_INDEX_PAGE_SIZE, cursor=subject.page_cursor)
    block = _artifact_block(page, subject.artifact_id)

    if verdict == fmt.BENIGN_VERDICT:
        assert f"backdoor review: ` {verdict} `" in block
        assert "BACKDOOR REVIEW" not in block
    else:
        assert f"BACKDOOR REVIEW: ` {verdict} `" in block
        assert f"backdoor review: ` {verdict} `" not in block
    assert fmt.UNRECOGNISED_VERDICT not in block, "a documented verdict was flagged unknown"


@pytest.mark.parametrize("verdict", fmt.DOCUMENTED_VERDICTS)
async def test_a_detail_page_labels_a_stored_verdict_and_names_the_model(
    tools, corpus, verdict
):
    """The same rule on the detail page, plus the attribution that page owes.

    A verdict is the model's claim and never EIP's, including - especially - an
    all-clear, so the page has to say whose claim it is and which model made it.
    The model name is taken from the API payload for this artifact rather than
    pinned, so the assertion survives a pipeline changing models.
    """
    subject = corpus.require_verdict(verdict)
    out = await tools.get_exploit(subject.artifact_id)
    analysis = _section(out, "## Stored analysis")

    if verdict == fmt.BENIGN_VERDICT:
        assert f"Model verdict: ` {verdict} `" in analysis
        assert "MODEL VERDICT" not in analysis
    else:
        assert f"MODEL VERDICT: ` {verdict} `" in analysis
        assert f"Model verdict: ` {verdict} `" not in analysis
    assert fmt.UNRECOGNISED_VERDICT not in analysis

    assert fmt.ANALYSIS_LABEL in analysis
    assert "not an EIP judgment" in analysis
    if subject.model:
        assert f"Model: ` {subject.model} `" in analysis
    else:
        assert "Model: not recorded" in analysis


async def test_an_undocumented_verdict_is_flagged_as_unrecognised(tools, corpus):
    """The fail-open case the renderer's exact-match rule exists to catch.

    A verdict outside the documented vocabulary is one this renderer cannot reason
    about, so it takes the loud label *and* says so. Nothing in the live corpus has
    ever carried one, which is why this skips rather than passes: an assertion that
    never runs against a real value should say it never ran.
    """
    subject = corpus.require_unrecognised()
    out = await tools.get_exploit(subject.artifact_id)
    analysis = _section(out, "## Stored analysis")
    assert f"MODEL VERDICT - {fmt.UNRECOGNISED_VERDICT}: ` {subject.verdict} `" in analysis


async def test_non_viewable_file_is_listed_as_such_and_cannot_be_read(tools):
    """The read-only boundary, on a real binary: listed, labelled, and refused.

    This is the path that would otherwise tempt a caller toward poc-download,
    which this server refuses to expose at all.
    """
    listing = await tools.read_exploit_file(NON_VIEWABLE)
    assert NON_VIEWABLE_FILE in listing
    # The flag, not a cause this renderer invented: the API's gate is size *and*
    # extension, so "binary or too large" was wrong for every file refused on its
    # extension alone. The policy is stated once, in the header.
    entry = next(line for line in listing.splitlines() if NON_VIEWABLE_FILE in line)
    assert entry.endswith("not viewable")
    assert "text allowlist" in listing

    from eip_mcp_v3.errors import ApiError

    with pytest.raises(ApiError, match="download-only"):
        await tools.read_exploit_file(NON_VIEWABLE, path=NON_VIEWABLE_FILE)


async def test_empty_searches_say_so_rather_than_failing(tools):
    nonsense = "zzzqqqxxnotathinginthecorpus"
    vulns = await tools.search_vulnerabilities(query=nonsense, limit=5)
    assert "No matching vulnerabilities." in vulns
    pocs = await tools.search_exploits(query=nonsense, limit=5)
    assert "No matching artifacts." in pocs


async def test_zero_match_code_search_returns_an_empty_page(tools):
    """A code search that matches nothing renders an empty page, not an error.

    This was xfail: the API answered 500 for a zero-match query, so the caller was
    told the service was degraded when the truth was "no matches" - the very
    distinction get_corpus_readiness exists to draw. Upstream now answers 200 and
    the marker is gone.

    Asserting the rendered shape rather than `"0" in out`, which the page satisfies
    incidentally in half a dozen places and would pass against almost any output.
    """
    out = await tools.search_exploit_code("zzzqqqxxnotathinginthecorpus", limit=5)
    assert out.startswith("# PoC code search - 0 total match(es), 0 on this page")
    # A zero-result page still carries the ordering caveat and the untrusted-content
    # note: they describe the tool, not the rows, and a reader who sees them only on
    # populated pages learns the wrong lesson about when they apply.
    assert "textual relevance" in out
    assert UNTRUSTED_NOTE in out


async def test_large_file_manifest_discloses_its_own_ceiling(tools):
    """A truncated manifest a reader believes is complete is worse than a short one.

    The 200-file ceiling is a renderer constant that no fixture reaches; this real
    artifact holds 499 paths, so the disclosure line is exercised rather than assumed.
    """
    listing = await tools.read_exploit_file(BIG_MANIFEST)
    assert "Showing the first 200 of 499; 299 omitted." in listing
    assert len(listing) < 40_000


@pytest.mark.parametrize(("artifact_id", "path"), (CAPPED, CAPPED_WIDE_FENCE))
async def test_oversized_file_read_is_capped_with_the_fence_reclosed(
    tools, artifact_id, path
):
    """cap() on real data: the ceiling holds and the cut does not leak a raw fence.

    Every earlier live call fitted well inside the ceiling, so this backstop was
    fixture-only. These files are 72 KB and 906 KB, so the cut lands inside the
    fenced body - which is the case that matters, because an unterminated fence
    would let the truncation marker be read as more untrusted source rather than
    as a system message. The text and structured source payload share one complete
    serialized-result budget, so neither channel alone is required to fill it.
    """
    out = await tools.read_exploit_file(artifact_id, path=path)
    wire = call_tool_result("read_exploit_file", out).model_dump_json()
    assert len(wire) <= 40_000
    assert out.structured.truncated is True
    # Reading one file already *is* the narrowest form of the request, so there is
    # no parameter to name: the notice points at the ceiling itself, which is the
    # one thing that can change the outcome.
    assert out.endswith(
        f"…[truncated at {len(out)} chars; raise EIP_MCP_MAX_OUTPUT_CHARS]"
    )

    body = out.rsplit("\n\n…[truncated", 1)[0]
    closing = body.rsplit("\n", 1)[-1]
    assert set(closing) == {"`"} and len(closing) >= 3, (
        f"expected the cut fence to be re-closed, got {closing!r}"
    )


# --------------------------------------------------------------------------
# Audit fixes, against real data. Fixtures cannot prove any of these: the Nuclei
# rendering is a claim about what the live API returns per template, the count
# reconciliation is a claim about two live surfaces agreeing, and the identifier
# and transport behaviour are claims about what happens instead of a round trip.
# --------------------------------------------------------------------------

# One template per shape, found by scanning the live corpus: the CVE-named template
# carries no reconnaissance and the product-specific ones do.
NUCLEI_WITH_RECON = "apache-druid-log4j-rce"
NUCLEI_WITHOUT_RECON = "CVE-2021-44228"


def _template_block(out: str, template_id: str) -> str:
    """The bullet and sub-bullets of one template, cut at the next top-level bullet."""
    marker = f"- ` {template_id} `"
    assert marker in out, f"{template_id} did not render"
    after = out.split(marker, 1)[1]
    return after.split("\n- ", 1)[0]


async def test_nuclei_templates_render_what_a_researcher_would_act_on(tools):
    """V-06: the section rendered `template_id` and `name` and dropped ten fields.

    Asserted against live template data rather than a fixture, because the claim is
    about what the API actually carries per template - description, severity,
    authors, tags, impact, remediation, the CVSS vector, CWEs, a CPE, references and
    provenance - every one of which arrived and was thrown away.
    """
    out = await tools.get_vulnerability(
        "CVE-2021-44228", sections=["nuclei"], section_limit=10
    )
    block = _template_block(out, NUCLEI_WITHOUT_RECON)
    for fragment in (
        "template severity ",
        "  - description: ",
        "  - impact: ",
        "  - remediation: ",
        "  - tags: ",
        "  - template authors: ",
        "  - classification: ",
        "CVSS ",
        "vector ",
        "CWE ",
        "CPE ",
        "  - references: ",
        "source ` nuclei `",
        "provider ` ProjectDiscovery `",
    ):
        assert fragment in block, f"template no longer renders {fragment!r}"


async def test_nuclei_reconnaissance_renders_only_where_the_corpus_has_it(tools):
    """Most templates carry none, and an empty label says only that we looked."""
    out = await tools.get_vulnerability(
        "CVE-2021-44228", sections=["nuclei"], section_limit=10
    )
    assert "  - recon: " in _template_block(out, NUCLEI_WITH_RECON)
    assert "  - recon: " not in _template_block(out, NUCLEI_WITHOUT_RECON)


async def test_a_nuclei_url_stays_inert_on_a_live_page(tools):
    """References are corpus URLs. They are disclosed, and they are never links."""
    out = await tools.get_vulnerability("CVE-2021-44228", sections=["nuclei"], section_limit=3)
    assert "https://" in out
    for construct in ("](http", "<http"):
        assert construct not in out


def _int(rendered: str) -> int:
    """Undo `_number`'s digit grouping, so a rendered count can be compared."""
    return int(rendered.replace(",", ""))


def _collection_total(page: str, name: str) -> int:
    """The `- \\`pocs\\`: N` figure from a rendered brief's collection summary."""
    line = next(line for line in page.splitlines() if line.startswith(f"- `{name}`:"))
    return _int(line.split(": ", 1)[1].split(" ")[0])


_SEARCH_COUNTS = re.compile(
    rf"^([\d,]+) {re.escape(fmt.POC_COUNT_LABEL[:-1])}s?"
    rf"(?: \({fmt.POC_PART_PREFIX} (?P<parts>[^)]*)\))?",
    re.MULTILINE,
)


def _search_counts(block: str) -> tuple[int, dict[str, int]]:
    """Read a rendered search result's PoC total and its nested parts back out."""
    head = _SEARCH_COUNTS.search(block)
    assert head is not None, block
    parts = {
        noun: _int(number)
        for fragment in (head.group("parts") or "").split(", ")
        if fragment
        for number, noun in [fragment.split(" ", 1)]
    }
    return _int(head.group(1)), parts


def _singular(plural: str, count: int) -> str:
    """The noun `_quantity` prints for this count, so a lookup can match it."""
    return plural[:-1] if count == 1 and plural.endswith("s") else plural


def _brief_counts(page: str) -> dict[str, int]:
    """Read a rendered brief's `- Counts:` line back out as noun -> number.

    Scoped to the exploitation context so the line found is the renderer's, not a
    sentence inside quoted corpus text. Read as a mapping rather than searched for as
    a substring: two populations rendered under one noun collapse to one entry here,
    and the count they collapse onto stops matching the field it was supposed to
    name - which a substring test cannot see, because the wrong label still prints
    beside the right number.
    """
    context = page.split("## Exploitation context", 1)[1].split("\n## ", 1)[0]
    line = next(line for line in context.splitlines() if line.startswith("- Counts: "))
    return {
        noun: _int(number)
        for fragment in line.split(": ", 1)[1].split(", ")
        for number, noun in [fragment.split(" ", 1)]
    }


async def test_search_and_detail_counts_reconcile_on_live_data(tools):
    """V-02, and the drift that broke its fix.

    The fix for V-02 read `poc_count` as the curated subset and printed the candidate
    count beside it, so the two summed to the detail's `pocs` total. eip-loader-v3
    `f9e1cda` widened the `poc_count` FILTER to all three PoC sources: it became the
    collection itself, and the old assertion `curated + candidates == total` started
    double-counting the candidates on live data - 8 + 409 against a total of 417 on
    CVE-2021-44228, which is 409 too many.

    So the relationship asserted here is re-derived rather than adjusted: the search
    page's PoC number *is* the detail's collection total, and the counts beside it
    are parts inside it. Both halves are read off live output.
    """
    # The audit's own query, so this reads against the same two rows it reported.
    search = await tools.search_vulnerabilities(
        query="log4j", cisa_kev=True, sort="epss", limit=2
    )
    detail = await tools.get_vulnerability("CVE-2021-44228", sections=[])

    heading = "## Vulnerability ` CVE-2021-44228 `"
    assert heading in search, search
    total, parts = _search_counts(search.split(heading, 1)[1].split("\n## ", 1)[0])
    collection = _collection_total(detail, "pocs")

    assert total == collection, (
        f"the search page's PoC number is no longer the `pocs` total: "
        f"{total} vs {collection}"
    )
    # Parts, not siblings. Each is inside the total, and none of them may be the
    # total - the shape that let a reader add a collection to its own subset.
    assert parts, "the breakdown vanished from the page"
    for noun, value in parts.items():
        assert value <= total, f"{noun} ({value}) exceeds the total it sits inside"
    assert sum(parts.values()) <= total, f"the parts over-count the total: {parts}"
    assert not re.search(r"\d+ PoCs\b", search), "the ambiguous label is back"
    assert "curated PoCs" not in search, "the label that named the wrong number is back"


# The CVE whose whole PoC collection is one repository unit admitted to the catalog in
# its own right. It is the case that used to be unprintable: with only
# `catalogued_exploit_count` and `repository_candidate_count` the brief read
# "0 catalogued exploits, 0 repository candidates" above "`pocs`: 1" and accounted for
# the 1 nowhere. `curated_repository_poc_count` is the field that holds it, so this CVE
# is now the sharpest check that the brief prints all three.
ADMITTED_UNIT_ONLY = "CVE-2026-28409"


async def test_the_brief_reconciles_its_own_counts_on_live_data(tools, api):
    """V-03: `0 catalogued exploits, 0 repository candidates` beside `pocs`: 1.

    Nothing there was false, and nothing there was readable either. The API now
    carries the population that held the 1, and the brief prints it - so the numbers
    reconcile on the page instead of in a note explaining why they cannot.
    """
    brief = await tools.get_vulnerability(ADMITTED_UNIT_ONLY, sections=[])
    payload = await api.get(f"/api/v1/vulnerabilities/{ADMITTED_UNIT_ONLY}")
    context = brief.split("## Exploitation context", 1)[1].split("\n## ", 1)[0]
    exploitation = payload["exploitation"]

    # The premise: this CVE's collection is made entirely of the population the two
    # old counts could not name. If the corpus moves off that shape the test is
    # measuring nothing and should be pointed at another CVE rather than pass quietly.
    assert exploitation["curated_repository_poc_count"] > 0, (
        f"{ADMITTED_UNIT_ONLY} no longer holds an admitted repository unit"
    )
    assert exploitation["catalogued_exploit_count"] == 0

    counts = re.search(r"- Counts: (.+)", context)
    assert counts is not None, context
    for label, key in (
        (fmt.CATALOGUED_COUNT_LABEL, "catalogued_exploit_count"),
        (fmt.CURATED_COUNT_LABEL, "curated_repository_poc_count"),
        (fmt.CANDIDATE_COUNT_LABEL, "repository_candidate_count"),
    ):
        value = exploitation[key]
        assert f"{value} {_singular(label, value)}" in counts.group(1), (
            f"{key} is not on the page as {label!r}: {counts.group(1)}"
        )
    # The gap the old note existed to excuse, closed arithmetically on the page.
    assert sum(exploitation[key] for key in fmt._POC_POPULATION_KEYS) == _collection_total(
        brief, "pocs"
    )
    # The ninety words that *define* the three populations are read once, from the
    # tool description and the usage guide, and are asserted there by
    # tests/test_server.py - printing them on every brief was the per-call repetition
    # the page-level note replaced.
    assert fmt.EXPLOITATION_COUNT_NOTE in context
    assert fmt.EXPLOITATION_COUNT_RULE not in brief
    assert "usage-guide" in context, "the definitions are unreachable from the page"


# How many CVEs the drift sweep below covers. One CVE cannot catch a label that
# drifted: on CVE-2021-44228 the catalogued and candidate counts happen to reach the
# total, so a page that had silently dropped the third population would still add up
# there. The sweep is what makes the relationship a property of the corpus rather
# than of a lucky row.
_COUNT_SAMPLE = 12

# The other half of the sample, and the half that was missing. Under the default
# `published` sort this query returned the twelve newest RCE records, and a CVE
# published this week has no PoCs yet: every row came back with `poc_count` and all
# three population counts at zero, so every `if value:` guard in the sweep stayed
# shut and no label was ever compared to a field. Setting `CATALOGUED_COUNT_LABEL`
# to `CANDIDATE_COUNT_LABEL` in the renderer - the exact mislabel this test exists to
# catch - left it passing.
#
# Ordered by EPSS the same query returns the corpus's most-exploited RCEs, which are
# the records that actually carry PoCs. Observed 2026-08-03: `poc_count`,
# `catalogued_exploit_count` and `repository_candidate_count` nonzero on all twelve
# rows, and `curated_repository_poc_count` - the rare one, zero on Log4Shell and on
# most of the corpus - held by CVE-2025-3248 (28 = 3 + 1 + 24) and CVE-2018-11776
# (19 = 4 + 1 + 14). Rows are discovered by the query rather than pinned, so the
# sweep follows the corpus; what is not left to chance is whether they exercise
# anything, which `exercised` below asserts. If the corpus moves off this shape that
# assertion fails and names the part that went uncovered, and the sample is repointed
# at records that carry it rather than left passing on nothing.
_COUNT_SAMPLE_SORT = "epss"


async def test_rendered_counts_are_the_api_fields_they_claim_to_be(tools, api):
    """The drift-catcher: every rendered count, against the field it came from.

    This is the assertion whose absence let "curated PoCs" survive the change that
    falsified it. Every count on this server's pages had a correct *value* - the
    renderer printed `poc_count` faithfully - and one of them had a noun describing a
    population the API had stopped returning under that field. Reading the page could
    never detect that; only comparing the number to its source can.

    So each rendered count is matched to the API field it is rendered from, and the
    partition the labels assert is checked against the collection they claim to
    partition. A future change of meaning fails here rather than printing a false
    sentence.

    A comparison only happens where there is a number to compare, so the sample has
    to supply one for every part - see `_COUNT_SAMPLE_SORT` for the sweep that did
    not, and `exercised` for the assertion that now says so out loud.
    """
    page = await api.get(
        "/api/v1/vulnerabilities",
        {"q": "rce", "sort": _COUNT_SAMPLE_SORT, "limit": _COUNT_SAMPLE},
    )
    items = page["items"]
    assert len(items) >= 2, f"the corpus returned too few rows to sweep: {len(items)}"

    search = await tools.search_vulnerabilities(
        query="rce", sort=_COUNT_SAMPLE_SORT, limit=_COUNT_SAMPLE
    )
    partitioned = 0
    # How many rows put a nonzero number in front of each comparison below. A part
    # that stays at zero across the whole sample is a part this sweep did not test,
    # and a sweep that tests nothing passes for the same reason a correct one does.
    exercised = dict.fromkeys(("poc_count", *fmt._POC_POPULATION_KEYS), 0)
    for item in items:
        identifier = item["identifier"]
        heading = f"## Vulnerability ` {identifier} `"
        assert heading in search, f"{identifier} is missing from the rendered page"
        total, parts = _search_counts(search.split(heading, 1)[1].split("\n## ", 1)[0])

        # The search page: the head number is `poc_count`, and each nested number is
        # the field whose label it carries. Nothing here is derived.
        assert total == item["poc_count"], f"{identifier}: head number is not `poc_count`"
        exercised["poc_count"] += bool(item["poc_count"])
        for label, key in (
            (fmt.CATALOGUED_COUNT_LABEL, "catalogued_exploit_count"),
            (fmt.CANDIDATE_COUNT_LABEL, "repository_candidate_count"),
        ):
            value = item[key]
            if value:
                exercised[key] += 1
                assert parts.get(_singular(label, value)) == value, (
                    f"{identifier}: {label!r} does not render {key}"
                )

        # The detail: `poc_count` and the `pocs` collection are the same population,
        # and the three exploitation counts partition it. Sequential by design - one
        # awaited request at a time, never two in flight.
        detail = await tools.get_vulnerability(identifier, sections=[])
        payload = await api.get(f"/api/v1/vulnerabilities/{identifier}")
        collection = payload["pocs"]["total"]
        assert item["poc_count"] == collection, (
            f"{identifier}: `poc_count` {item['poc_count']} is not `pocs.total` {collection}"
        )
        exploitation = payload["exploitation"]
        assert sum(exploitation[key] for key in fmt._POC_POPULATION_KEYS) == collection, (
            f"{identifier}: the three PoC counts no longer partition `pocs`: "
            f"{ {key: exploitation[key] for key in fmt._POC_POPULATION_KEYS} } vs {collection}"
        )
        # The brief prints all three populations, so it is the only page where the
        # third one's label can be checked at all: `SearchItem` does not carry
        # `curated_repository_poc_count`, and the search block above therefore cannot
        # catch it drifting. Every one of the three is read back off the rendered
        # line and compared to the field it claims.
        brief_counts = _brief_counts(detail)
        for label, key in (
            (fmt.CATALOGUED_COUNT_LABEL, "catalogued_exploit_count"),
            (fmt.CURATED_COUNT_LABEL, "curated_repository_poc_count"),
            (fmt.CANDIDATE_COUNT_LABEL, "repository_candidate_count"),
        ):
            value = exploitation[key]
            assert brief_counts.get(_singular(label, value)) == value, (
                f"{identifier}: {label!r} does not render {key} ({value}): {brief_counts}"
            )
        # Counted here rather than beside the search block, because here is where a
        # nonzero curated count is the difference between checking that label and
        # not checking it.
        exercised["curated_repository_poc_count"] += bool(
            exploitation["curated_repository_poc_count"]
        )

        if collection:
            assert _collection_total(detail, "pocs") == collection
            partitioned += 1

    assert partitioned, "no sampled CVE had a PoC collection; the sweep proved nothing"
    unexercised = [key for key, rows in exercised.items() if not rows]
    assert not unexercised, (
        f"the sample left {', '.join(unexercised)} at zero on all {len(items)} rows, so "
        f"nothing above compared a rendered count to it and this sweep would pass with "
        f"that label pointed at any field at all. Repoint the sample at records that "
        f"carry it - see `_COUNT_SAMPLE_SORT`. Rows exercised: {exercised}"
    )
    # Three populations, three nouns. Two labels collapsing onto one renders "3
    # catalogued exploits, 1 catalogued exploit" - a grammatical line that names one
    # population twice and another never, and where both counts happen to coincide no
    # comparison above can see it, because the expected value moves with the label.
    labels = (fmt.CATALOGUED_COUNT_LABEL, fmt.CURATED_COUNT_LABEL, fmt.CANDIDATE_COUNT_LABEL)
    assert len(set(labels)) == len(labels), f"two PoC populations share one label: {labels}"


# --------------------------------------------------------------------------
# V-10 and V-11: the two rendering changes, checked against the corpus rather than
# against a fixture. Both are about shapes the live payload actually carries - the
# long CVE 5.0 version list, and the same source record cited by dozens of claims -
# so a fixture-only check would be measuring the fixture.
# --------------------------------------------------------------------------

# The record the audit quoted: seventy affected versions on one Cisco FMC entry,
# which the flattener rendered as sixty-eight repetitions of `status=affected` cut
# mid-token before the versions a reader came for.
LONG_VERSION_LIST = "CVE-2026-20131"


async def test_affected_versions_render_as_versions_on_live_data(tools):
    out = await tools.get_vulnerability(LONG_VERSION_LIST, sections=["affected"])
    line = next(line for line in out.splitlines() if "` versions `" in line)
    assert "status=affected" not in line, "the version structure is back"
    assert "7.0.0" in line and "7.0.1" in line, "the versions a researcher asked for"
    assert re.search(r"…and [\d,]+ more version\(s\)", line), "the bound is undisclosed"
    assert "…truncated" not in line, "a bounded list must not also be a cut one"


_LIVE_TABLE_ROW = re.compile(r"^- (\[S\d+\]) = (`+) (.*?) \2$")
_LIVE_HOISTED = re.compile(r"pointer (\[S\d+\])(?: (`+) (.*?) \2)?")
_LIVE_WHOLE = re.compile(r"pointer (`+) (.*?) \1")


def _live_pointers(out: str) -> list[str]:
    """Every pointer on a rendered page, rebuilt from what the page rendered."""
    records = {
        row.group(1): row.group(3)
        for line in out.splitlines()
        if (row := _LIVE_TABLE_ROW.match(line))
    }
    found = []
    for line in out.splitlines():
        if _LIVE_TABLE_ROW.match(line):
            continue
        if hoisted := _LIVE_HOISTED.search(line):
            found.append(records[hoisted.group(1)] + (hoisted.group(3) or ""))
        elif whole := _LIVE_WHOLE.search(line):
            found.append(whole.group(2))
    return found


async def test_every_pointer_on_a_live_brief_is_reconstructible(tools):
    """V-11: hoisting a record must move a pointer, never shorten or drop one.

    Checked against the API payload the page was rendered from, so the assertion is
    that a reader following the footnote's own rule recovers the string the corpus
    holds - not merely that the page is self-consistent.
    """
    out = await tools.get_vulnerability("CVE-2021-44228", sections=["references"])
    assert fmt._SOURCE_SECTION in out, "this brief no longer hoists; the test is measuring nothing"
    payload = await tools._api.get("/api/v1/vulnerabilities/CVE-2021-44228")
    expected = {
        item["pointer"] for item in payload["references"]["items"][:10] if item.get("pointer")
    }
    rebuilt = set(_live_pointers(out))
    assert expected <= rebuilt, sorted(expected - rebuilt)
    assert all(p.startswith("fixed-source-record:") for p in rebuilt), sorted(rebuilt)
    assert "\x00" not in out, "a substitution placeholder reached the client"


async def test_hoisting_a_live_brief_never_makes_it_larger(tools):
    """The footnote is an optimisation, so it may never be the more expensive branch."""
    for identifier, sections in (
        ("CVE-2021-44228", None),
        ("CVE-2021-44228", ["references"]),
        (ADMITTED_UNIT_ONLY, None),
    ):
        payload = await tools._api.get(f"/api/v1/vulnerabilities/{identifier}")
        hoisted = fmt.format_vulnerability(payload, sections=sections or (), section_limit=10)
        # max_chars=1 forces the fallback the registry uses when a page would be cut,
        # which renders the same page with every pointer inline.
        inline_only = fmt.format_vulnerability(
            payload, sections=sections or (), section_limit=10, max_chars=1
        )
        assert fmt._SOURCE_SECTION not in inline_only
        assert len(hoisted) <= len(inline_only), identifier
        assert _live_pointers(hoisted) == _live_pointers(inline_only), identifier


async def test_the_pagination_instruction_names_limit_on_a_live_page(tools):
    """V-09: a cursor is refused when `limit` changes, and the page never said so."""
    page = await tools.search_vulnerabilities(cisa_kev=True, limit=5)
    instruction = next(line for line in page.splitlines() if "verbatim as `cursor`" in line)
    assert "`limit`" in instruction
    assert "filter" in instruction


async def test_a_cursor_replayed_at_a_different_limit_is_still_refused(tools):
    """The instruction has to describe the API's real rule, so pin the rule too."""
    first = await tools.search_vulnerabilities(cisa_kev=True, limit=5)
    with pytest.raises(ApiError, match="cursor"):
        await tools.search_vulnerabilities(
            cisa_kev=True, limit=4, cursor=rendered_cursor(first)
        )


@pytest.mark.parametrize(
    "identifier", ["CVE-20211-44228", "CVE-XX-YY", "CVE-2021", "CVE-2021-44228x"]
)
async def test_a_malformed_cve_is_told_apart_from_a_missing_one(tools, identifier):
    """V-04: every one of these came back as `vulnerability not found` from the API."""
    with pytest.raises(ValueError) as raised:
        await tools.get_vulnerability(identifier)
    assert not isinstance(raised.value, ApiNotFound)
    assert "malformed" in str(raised.value)


async def test_a_well_formed_but_absent_cve_is_still_a_not_found(tools):
    """The distinction is only worth anything if the other answer still happens."""
    with pytest.raises(ApiNotFound):
        await tools.get_vulnerability("CVE-1999-99999")


async def test_an_unreachable_api_names_the_endpoint_it_tried():
    """V-01: `All connection attempts failed` named neither URL nor address family.

    A dead port on the same host as the live API: the failure is real, and the only
    thing under test is whether the error says where it happened.
    """
    dead = Settings.from_env({"EIP_API_BASE_URL": "http://127.0.0.1:59999"})
    client = EipApiClient(dead)
    try:
        with pytest.raises(ApiUnavailable) as raised:
            await EipTools(client, dead).get_corpus_readiness()
    finally:
        await client.aclose()
    assert "http://127.0.0.1:59999" in str(raised.value)


async def test_stdio_reports_a_bad_enum_in_this_servers_own_words():
    """V-10: `source="bogus"` returned the Pydantic taxonomy and a pinned SDK URL."""
    async with mcp_session() as client:
        result = await client.call_tool("search_exploits", {"source": "bogus"})
        assert result.is_error is True
        message = result.content[0].text
    assert "source must be one of: exploitdb, metasploit, repository-inventory" in message
    for internal in ("errors.pydantic.dev", "validation error", "literal_error", "[type="):
        assert internal not in message


# --------------------------------------------------------------------------
# Streamable HTTP transport.
#
# A flag that parses is not a transport that serves. Everything below runs the real
# console entrypoint as a separate process, over a real loopback socket, and drives
# it with the SDK's own HTTP client - the same standard a client in the wild would
# hold it to. They live here rather than in the hermetic suite because a tool call
# has to reach the real API to return anything; `tests/test_entrypoint.py` covers
# the argument wiring without a socket.
# --------------------------------------------------------------------------

HTTP_PATH = "/mcp"


def _free_loopback_port() -> int:
    """Claim a port from the kernel, then release it for the server to bind.

    There is a window between the close and the child's bind. Nothing else on a
    test host is racing for ephemeral ports hard enough to matter, and the
    alternative - a hard-coded port - collides with whatever the developer is
    already running, which is the failure that actually happens.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _await_listener(process: subprocess.Popen, port: int, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = process.stderr.read().decode(errors="replace") if process.stderr else ""
            raise AssertionError(
                f"server exited with status {process.returncode} before listening:\n{stderr}"
            )
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"server never listened on 127.0.0.1:{port}")


@asynccontextmanager
async def http_server(*, allowed_hosts: str | None = None):
    """Run the real entrypoint over HTTP and yield its endpoint URL.

    The allowlist defaults to the exact `host:port` the client's Host header will
    carry, not to a `:*` wildcard: a wildcard would still pass if the configured
    list were being ignored, and proving the configured list is what gets matched
    is the point of the exercise.
    """
    port = _free_loopback_port()
    env = {
        **os.environ,
        "EIP_API_BASE_URL": BASE_URL,
        "EIP_MCP_ALLOWED_HOSTS": (
            f"127.0.0.1:{port}" if allowed_hosts is None else allowed_hosts
        ),
    }
    env.pop("EIP_MCP_ALLOWED_ORIGINS", None)
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "eip_mcp_v3",
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--path",
            HTTP_PATH,
        ],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        # Blocking, deliberately: the child is not listening yet, so there is
        # nothing for this event loop to interleave with.
        await asyncio.to_thread(_await_listener, process, port)
        yield f"http://127.0.0.1:{port}{HTTP_PATH}"
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            process.kill()
            process.wait(timeout=10)
        if process.stderr is not None:
            process.stderr.close()


async def test_http_session_negotiates_the_current_protocol():
    async with http_server() as url:
        async with Client(streamable_http_client(url), raise_exceptions=True) as client:
            assert client.protocol_version == LATEST_PROTOCOL_VERSION
            assert client.server_info.name == "eip-research"
            assert client.server_info.version == __version__


async def test_http_lists_every_tool():
    """The same tool surface over HTTP as over stdio, in the same order."""
    async with http_server() as url:
        async with Client(streamable_http_client(url), raise_exceptions=True) as client:
            listed = await client.list_tools()
    names = [tool.name for tool in listed.tools]
    assert names == list(TOOL_ORDER)
    for tool in listed.tools:
        assert tool.annotations is not None and tool.annotations.read_only_hint is True


async def test_http_call_tool_returns_the_live_checkpoint(tools):
    """A real tool call over HTTP, tied to the API's own answer so a stub cannot pass."""
    async with http_server() as url:
        async with Client(streamable_http_client(url), raise_exceptions=True) as client:
            result = await client.call_tool("get_corpus_readiness", {})
    assert result.is_error in (False, None)
    rendered = result.content[0].text
    assert "EIP corpus readiness" in rendered

    live = await tools._api.get("/health/ready")
    assert live["source_checkpoint_sha256"] in rendered
    assert live["read_model_version"] in rendered
    assert result.structured_content["kind"] == "corpus_readiness"
    assert result.structured_content["data"]["source_checkpoint_sha256"] == (
        live["source_checkpoint_sha256"]
    )


async def test_http_survives_a_restart_between_calls():
    """Stateless means a second process answers a client that never re-initialised.

    Two independent servers on two ports, each driven to a completed tool call:
    what this actually shows is that nothing is being kept between requests, which
    is what lets a restart mid-conversation cost the caller nothing.
    """
    for _ in range(2):
        async with http_server() as url:
            async with Client(streamable_http_client(url), raise_exceptions=True) as client:
                result = await client.call_tool("get_corpus_readiness", {})
        assert result.is_error in (False, None)


async def test_http_rejects_a_host_header_outside_the_allowlist():
    """The allowlist is enforced, not merely constructed.

    Behind a proxy the Host header is attacker-choosable, and this middleware is
    the only thing that checks it. 421 is the SDK's answer for a Host that is not
    on the list; a 200 here would mean rebinding protection is inert.
    """
    async with http_server() as url:
        async with httpx2.AsyncClient() as http:
            response = await http.post(
                url,
                headers={
                    "Host": "attacker.example.test",
                    "content-type": "application/json",
                    "accept": "application/json, text/event-stream",
                },
                content=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
            )
    assert response.status_code == 421
    assert "Host" in response.text


async def test_http_refuses_to_start_without_an_allowlist():
    """Fail-closed, proven on the real process rather than in-process."""
    port = _free_loopback_port()
    env = {**os.environ, "EIP_API_BASE_URL": BASE_URL}
    env.pop("EIP_MCP_ALLOWED_HOSTS", None)
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "eip_mcp_v3",
            "--transport",
            "streamable-http",
            "--port",
            str(port),
        ],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        timeout=60,
    )
    assert completed.returncode == 2
    assert b"EIP_MCP_ALLOWED_HOSTS" in completed.stderr
    assert completed.stdout == b""
    assert b"Traceback" not in completed.stderr
    # Nothing may be left listening on that port.
    with pytest.raises(OSError):
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            pass


# --------------------------------------------------------------------------
# Review findings, on the real process.
#
# The hermetic suite proves the wiring; these prove the behaviour an operator
# actually meets, over a real socket or a real exit status.
# --------------------------------------------------------------------------


async def test_http_accepts_the_root_dot_form_of_an_allowlisted_host():
    """`127.0.0.1.` and `127.0.0.1` name the same host, so both must be served.

    The allowlist here is written without the dot; the entry is registered both
    ways by `HttpTransportSettings`. Before that normalisation this returned 421,
    which is fail-closed but is an availability wart, not a defence.
    """
    async with http_server() as url:
        port = httpx2.URL(url).port
        async with httpx2.AsyncClient() as http:
            response = await http.post(
                url,
                headers={
                    "Host": f"127.0.0.1.:{port}",
                    "content-type": "application/json",
                    "accept": "application/json, text/event-stream",
                },
                content=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
            )
    assert response.status_code == 200


async def test_http_still_rejects_a_mixed_case_host_header():
    """The documented limitation, pinned so the docs cannot quietly become wrong.

    Normalising our own entries cannot make the SDK's `==` case-insensitive, and
    loosening that matcher to fix an ergonomics complaint is not a trade this repo
    makes. 421 is the honest outcome; `docs/self-hosting.md` says so.

    The allowlist is written in mixed case here and the accepted request is sent in
    lowercase, which is the half that *is* fixed - without entry normalisation this
    allowlist would match nothing at all and the 421 below would prove nothing.
    """
    async def post(url: str, host: str):
        async with httpx2.AsyncClient() as http:
            return await http.post(
                url,
                headers={
                    "Host": host,
                    "content-type": "application/json",
                    "accept": "application/json, text/event-stream",
                },
                content=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
            )

    async with http_server(allowed_hosts="MCP.Example.Test") as url:
        accepted = await post(url, "mcp.example.test")
        refused = await post(url, "MCP.Example.Test")
    assert accepted.status_code == 200
    assert refused.status_code == 421


def test_http_refuses_a_bare_wildcard_allowlist():
    """`*` boots and matches nothing real. Refusing is what the operator meant."""
    port = _free_loopback_port()
    env = {**os.environ, "EIP_API_BASE_URL": BASE_URL, "EIP_MCP_ALLOWED_HOSTS": "*"}
    completed = subprocess.run(
        [sys.executable, "-m", "eip_mcp_v3", "--transport", "streamable-http", "--port", str(port)],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        timeout=60,
    )
    assert completed.returncode == 2
    assert b"EIP_MCP_ALLOWED_HOSTS" in completed.stderr
    assert completed.stdout == b""
    assert b"Traceback" not in completed.stderr
    with pytest.raises(OSError):
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            pass


def test_stdio_refuses_the_http_only_flags():
    """They applied to nothing; the process must say so instead of starting."""
    completed = subprocess.run(
        [sys.executable, "-m", "eip_mcp_v3", "--port", "13003"],
        cwd=str(REPO_ROOT),
        env={**os.environ, "EIP_API_BASE_URL": BASE_URL},
        capture_output=True,
        timeout=60,
    )
    assert completed.returncode == 2
    assert b"--port" in completed.stderr
    assert b"streamable-http" in completed.stderr
    assert completed.stdout == b""
    assert b"Traceback" not in completed.stderr


def test_a_non_loopback_bind_warns_on_the_real_processes_stderr():
    """Warned, never refused - and never on stdout.

    The address is TEST-NET-1 (RFC 5737), which is never assigned to an interface,
    so the warning is printed and the bind then fails: the real process prints the
    real warning without this test opening a routable socket on the machine it runs
    on. Passing `0.0.0.0` here would prove the same thing by exposing the corpus to
    the tester's LAN for the duration, which is not a trade a test should make.
    """
    port = _free_loopback_port()
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "eip_mcp_v3",
            "--transport",
            "streamable-http",
            "--host",
            "192.0.2.1",
            "--port",
            str(port),
        ],
        cwd=str(REPO_ROOT),
        env={
            **os.environ,
            "EIP_API_BASE_URL": BASE_URL,
            "EIP_MCP_ALLOWED_HOSTS": f"192.0.2.1:{port}",
        },
        capture_output=True,
        timeout=60,
    )
    stderr = completed.stderr.decode(errors="replace")
    assert "warning" in stderr.lower()
    assert "192.0.2.1" in stderr
    # It is a warning, not a refusal: the run proceeded to the bind, and only the
    # unassignable address stopped it.
    assert "loopback" in stderr
    assert completed.stdout == b""
    # The silent-on-loopback half is covered hermetically in tests/test_entrypoint.py;
    # every other live HTTP test here binds 127.0.0.1 and would fail its startup wait
    # if the warning path had grown a side effect.
