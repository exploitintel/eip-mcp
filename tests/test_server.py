import asyncio
import inspect
from importlib.metadata import version

import pytest
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import LATEST_PROTOCOL_VERSION

from eip_mcp_v3 import __version__, prompts
from eip_mcp_v3 import format as fmt
from eip_mcp_v3 import tools as tools_module
from eip_mcp_v3.api_client import EipApiClient
from eip_mcp_v3.config import Settings
from eip_mcp_v3.server import CACHE_HINTS, TOOL_ORDER, create_mcp_server
from eip_mcp_v3.structured import RenderedText, StructuredResult
from eip_mcp_v3.tools import EipTools

SETTINGS = Settings(api_base_url="http://api.test")


def test_targets_current_protocol_revision():
    assert LATEST_PROTOCOL_VERSION == "2026-07-28"


def test_server_version_comes_from_installed_package_metadata():
    expected = version("eip-mcp")
    assert __version__ == expected
    assert create_mcp_server(SETTINGS).version == expected


def test_fastmcp_is_not_importable():
    with pytest.raises(ModuleNotFoundError):
        import mcp.server.fastmcp  # noqa: F401


# `cache_hints` is a client-visible retention policy, not a performance knob:
# `scope="public"` invites a *shared* cache to keep the response and hand it to
# somebody else, and the TTL says for how long. Flipping a scope, stretching a
# TTL, or adding a sixth method are each a change to what a host may retain and
# who may see it, so the whole declaration is pinned rather than spot-checked -
# every one of those edits used to survive the suite untouched.
EXPECTED_CACHE_HINTS = {
    "tools/list": (3_600_000, "public"),
    "prompts/list": (3_600_000, "public"),
    "resources/list": (3_600_000, "public"),
    "resources/read": (3_600_000, "public"),
    "server/discover": (3_600_000, "public"),
}


def test_declared_cache_hints_are_pinned():
    declared = {method: (hint.ttl_ms, hint.scope) for method, hint in CACHE_HINTS.items()}
    assert declared == EXPECTED_CACHE_HINTS


def test_no_corpus_bearing_method_is_declared_cacheable():
    """Only the five static surfaces above may be cached.

    `tools/call` is the one method whose result can carry PoC source, artifact
    metadata, or a file body, all of which the API serves `private, no-store`.
    The SDK refuses to accept a hint for it, but the refusal is the SDK's
    invariant; this is ours.
    """
    assert "tools/call" not in CACHE_HINTS
    assert all(hint.scope == "public" for hint in CACHE_HINTS.values())


async def test_registers_exactly_nineteen_tools():
    server = create_mcp_server(SETTINGS)
    tools = await server.list_tools()
    assert len(tools) == 19


async def test_tool_names_match_declared_order():
    server = create_mcp_server(SETTINGS)
    names = [tool.name for tool in await server.list_tools()]
    assert names == list(TOOL_ORDER)


async def test_tool_order_is_deterministic():
    first = [t.name for t in await create_mcp_server(SETTINGS).list_tools()]
    second = [t.name for t in await create_mcp_server(SETTINGS).list_tools()]
    assert first == second


async def test_every_tool_is_annotated_read_only():
    server = create_mcp_server(SETTINGS)
    for tool in await server.list_tools():
        assert tool.annotations is not None, f"{tool.name} has no annotations"
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False
        assert tool.annotations.open_world_hint is True


async def test_every_tool_has_a_description():
    server = create_mcp_server(SETTINGS)
    for tool in await server.list_tools():
        assert tool.description and len(tool.description) > 40


async def test_no_download_tool_is_registered():
    server = create_mcp_server(SETTINGS)
    names = [tool.name for tool in await server.list_tools()]
    assert not any("download" in name for name in names)


async def test_registers_four_prompts():
    server = create_mcp_server(SETTINGS)
    assert len(await server.list_prompts()) == 4


async def test_registers_usage_guide_resource():
    server = create_mcp_server(SETTINGS)
    uris = [str(resource.uri) for resource in await server.list_resources()]
    assert "eip://research/usage-guide" in uris


# --- Connection-pool lifecycle ------------------------------------------------
#
# The client this function builds owns an httpx2 connection pool. Nothing called
# aclose() on it, so every server built here leaked one. MCPServer's `lifespan`
# hook is the only shutdown seam the SDK offers, so ownership is expressed there:
# close what we constructed, never what the caller handed us and still holds.


async def test_lifespan_closes_the_client_it_created(monkeypatch):
    """A real httpx2 pool, really closed - not a stub recording a call."""
    created: list[EipApiClient] = []
    real = EipApiClient

    def _capture(settings):
        client = real(settings)
        created.append(client)
        return client

    monkeypatch.setattr("eip_mcp_v3.server.EipApiClient", _capture)
    server = create_mcp_server(SETTINGS)

    assert len(created) == 1
    async with server.settings.lifespan(server):
        assert created[0]._client.is_closed is False
    assert created[0]._client.is_closed is True


async def test_lifespan_leaves_a_caller_supplied_client_open():
    """Injected tools belong to the caller; closing their pool would break them."""
    client = EipApiClient(SETTINGS)
    server = create_mcp_server(SETTINGS, EipTools(client, SETTINGS))

    async with server.settings.lifespan(server) as context:
        # The SDK's default lifespan yields {}; ours must not change what
        # request handlers find in ctx.lifespan_context.
        assert context == {}

    assert client._client.is_closed is False
    await client.aclose()


def test_instructions_declare_content_hostile():
    from eip_mcp_v3.server import SERVER_INSTRUCTIONS

    lowered = SERVER_INSTRUCTIONS.lower()
    assert "untrusted" in lowered
    assert "never execute" in lowered or "do not execute" in lowered


def test_instructions_carry_the_containment_rule_verbatim():
    """The one sentence a shortened page-level note is allowed to lean on.

    `get_corpus_readiness` and `get_corpus_statistics` render a scaled-down security
    note, on the grounds that a client surfaces these instructions to the model once
    per session. That is only true while the instructions actually carry the full
    statement, so it is asserted here character for character rather than paraphrased.
    """
    from eip_mcp_v3.server import SERVER_INSTRUCTIONS
    from eip_mcp_v3.text import CONTAINMENT_RULE, UNTRUSTED_NOTE

    assert CONTAINMENT_RULE in SERVER_INSTRUCTIONS
    assert CONTAINMENT_RULE in UNTRUSTED_NOTE, "the page note and the server have drifted"
    assert "code span or a quoted block" in CONTAINMENT_RULE
    assert "every word outside them is EIP's own" in CONTAINMENT_RULE


async def test_the_vulnerability_tool_defines_the_counts_the_brief_only_points_at():
    """The brief stopped printing ninety words of definition on every call.

    It now prints the property and points at the guide, which is only honest while the
    definitions are somewhere the model reads. Both places are asserted here, so
    shortening the brief cannot quietly become dropping the explanation.
    """
    from eip_mcp_v3 import format as fmt

    server = create_mcp_server(SETTINGS, _StubTools())
    tool = next(t for t in await server.list_tools() if t.name == "get_vulnerability")
    assert fmt.EXPLOITATION_COUNT_RULE in tool.description
    assert fmt.EXPLOITATION_COUNT_RULE in prompts.USAGE_GUIDE
    assert fmt.POC_COUNT_RULE in prompts.USAGE_GUIDE


# --- Registration is wiring, so prove the wires carry something. ---------------
#
# Every test above passes on a server whose handlers call the wrong EipTools
# method, drop an argument, or return a constant: they only inspect the listing.
# The tests below exercise the registered callables themselves, so a wiring
# mistake fails here instead of at live verification.


class _StubTools:
    """Records dispatch. Deliberately declares each method by hand.

    No `__getattr__` fallback: a handler that called a misspelled EipTools method
    must raise AttributeError here rather than be silently absorbed.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def _record(self, name: str, **kwargs: object) -> RenderedText:
        self.calls.append((name, kwargs))
        return RenderedText(
            f"rendered:{name}", StructuredResult(kind=name, data={})
        )

    async def get_corpus_readiness(self) -> str:
        return self._record("get_corpus_readiness")

    async def get_corpus_statistics(self, trends: str = "none") -> str:
        return self._record("get_corpus_statistics", trends=trends)

    async def search_vulnerabilities(self, **kwargs: object) -> str:
        return self._record("search_vulnerabilities", **kwargs)

    async def browse_vendors(self, **kwargs: object) -> str:
        return self._record("browse_vendors", **kwargs)

    async def browse_products(self, **kwargs: object) -> str:
        return self._record("browse_products", **kwargs)

    async def browse_ecosystems(self, **kwargs: object) -> str:
        return self._record("browse_ecosystems", **kwargs)

    async def browse_packages(self, **kwargs: object) -> str:
        return self._record("browse_packages", **kwargs)

    async def browse_weaknesses(self, **kwargs: object) -> str:
        return self._record("browse_weaknesses", **kwargs)

    async def get_weakness(self, cwe_id) -> str:
        return self._record("get_weakness", cwe_id=cwe_id)

    async def browse_authors(self, **kwargs: object) -> str:
        return self._record("browse_authors", **kwargs)

    async def get_author(self, public_id) -> str:
        return self._record("get_author", public_id=public_id)

    async def get_vulnerability(self, identifier, sections=None, section_limit=10) -> str:
        return self._record(
            "get_vulnerability",
            identifier=identifier,
            sections=sections,
            section_limit=section_limit,
        )

    async def get_vulnerability_stix(self, identifier) -> str:
        return self._record("get_vulnerability_stix", identifier=identifier)

    async def get_artifact(self, artifact_id) -> str:
        return self._record("get_artifact", artifact_id=artifact_id)

    async def search_labs(self, **kwargs: object) -> str:
        return self._record("search_labs", **kwargs)

    async def search_exploits(self, **kwargs: object) -> str:
        return self._record("search_exploits", **kwargs)

    async def get_exploit(self, artifact_id) -> str:
        return self._record("get_exploit", artifact_id=artifact_id)

    async def search_exploit_code(
        self,
        query,
        source=None,
        public_id=None,
        vulnerability_id=None,
        limit=25,
        cursor=None,
    ) -> str:
        return self._record(
            "search_exploit_code",
            query=query,
            source=source,
            public_id=public_id,
            vulnerability_id=vulnerability_id,
            limit=limit,
            cursor=cursor,
        )

    async def read_exploit_file(self, artifact_id, path=None) -> str:
        return self._record("read_exploit_file", artifact_id=artifact_id, path=path)


MINIMAL_ARGUMENTS = {
    "get_corpus_readiness": {},
    "get_corpus_statistics": {},
    "search_vulnerabilities": {},
    "browse_vendors": {},
    "browse_products": {"vendor": "Microsoft"},
    "browse_ecosystems": {},
    "browse_packages": {"ecosystem": "npm"},
    "browse_weaknesses": {},
    "get_weakness": {"cwe_id": "CWE-79"},
    "browse_authors": {},
    "get_author": {"public_id": 123},
    "get_vulnerability": {"identifier": "CVE-2021-44228"},
    "get_vulnerability_stix": {"identifier": "CVE-2021-44228"},
    "get_artifact": {"artifact_id": "abc-123"},
    "search_labs": {},
    "search_exploits": {},
    "get_exploit": {"artifact_id": "abc-123"},
    "search_exploit_code": {"query": "jndi"},
    "read_exploit_file": {"artifact_id": "abc-123"},
}


def test_tool_names_are_the_public_eiptools_surface():
    """Ties TOOL_ORDER to the real class, so neither side can drift unnoticed."""
    public = {
        name
        for name, member in inspect.getmembers(EipTools, inspect.iscoroutinefunction)
        if not name.startswith("_")
    }
    assert set(TOOL_ORDER) == public


@pytest.mark.parametrize("tool_name", TOOL_ORDER)
async def test_each_tool_dispatches_to_its_handler(tool_name):
    stub = _StubTools()
    server = create_mcp_server(SETTINGS, stub)

    result = await server.call_tool(tool_name, dict(MINIMAL_ARGUMENTS[tool_name]))

    assert [name for name, _ in stub.calls] == [tool_name]
    assert result.is_error is False
    assert result.content[0].text == f"rendered:{tool_name}"


async def test_arguments_reach_the_handler_unchanged():
    stub = _StubTools()
    server = create_mcp_server(SETTINGS, stub)

    await server.call_tool(
        "get_vulnerability",
        {"identifier": "CVE-2021-44228", "sections": ["pocs"], "section_limit": 3},
    )
    await server.call_tool("read_exploit_file", {"artifact_id": "abc", "path": "poc.py"})

    assert stub.calls == [
        (
            "get_vulnerability",
            {"identifier": "CVE-2021-44228", "sections": ["pocs"], "section_limit": 3},
        ),
        ("read_exploit_file", {"artifact_id": "abc", "path": "poc.py"}),
    ]


# --- Parameter passthrough, exhaustively ---------------------------------------
#
# `test_arguments_reach_the_handler_unchanged` above covers two tools, and
# `test_each_tool_dispatches_to_its_handler` calls every tool with defaults only,
# so a dropped optional parameter changes nothing either one can see. A mutation
# harness confirmed the hole: dropping `trends` from the get_corpus_statistics
# call, and passing `cwe=cursor` in search_vulnerabilities, both survived the
# whole suite. Silently dropping or crossing a parameter is the worst defect this
# layer can have - the model asks one question and the corpus answers another.
#
# The table below drives a distinct non-default value through every parameter of
# every tool. `observed_defaults` is what each EipTools method sees when only its
# required arguments are supplied, so a parameter that never arrives shows up as
# its default and a parameter that lands on the wrong name shows up there.

PASSTHROUGH: dict[str, dict[str, dict]] = {
    "get_corpus_readiness": {
        "required": {},
        "observed_defaults": {},
        "variants": {},
    },
    "get_corpus_statistics": {
        "required": {},
        "observed_defaults": {"trends": "none"},
        "variants": {"trends": "cwe"},
    },
    "search_vulnerabilities": {
        "required": {},
        "observed_defaults": {
            "query": None,
            "severity": None,
            "cwe": None,
            "vendor": None,
            "product": None,
            "ecosystem": None,
            "package": None,
            "cisa_kev": False,
            "ransomware": False,
            "nuclei": False,
            "with_artifacts": False,
            "sort": "published",
            "limit": 25,
            "cursor": None,
        },
        "variants": {
            "query": "log4j jndi",
            "severity": ["HIGH"],
            "cwe": "CWE-502",
            "vendor": "Apache Software Foundation",
            "product": "Apache Struts",
            "ecosystem": "npm",
            "package": "@scope/Exact-Package",
            "cisa_kev": True,
            "ransomware": True,
            "nuclei": True,
            "with_artifacts": True,
            "sort": "epss",
            "limit": 7,
            "cursor": "CURSOR-VULN-1",
        },
    },
    "browse_vendors": {
        "required": {},
        "observed_defaults": {"query": None, "limit": 25, "cursor": None},
        "variants": {"query": "apache", "limit": 7, "cursor": "CURSOR-VENDOR-1"},
    },
    "browse_products": {
        "required": {"vendor": "Microsoft"},
        "observed_defaults": {
            "vendor": "Microsoft",
            "query": None,
            "limit": 25,
            "cursor": None,
        },
        "variants": {
            "vendor": "Apache Software Foundation",
            "query": "struts",
            "limit": 7,
            "cursor": "CURSOR-PRODUCT-1",
        },
    },
    "browse_ecosystems": {
        "required": {},
        "observed_defaults": {"query": None, "limit": 25, "cursor": None},
        "variants": {"query": "npm", "limit": 7, "cursor": "CURSOR-ECOSYSTEM-1"},
    },
    "browse_packages": {
        "required": {"ecosystem": "npm"},
        "observed_defaults": {
            "ecosystem": "npm",
            "query": None,
            "limit": 25,
            "cursor": None,
        },
        "variants": {
            "ecosystem": "PyPI",
            "query": "django",
            "limit": 7,
            "cursor": "CURSOR-PACKAGE-1",
        },
    },
    "browse_weaknesses": {
        "required": {},
        "observed_defaults": {"query": None, "limit": 25, "cursor": None},
        "variants": {"query": "cross-site", "limit": 7, "cursor": "CURSOR-CWE-1"},
    },
    "get_weakness": {
        "required": {"cwe_id": "CWE-79"},
        "observed_defaults": {"cwe_id": "CWE-79"},
        "variants": {"cwe_id": "CWE-89"},
    },
    "browse_authors": {
        "required": {},
        "observed_defaults": {
            "query": None,
            "source_scope": None,
            "role": None,
            "limit": 25,
            "cursor": None,
        },
        "variants": {
            "query": "rapid7",
            "source_scope": "github",
            "role": "owner",
            "limit": 7,
            "cursor": "CURSOR-AUTHOR-1",
        },
    },
    "get_author": {
        "required": {"public_id": 123},
        "observed_defaults": {"public_id": 123},
        "variants": {"public_id": 456},
    },
    "get_vulnerability": {
        "required": {"identifier": "CVE-2021-44228"},
        "observed_defaults": {
            "identifier": "CVE-2021-44228",
            "sections": None,
            "section_limit": 10,
        },
        "variants": {
            "identifier": "CVE-2017-0144",
            "sections": ["pocs", "nuclei"],
            "section_limit": 3,
        },
    },
    "get_vulnerability_stix": {
        "required": {"identifier": "CVE-2021-44228"},
        "observed_defaults": {"identifier": "CVE-2021-44228"},
        "variants": {"identifier": "CVE-2017-0144"},
    },
    "get_artifact": {
        "required": {"artifact_id": "abc-123"},
        "observed_defaults": {"artifact_id": "abc-123"},
        "variants": {"artifact_id": "ART-9999"},
    },
    "search_labs": {
        "required": {},
        "observed_defaults": {
            "query": None,
            "kind": "all",
            "association": "all",
            "analysis": "all",
            "include_analysis": False,
            "limit": 25,
            "cursor": None,
        },
        "variants": {
            "query": "log4shell",
            "kind": "compose",
            "association": "linked",
            "analysis": "available",
            "include_analysis": True,
            "limit": 7,
            "cursor": "CURSOR-LAB-1",
        },
    },
    "search_exploits": {
        "required": {},
        "observed_defaults": {
            "query": None,
            "source": None,
            "catalog_kind": None,
            "association": "all",
            "language": None,
            "source_date_from": None,
            "source_date_to": None,
            "author_id": None,
            "limit": 25,
            "cursor": None,
        },
        "variants": {
            "query": "smb relay",
            "source": "metasploit",
            "catalog_kind": "metasploit-auxiliary",
            "association": "linked",
            "language": "Ruby",
            "source_date_from": "2021-01-01",
            "source_date_to": "2022-12-31",
            "author_id": 123,
            "limit": 9,
            "cursor": "CURSOR-POC-1",
        },
    },
    "get_exploit": {
        "required": {"artifact_id": "abc-123"},
        "observed_defaults": {"artifact_id": "abc-123"},
        "variants": {"artifact_id": "ART-9999"},
    },
    "search_exploit_code": {
        "required": {"query": "jndi"},
        "observed_defaults": {
            "query": "jndi",
            "source": None,
            "public_id": None,
            "vulnerability_id": None,
            "limit": 25,
            "cursor": None,
        },
        "variants": {
            "query": "readObject deserialize",
            "source": "exploitdb",
            "public_id": 3505014494080483,
            "vulnerability_id": "CVE-2021-44228",
            "limit": 11,
            "cursor": "CURSOR-CODE-1",
        },
    },
    "read_exploit_file": {
        "required": {"artifact_id": "abc-123"},
        "observed_defaults": {"artifact_id": "abc-123", "path": None},
        "variants": {
            "artifact_id": "ART-4242",
            "path": "exploits/linux/local/poc.py",
        },
    },
}

ONE_AT_A_TIME = [
    (tool_name, parameter)
    for tool_name, spec in PASSTHROUGH.items()
    for parameter in spec["variants"]
]


def test_passthrough_table_covers_every_tool_and_every_parameter():
    """Ties the table to the real signatures, so a new parameter cannot ship untested.

    Without this, adding a parameter to an EipTools method and wiring it through
    server.py leaves it silently outside the passthrough coverage below.
    """
    assert set(PASSTHROUGH) == set(TOOL_ORDER)
    for tool_name in TOOL_ORDER:
        signature = inspect.signature(getattr(EipTools, tool_name))
        parameters = {name for name in signature.parameters if name != "self"}
        assert set(PASSTHROUGH[tool_name]["variants"]) == parameters, tool_name
        assert set(PASSTHROUGH[tool_name]["observed_defaults"]) == parameters, tool_name


@pytest.mark.parametrize("tool_name,parameter", ONE_AT_A_TIME)
async def test_each_parameter_reaches_its_handler_under_its_own_name(tool_name, parameter):
    """One non-default parameter at a time: everything else must stay at its default.

    Varying exactly one parameter is what catches a crossed wire. If
    search_vulnerabilities passed `cwe=cursor`, the `cursor` case would show a
    value on `cwe`, and the `cwe` case would show `cwe` still None.
    """
    spec = PASSTHROUGH[tool_name]
    value = spec["variants"][parameter]
    stub = _StubTools()
    server = create_mcp_server(SETTINGS, stub)

    await server.call_tool(tool_name, {**spec["required"], parameter: value})

    assert stub.calls == [(tool_name, {**spec["observed_defaults"], parameter: value})]


@pytest.mark.parametrize("tool_name", TOOL_ORDER)
async def test_every_parameter_reaches_its_handler_together(tool_name):
    """All parameters non-default at once: catches a parameter dropped from the call."""
    spec = PASSTHROUGH[tool_name]
    stub = _StubTools()
    server = create_mcp_server(SETTINGS, stub)

    await server.call_tool(tool_name, {**spec["required"], **spec["variants"]})

    assert stub.calls == [
        (tool_name, {**spec["observed_defaults"], **spec["variants"]})
    ]


# --- Schema enums are a hint; tools.py stays the gate ---------------------------

SCHEMA_ENUMS = [
    ("get_corpus_statistics", "trends", tools_module.TREND_SERIES),
    ("search_vulnerabilities", "sort", tools_module.SORTS),
    ("search_exploits", "source", tools_module.POC_SOURCES),
    ("search_exploits", "catalog_kind", tools_module.CATALOG_KINDS),
    ("search_exploits", "association", tools_module.ASSOCIATIONS),
    ("browse_authors", "source_scope", tools_module.AUTHOR_SOURCES),
    ("browse_authors", "role", tools_module.AUTHOR_ROLES),
    ("search_exploit_code", "source", tools_module.POC_SOURCES),
    ("search_labs", "kind", tools_module.LAB_KINDS),
    ("search_labs", "association", tools_module.LAB_ASSOCIATIONS),
    ("search_labs", "analysis", tools_module.LAB_ANALYSIS),
]


def _enum_of(schema: dict, name: str) -> list[str] | None:
    """Pull a property's enum, whether or not the property is Optional.

    A required Literal renders as {"enum": [...]}; an optional one renders as
    {"anyOf": [{"enum": [...]}, {"type": "null"}]}.
    """
    prop = schema["properties"][name]
    if "enum" in prop:
        return prop["enum"]
    for branch in prop.get("anyOf", []):
        if "enum" in branch:
            return branch["enum"]
    return None


@pytest.mark.parametrize("tool_name,parameter,accepted", SCHEMA_ENUMS)
async def test_schema_enum_matches_the_runtime_gate(tool_name, parameter, accepted):
    """The advertised values must be exactly the values tools.py accepts.

    Comparing against the tools.py tuple rather than a copied literal means the
    hint cannot drift away from the gate it is describing.
    """
    server = create_mcp_server(SETTINGS, _StubTools())
    tool = {t.name: t for t in await server.list_tools()}[tool_name]

    assert _enum_of(tool.input_schema, parameter) == list(accepted)


# --------------------------------------------------------------------------
# Audit V-10: framework internals leaked from one tool's enum rejections.
#
# `search_exploits(source="bogus")` returned the internal argument-model name, the
# Pydantic error taxonomy and a version-pinned `errors.pydantic.dev` URL, while
# `search_vulnerabilities(severity=["BOGUS"])` returned one clean sentence naming the
# accepted values. Same server, same class of mistake, two unrecognisable surfaces.
#
# The asymmetry was structural: `severity` is not `Literal`-annotated, so it reached
# the hand-written check in tools.py, while the `Literal` parameters were rejected by
# the SDK before any of this server's code ran. The annotations stay - they are what
# puts the accepted values in the tool schema - and the rejection is reworded instead.
# --------------------------------------------------------------------------

PYDANTIC_INTERNALS = (
    "validation error",
    "Arguments",
    "errors.pydantic.dev",
    "literal_error",
    "input_type",
    "[type=",
)

ENUM_REJECTIONS = [
    ("get_corpus_statistics", {"trends": "bogus"}, "trends must be one of"),
    ("search_vulnerabilities", {"sort": "bogus"}, "sort must be one of"),
    ("search_exploits", {"source": "bogus"}, "source must be one of"),
    ("search_exploits", {"catalog_kind": "bogus"}, "catalog_kind must be one of"),
    ("search_exploits", {"association": "bogus"}, "association must be one of"),
    ("search_exploit_code", {"query": "jndi", "source": "bogus"}, "source must be one of"),
    # A wrong *type* is the same mistake made differently, and used to leak the same
    # internals. Both have to come back in this server's own words.
    ("search_exploits", {"source": 7}, "source must be one of"),
    ("search_exploits", {"source": ["exploitdb"]}, "source must be one of"),
    ("search_exploits", {"association": None}, "association must be one of"),
    ("browse_authors", {"source_scope": "bogus"}, "source_scope must be one of"),
    ("browse_authors", {"role": "bogus"}, "role must be one of"),
]


# The same division of labour for the bounded integers. Two distinct refusals,
# kept apart deliberately: a number outside the range, and a value that is not a
# whole number at all. Telling a caller who sent `"abc"` that it "must be between
# 1 and 100" sends them looking for a different number.
#
# `limit=True` is the one case that must be refused rather than coerced: `bool`
# subclasses `int`, so without the guard it silently became `limit=1`.
RANGE_REJECTIONS = [
    ("search_vulnerabilities", {"limit": 0}, "limit must be between 1 and 100"),
    ("search_vulnerabilities", {"limit": 101}, "limit must be between 1 and 100"),
    ("search_vulnerabilities", {"limit": -1}, "limit must be between 1 and 100"),
    ("browse_weaknesses", {"limit": 0}, "limit must be between 1 and 100"),
    ("browse_weaknesses", {"limit": 101}, "limit must be between 1 and 100"),
    ("browse_authors", {"limit": 101}, "limit must be between 1 and 100"),
    ("get_author", {"public_id": 0}, "public_id must be between 1 and"),
    ("search_exploits", {"author_id": 0}, "author_id must be between 1 and"),
    ("search_exploits", {"limit": 101}, "limit must be between 1 and 100"),
    ("search_exploit_code", {"query": "jndi", "limit": 51}, "limit must be between 1 and 50"),
    ("search_exploit_code", {"query": "jndi", "limit": 0}, "limit must be between 1 and 50"),
    ("get_vulnerability", {"identifier": "CVE-2021-44228", "section_limit": 0},
     "section_limit must be between 1 and 50"),
    ("get_vulnerability", {"identifier": "CVE-2021-44228", "section_limit": 51},
     "section_limit must be between 1 and 50"),
    # Not a whole number: a different fact, and it gets a different sentence.
    ("search_vulnerabilities", {"limit": 2.5}, "limit must be a whole number"),
    ("search_vulnerabilities", {"limit": "abc"}, "limit must be a whole number"),
    ("search_vulnerabilities", {"limit": None}, "limit must be a whole number"),
    ("search_vulnerabilities", {"limit": [25]}, "limit must be a whole number"),
    ("search_vulnerabilities", {"limit": True}, "limit must be a whole number"),
    # A whole number that is simply out of range, sent as a string: the string
    # is not the problem, so it must get the range sentence, not the other one.
    ("search_vulnerabilities", {"limit": "500"}, "limit must be between 1 and 100"),
]


# Pydantic's non-strict mode coerced these before the bounds were published, and
# the SDK hands a bare numeric scalar through as the string it arrived as. Refusing
# them would break callers that worked yesterday, so they must still be accepted.
COERCED_LIMITS = [
    ("search_vulnerabilities", {"limit": "25"}, 25),
    ("search_vulnerabilities", {"limit": 25.0}, 25),
    ("search_vulnerabilities", {"limit": " 25 "}, 25),
    ("search_vulnerabilities", {"limit": "25.0"}, 25),
    ("search_vulnerabilities", {"limit": "+25"}, 25),
    ("search_vulnerabilities", {"limit": "025"}, 25),
    ("search_exploit_code", {"query": "jndi", "limit": "50"}, 50),
]

# The other direction, and the reason the coercion is delegated to Pydantic rather
# than rewritten: a hand-written check accepted these, Pydantic never did, and the
# schema advertises `"type": "integer"`. Accepting a grammar the server does not
# publish is the same defect as dropping an argument it does not declare.
NOT_PYDANTIC_INTEGERS = ["٢٥", "２５", "２5", "1e2", "0x19", "0b11001", "25e0", "２5.0"]


@pytest.mark.parametrize("value", NOT_PYDANTIC_INTEGERS)
async def test_a_grammar_the_schema_does_not_publish_is_refused(value):
    server = create_mcp_server(SETTINGS, _StubTools())
    with pytest.raises(ToolError, match="limit must be a whole number"):
        await server.call_tool("search_vulnerabilities", {"limit": value})


@pytest.mark.parametrize("tool_name,arguments,expected", COERCED_LIMITS)
async def test_a_numeric_scalar_is_still_coerced_not_refused(tool_name, arguments, expected):
    stub = _StubTools()
    server = create_mcp_server(SETTINGS, stub)
    await server.call_tool(tool_name, arguments)
    assert stub.calls[-1][1]["limit"] == expected


@pytest.mark.parametrize("tool_name,arguments,expected", RANGE_REJECTIONS)
async def test_a_rejected_bound_reads_like_this_servers_own_errors(
    tool_name, arguments, expected
):
    server = create_mcp_server(SETTINGS, _StubTools())
    with pytest.raises(ToolError) as raised:
        await server.call_tool(tool_name, arguments)
    message = str(raised.value)
    assert expected in message, message
    for internal in PYDANTIC_INTERNALS:
        assert internal not in message, f"framework internals leaked: {message}"


@pytest.mark.parametrize(
    "tool_name,parameter,low,high",
    [
        ("search_vulnerabilities", "limit", 1, tools_module.PAGE_LIMIT_MAX),
        ("browse_vendors", "limit", 1, tools_module.PAGE_LIMIT_MAX),
        ("browse_products", "limit", 1, tools_module.PAGE_LIMIT_MAX),
        ("browse_ecosystems", "limit", 1, tools_module.PAGE_LIMIT_MAX),
        ("browse_packages", "limit", 1, tools_module.PAGE_LIMIT_MAX),
        ("browse_weaknesses", "limit", 1, tools_module.PAGE_LIMIT_MAX),
        ("browse_authors", "limit", 1, tools_module.PAGE_LIMIT_MAX),
        ("get_author", "public_id", 1, tools_module.AUTHOR_PUBLIC_ID_MAX),
        ("search_exploits", "author_id", 1, tools_module.AUTHOR_PUBLIC_ID_MAX),
        ("search_exploits", "limit", 1, tools_module.PAGE_LIMIT_MAX),
        ("search_exploit_code", "limit", 1, tools_module.CODE_PAGE_LIMIT_MAX),
        ("search_exploit_code", "public_id", 1, tools_module.AUTHOR_PUBLIC_ID_MAX),
        ("get_vulnerability", "section_limit", 1, fmt.SECTION_LIMIT_MAX),
    ],
)
async def test_each_bound_is_published_in_the_schema(tool_name, parameter, low, high):
    """A caller must be able to read the ceiling instead of discovering it."""
    server = create_mcp_server(SETTINGS, _StubTools())
    tool = next(t for t in await server.list_tools() if t.name == tool_name)
    spec = tool.input_schema["properties"][parameter]
    if "anyOf" in spec:
        spec = next(branch for branch in spec["anyOf"] if branch.get("type") == "integer")
    assert (spec.get("minimum"), spec.get("maximum")) == (low, high)


@pytest.mark.parametrize(
    "tool_name,parameter,extra",
    [
        ("search_vulnerabilities", "limit", {}),
        ("browse_vendors", "limit", {}),
        ("browse_products", "limit", {"vendor": "Microsoft"}),
        ("browse_ecosystems", "limit", {}),
        ("browse_packages", "limit", {"ecosystem": "npm"}),
        ("browse_weaknesses", "limit", {}),
        ("browse_authors", "limit", {}),
        ("get_author", "public_id", {}),
        ("search_exploits", "author_id", {}),
        ("search_exploits", "limit", {}),
        ("search_exploit_code", "limit", {"query": "jndi"}),
        ("get_vulnerability", "section_limit", {"identifier": "CVE-2021-44228"}),
    ],
)
async def test_the_advertised_ceiling_is_the_one_actually_enforced(tool_name, parameter, extra):
    """Behavioural tie, deliberately not a comparison of two constants.

    An earlier version of this read the same constant on both sides and so could
    not fail: hardcoding the server's annotation back to a literal left it green.
    This takes the ceiling from the *published schema* and then checks the
    *enforcement layer* honours exactly that number - the schema is the claim, and
    accepting `maximum` while refusing `maximum + 1` is the claim being true.
    """
    # Real EipTools, not the stub: the stub *replaces* the enforcement layer this
    # test is about, so with it the assertion cannot fail no matter how far the
    # advertised ceiling drifts from the enforced one. That is how the previous
    # two attempts at this test came out green under both drift mutations.
    import httpx2

    from eip_mcp_v3.api_client import EipApiClient

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.startswith("/api/v1/authors/"):
            return httpx2.Response(
                200,
                json={
                    "public_id": int(request.url.path.rsplit("/", 1)[1]),
                    "source_scope": "github",
                    "external_id": "octocat",
                    "display_name": "Octocat",
                    "roles": ["owner"],
                    "poc_count": 1,
                    "vulnerability_count": 1,
                },
            )
        return httpx2.Response(200, json={"items": [], "total": 0})

    client = EipApiClient(SETTINGS, transport=httpx2.MockTransport(handler))
    try:
        server = create_mcp_server(SETTINGS, EipTools(client, SETTINGS))
        tool = next(t for t in await server.list_tools() if t.name == tool_name)
        spec = tool.input_schema["properties"][parameter]
        if "anyOf" in spec:
            spec = next(
                branch for branch in spec["anyOf"] if branch.get("type") == "integer"
            )
        ceiling = spec["maximum"]

        await server.call_tool(tool_name, extra | {parameter: ceiling})

        with pytest.raises(ToolError) as raised:
            await server.call_tool(tool_name, extra | {parameter: ceiling + 1})
        assert f"between 1 and {ceiling}" in str(raised.value)
    finally:
        await client.aclose()


@pytest.mark.parametrize("tool_name,arguments,expected", ENUM_REJECTIONS)
async def test_a_rejected_enum_reads_like_this_servers_own_errors(
    tool_name, arguments, expected
):
    server = create_mcp_server(SETTINGS, _StubTools())
    with pytest.raises(ToolError) as raised:
        await server.call_tool(tool_name, arguments)
    message = str(raised.value)
    assert expected in message, message
    for internal in PYDANTIC_INTERNALS:
        assert internal not in message, f"framework internals leaked: {message}"


@pytest.mark.parametrize("tool_name,parameter,accepted", SCHEMA_ENUMS)
async def test_a_rejected_enum_names_every_value_it_would_have_accepted(
    tool_name, parameter, accepted
):
    """The message is the only place a caller learns the values after a rejection."""
    server = create_mcp_server(SETTINGS, _StubTools())
    with pytest.raises(ToolError) as raised:
        await server.call_tool(tool_name, {parameter: "definitely-not-a-value"})
    for value in accepted:
        assert value in str(raised.value)


async def test_the_hand_written_and_the_sdk_rejections_are_one_shape():
    """`severity` was already clean; the rest now match it rather than the framework.

    Both rejections happen before a request is built, so the real `EipTools` here
    never reaches the network - it is present because the hand-written check lives
    in tools.py and a stub would bypass the very thing being compared against.
    """
    client = EipApiClient(SETTINGS)
    try:
        server = create_mcp_server(SETTINGS, EipTools(client, SETTINGS))
        messages = []
        for tool_name, arguments in (
            ("search_vulnerabilities", {"severity": ["BOGUS"]}),
            ("search_exploits", {"source": "bogus"}),
        ):
            with pytest.raises(ToolError) as raised:
                await server.call_tool(tool_name, arguments)
            messages.append(str(raised.value))
    finally:
        await client.aclose()
    assert all(message.startswith("Error executing tool ") for message in messages)
    assert all(message.count("\n") == 0 for message in messages), messages


async def test_an_accepted_enum_value_still_reaches_the_handler():
    """The reworded rejection must not have narrowed what the parameter takes."""
    stub = _StubTools()
    server = create_mcp_server(SETTINGS, stub)
    for value in tools_module.POC_SOURCES:
        await server.call_tool("search_exploits", {"source": value})
    await server.call_tool("search_exploits", {"source": None})
    assert [call[1]["source"] for call in stub.calls] == [*tools_module.POC_SOURCES, None]


async def test_severity_carries_no_enum_so_lowercase_still_reaches_the_handler():
    """Deliberate exception: severity is the one filter that self-corrects.

    tools.py accepts severity case-insensitively (`value.upper() in SEVERITIES`,
    covered in tests/test_tools.py). The SDK enforces a Literal at call time, so
    an uppercase-only enum here would start rejecting ["critical"] - input that
    works today, and the one case where a wrong case costs no round trip anyway.
    """
    stub = _StubTools()
    server = create_mcp_server(SETTINGS, stub)
    tool = {t.name: t for t in await server.list_tools()}["search_vulnerabilities"]
    assert _enum_of(tool.input_schema, "severity") is None

    await server.call_tool("search_vulnerabilities", {"severity": ["critical", "High"]})

    assert stub.calls[0][1]["severity"] == ["critical", "High"]


async def test_search_vulnerabilities_description_names_the_severity_values():
    """severity has no schema enum, so the description is where a model learns them."""
    server = create_mcp_server(SETTINGS, _StubTools())
    tool = {t.name: t for t in await server.list_tools()}["search_vulnerabilities"]
    for value in tools_module.SEVERITIES:
        assert value in tool.description


# --- Construction failure must not orphan a pool -------------------------------


def _explode(*_args: object, **_kwargs: object) -> MCPServer:
    raise RuntimeError("server construction failed")


def test_a_failed_construction_closes_the_client_it_created(monkeypatch):
    """The lifespan closes the pool, but only for a server that gets to run.

    If registration raises, this server is never returned and its lifespan never
    executes, so the pool built moments earlier would stay open with no reference
    left to close it.
    """
    created: list[EipApiClient] = []
    real = EipApiClient

    def _capture(settings):
        client = real(settings)
        created.append(client)
        return client

    monkeypatch.setattr("eip_mcp_v3.server.EipApiClient", _capture)
    monkeypatch.setattr("eip_mcp_v3.server.MCPServer", _explode)

    with pytest.raises(RuntimeError, match="server construction failed"):
        create_mcp_server(SETTINGS)

    assert len(created) == 1
    assert created[0]._client.is_closed is True


def test_a_failed_construction_leaves_a_caller_supplied_client_open(monkeypatch):
    """Same rule as the lifespan: never close a pool the caller still holds."""
    client = EipApiClient(SETTINGS)
    monkeypatch.setattr("eip_mcp_v3.server.MCPServer", _explode)

    with pytest.raises(RuntimeError, match="server construction failed"):
        create_mcp_server(SETTINGS, EipTools(client, SETTINGS))

    assert client._client.is_closed is False
    asyncio.run(client.aclose())


async def test_a_failing_tool_surfaces_only_the_exception_message():
    """A token lives as a frame local inside tools.py for the file-reading path.

    `MCPServer._handle_call_tool` puts `str(exc)` on the wire and nothing else, so
    frame locals never reach the model - provided this layer adds no handler that
    formats a traceback. This test fails if one is ever added.
    """
    secret = "eip-poc-token-DO-NOT-LEAK"

    class Failing(_StubTools):
        async def get_exploit(self, artifact_id) -> str:
            live_token = secret  # noqa: F841 - the point is that it is a frame local
            raise ValueError("artifact_id must be an artifact identifier")

    server = create_mcp_server(SETTINGS, Failing())
    with pytest.raises(ToolError) as caught:
        await server.call_tool("get_exploit", {"artifact_id": "!!"})

    rendered = str(caught.value)
    assert "artifact_id must be an artifact identifier" in rendered
    assert secret not in rendered
    assert "Traceback" not in rendered and "live_token" not in rendered


async def test_usage_guide_resource_serves_the_guide():
    server = create_mcp_server(SETTINGS, _StubTools())
    contents = list(await server.read_resource("eip://research/usage-guide"))
    assert contents[0].content == prompts.USAGE_GUIDE
    assert contents[0].mime_type == "text/markdown"


@pytest.mark.parametrize(
    "prompt_name,argument,value",
    [
        ("triage-cve", "cve_id", "CVE-2021-44228"),
        ("hunt-technique", "technique", "JNDI lookup"),
        ("screen-exploit-safety", "artifact_id", "abc-123"),
        ("corpus-report", "topic", "Apache"),
    ],
)
async def test_each_prompt_renders_its_argument(prompt_name, argument, value):
    server = create_mcp_server(SETTINGS, _StubTools())
    result = await server.get_prompt(prompt_name, {argument: value})
    text = result.messages[0].content.text
    assert value in text
    assert "EIP" in text or "corpus" in text


# The tool descriptions are what a model reads when choosing a tool, so they are
# the main defence against misuse. They must never imply EIP vouches for an
# exploit. Phrases match `tests/test_no_derived_judgments.py`; prompt bodies are
# excluded on purpose, since they legitimately carry negated forms such as
# "never advise that the code is safe to execute".
BANNED_DESCRIPTION_PHRASES = (
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
)


async def test_tool_descriptions_make_no_quality_claim():
    server = create_mcp_server(SETTINGS, _StubTools())
    for tool in await server.list_tools():
        lowered = tool.description.lower()
        for phrase in BANNED_DESCRIPTION_PHRASES:
            assert phrase not in lowered, f"{tool.name} description claims {phrase!r}"


# --------------------------------------------------------------------------
# Round 3, important 5 and 6: a description that misstates the tool it describes
# sends the model to the wrong query and lets it misread the answer.
# --------------------------------------------------------------------------


async def _description(name: str) -> str:
    server = create_mcp_server(SETTINGS, _StubTools())
    return {tool.name: tool for tool in await server.list_tools()}[name].description


async def test_search_exploits_states_that_a_query_matches_linked_cve_identifiers():
    """`q=CVE-2021-44228` finds artifacts linked to that CVE; the old text denied it.

    Upstream matches `q` against the linked vulnerability identifiers exactly and
    case-insensitively, on top of the substring match. A description that lists only
    title/native id/url/author/owner tells a model this query cannot work, so the
    model does not try it.
    """
    description = await _description("search_exploits")
    assert "vulnerability identifier" in description
    assert "CVE-2021-44228" in description


async def test_search_exploits_states_the_edb_alias_form():
    assert "EDB-" in await _description("search_exploits")


async def test_search_exploits_states_what_a_source_date_means_per_source():
    """The filter is offered; without the rule the answer is unreadable."""
    description = await _description("search_exploits")
    assert "repository-creation time" in description
    assert "first Git commit that added the current module path" in description
    assert "never the module's disclosure date" in description
    assert "source-supplied publication time" in description


async def test_get_vulnerability_names_every_section_it_accepts():
    description = await _description("get_vulnerability")
    for section in fmt.VULN_SECTIONS:
        assert section in description, f"section {section} is not advertised"


async def test_discarding_a_client_inside_a_running_loop_warns_about_nothing():
    """`asyncio.run(coro)` built the coroutine and *then* raised, leaving it
    un-awaited - a RuntimeWarning emitted while a construction failure is already
    propagating, which is the worst moment to add noise to an operator's log."""
    import warnings

    from eip_mcp_v3.api_client import EipApiClient
    from eip_mcp_v3.server import _discard_client

    client = EipApiClient(SETTINGS)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _discard_client(client)
        await asyncio.sleep(0)
    unawaited = [w for w in caught if "never awaited" in str(w.message)]
    assert not unawaited, [str(w.message) for w in unawaited]
    assert client._client.is_closed


def test_discarding_a_client_outside_a_loop_closes_it_without_warning():
    import warnings

    from eip_mcp_v3.api_client import EipApiClient
    from eip_mcp_v3.server import _discard_client

    client = EipApiClient(SETTINGS)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _discard_client(client)
    assert not [w for w in caught if "never awaited" in str(w.message)]
    assert client._client.is_closed


# `_a_flag` was hand-written and drifted from pydantic in BOTH directions - the
# exact class `_bounded_int` was rewritten to eliminate. It narrowed ("y"/"n"/"t"/
# "f" and 1.0, all of which pydantic accepts, and a JSON `1.0` literal arrives as
# a float) and it widened (" true ", because it called .strip() and pydantic does
# not, while the published schema says "type": "boolean").
BOOLEAN_INPUTS = [
    "y", "n", "t", "f", "Y", "N", "T", "F", 1.0, 0.0, " true ", "  yes",
    "true", "false", "on", "off", 1, 0, "TRUE", "maybe", 2, None, [],
]


@pytest.mark.parametrize("value", BOOLEAN_INPUTS, ids=[repr(v) for v in BOOLEAN_INPUTS])
async def test_a_flag_accepts_exactly_what_pydantic_accepts(value):
    """Delegation, asserted as an identity against pydantic itself."""
    from pydantic import TypeAdapter

    try:
        TypeAdapter(bool).validate_python(value)
        pydantic_accepts = True
    except Exception:
        pydantic_accepts = False

    server = create_mcp_server(SETTINGS, _StubTools())
    try:
        await server.call_tool("search_vulnerabilities", {"cisa_kev": value})
        server_accepts = True
    except ToolError:
        server_accepts = False

    assert server_accepts == pydantic_accepts, (
        f"{value!r}: pydantic {'accepts' if pydantic_accepts else 'rejects'}, "
        f"server {'accepts' if server_accepts else 'rejects'}"
    )


async def test_a_rejected_flag_still_reads_like_this_servers_own_error():
    server = create_mcp_server(SETTINGS, _StubTools())
    with pytest.raises(ToolError, match="cisa_kev must be true or false") as raised:
        await server.call_tool("search_vulnerabilities", {"cisa_kev": "maybe"})
    for internal in PYDANTIC_INTERNALS:
        assert internal not in str(raised.value)


# `_a_string` and `_a_string_list` were added to stop pydantic internals reaching
# the wire on plain text/list parameters - and shipped with no test of their own,
# so widening either to accept the wrong type left the suite green while a
# version-pinned errors.pydantic.dev URL went back on the wire.
WRONG_TYPE_PROBES = [
    ("search_vulnerabilities", "query", {"a": 1}, "query must be text"),
    ("search_vulnerabilities", "cwe", ["CWE-79"], "cwe must be text"),
    ("search_vulnerabilities", "cursor", 42, "cursor must be text"),
    ("search_vulnerabilities", "severity", "CRITICAL", "severity must be a list"),
    ("search_vulnerabilities", "severity", [1, 2], "severity must be a list"),
    ("search_vulnerabilities", "severity", 7, "severity must be a list"),
    ("search_exploits", "language", {"x": 1}, "language must be text"),
    ("search_exploits", "source_date_from", 20200101, "source_date_from must be text"),
    ("get_vulnerability", "sections", "pocs", "sections must be a list"),
    ("get_vulnerability", "sections", [1], "sections must be a list"),
    ("get_exploit", "artifact_id", 123, "artifact_id must be text"),
    ("read_exploit_file", "path", ["a"], "path must be text"),
    ("search_exploit_code", "query", ["jndi"], "query must be text"),
]


@pytest.mark.parametrize(
    "tool_name,parameter,value,expected",
    WRONG_TYPE_PROBES,
    ids=[f"{t}.{p}={v!r}" for t, p, v, _ in WRONG_TYPE_PROBES],
)
async def test_a_wrong_typed_text_or_list_argument_is_refused_in_house_style(
    tool_name, parameter, value, expected
):
    server = create_mcp_server(SETTINGS, _StubTools())
    required = {
        "get_vulnerability": {"identifier": "CVE-2021-44228"},
        "get_exploit": {"artifact_id": "3505014494080483"},
        "read_exploit_file": {"artifact_id": "3505014494080483"},
        "search_exploit_code": {"query": "jndi"},
    }.get(tool_name, {})
    with pytest.raises(ToolError) as raised:
        await server.call_tool(tool_name, {**required, parameter: value})
    message = str(raised.value)
    assert expected in message, message
    for internal in PYDANTIC_INTERNALS:
        assert internal not in message, f"framework internals leaked: {message}"


@pytest.mark.parametrize(
    "tool_name,arguments",
    [
        ("search_vulnerabilities", {"query": "struts", "cwe": "CWE-79"}),
        ("search_vulnerabilities", {"severity": ["CRITICAL", "HIGH"]}),
        ("search_vulnerabilities", {"query": None, "cursor": None}),
        ("get_vulnerability", {"identifier": "CVE-2021-44228", "sections": ["pocs"]}),
        ("read_exploit_file", {"artifact_id": "3505014494080483", "path": "a.py"}),
    ],
)
async def test_correctly_typed_text_and_list_arguments_still_pass(tool_name, arguments):
    server = create_mcp_server(SETTINGS, _StubTools())
    await server.call_tool(tool_name, arguments)
