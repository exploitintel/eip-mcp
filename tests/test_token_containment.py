"""The PoC access token must never leave the process.

`tests/test_tools_content.py` checks one fixed sentinel against two happy paths.
That passes for the wrong reason if the token merely happens not to be rendered.
These tests check the property itself, on every channel this layer controls: a
freshly minted token per request, every recorded request line, every rendered
byte, every propagated error, and the object graph left behind afterwards.

A token that reaches a tool result reaches the model's context and the session
transcript, where it can be replayed for the whole of its 300-second life.
"""

import json
import traceback

import httpx2
import pytest

from eip_mcp_v3.api_client import EipApiClient
from eip_mcp_v3.config import Settings
from eip_mcp_v3.errors import ApiError, ApiInvalidRequest, ApiNotFound, ApiUnavailable
from eip_mcp_v3.tools import EipTools

# Artifact ids are minted only by eip-loader-v3's `artifact_id()`, which returns a
# uuid5. `tools.py` now requires that shape, so a stand-in must have it too.
ARTIFACT = "abc12300-0000-5000-8000-000000000123"

SETTINGS = Settings(api_base_url="http://api.test", max_output_chars=50_000)

FILES = {
    "artifact_id": ARTIFACT,
    "items": [{"path": "exploit.py", "size": 100, "sha256": "sha256:aa", "viewable": True}],
}
CONTENT = {
    "artifact_id": ARTIFACT,
    "path": "exploit.py",
    "sha256": "sha256:aa",
    "content": "print('hello')",
}


class Recorder:
    """A mock API that mints a distinct token per grant and records every request.

    Distinct tokens matter: a suite that only ever checks one constant cannot
    tell "never rendered" from "rendered once, off-page, and not asserted on".
    """

    def __init__(
        self,
        routes: dict | None = None,
        access: dict | None = None,
        failure: tuple[str, int] | None = None,
        detail: str = "refused",
    ) -> None:
        self.routes = routes or {}
        self.access = access
        self.failure = failure
        # `{token}` is interpolated with the live grant, which is how a real API
        # that names the offending token in its rejection behaves.
        self.detail = detail
        self.tokens: list[str] = []
        self.requests: list[tuple[str, str, str]] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        body = request.content.decode() if request.content else ""
        self.requests.append((request.url.path, str(request.url), body))
        path = request.url.path
        if path == "/api/v1/poc-access":
            if self.access is not None:
                return httpx2.Response(200, json=self.access)
            token = f"tok_live_{len(self.tokens)}_2f8c1d9e4b7a6350"
            self.tokens.append(token)
            return httpx2.Response(200, json={"token": token, "expires_in": 300})
        if self.failure and self.failure[0] == path:
            detail = self.detail.format(token=self.tokens[-1] if self.tokens else "")
            return httpx2.Response(self.failure[1], json={"detail": detail})
        if path not in self.routes:
            return httpx2.Response(404, json={"detail": "not found"})
        return httpx2.Response(200, json=self.routes[path])

    @property
    def token(self) -> str:
        assert self.tokens, "no token was ever minted; the test proves nothing"
        return self.tokens[-1]

    def tools(self) -> EipTools:
        return EipTools(EipApiClient(SETTINGS, transport=httpx2.MockTransport(self)), SETTINGS)


def reachable_text(root: object, depth: int = 4) -> str:
    """Flatten the object graph hanging off ``root`` into searchable text."""
    seen: set[int] = set()
    chunks: list[str] = []

    def walk(obj: object, level: int) -> None:
        if level < 0 or id(obj) in seen:
            return
        seen.add(id(obj))
        if isinstance(obj, (str, bytes)):
            chunks.append(obj.decode(errors="replace") if isinstance(obj, bytes) else obj)
            return
        if isinstance(obj, dict):
            for key, value in obj.items():
                walk(key, level - 1)
                walk(value, level - 1)
            return
        if isinstance(obj, (list, tuple, set, frozenset)):
            for value in obj:
                walk(value, level - 1)
            return
        if isinstance(obj, BaseException):
            walk(obj.args, level - 1)
            walk(obj.__cause__, level - 1)
            walk(obj.__context__, level - 1)
        state = getattr(obj, "__dict__", None)
        if isinstance(state, dict):
            walk(state, level - 1)
        else:
            chunks.append(repr(obj))

    walk(root, depth)
    return "\n".join(chunks)


def traceback_local_text(exc: BaseException) -> str:
    """Flatten data locals from this package's traceback frames.

    Walking ``self`` would reach test-only recorder state that intentionally stores
    issued grants, so inspect the value-bearing locals that can actually retain a
    request: strings, bytes, and JSON-like containers.
    """
    chunks = []
    current = exc.__traceback__
    while current is not None:
        frame = current.tb_frame
        if "/eip_mcp_v3/" in frame.f_code.co_filename:
            for value in frame.f_locals.values():
                if isinstance(value, (str, bytes, dict, list, tuple, set, frozenset)):
                    chunks.append(reachable_text(value, depth=8))
        current = current.tb_next
    return "\n".join(chunks)


# --------------------------------------------------------------------------
# The token must not reach the tool result.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", [None, "exploit.py"])
async def test_minted_token_never_appears_in_the_tool_result(path):
    api = Recorder({"/api/v1/poc-files": FILES, "/api/v1/poc-file": CONTENT})
    out = await api.tools().read_exploit_file(ARTIFACT, path=path)
    assert api.tokens, "no token was minted, so nothing was proven"
    for token in api.tokens:
        assert token not in out


async def test_each_read_mints_a_fresh_token_and_none_of_them_render():
    api = Recorder({"/api/v1/poc-files": FILES, "/api/v1/poc-file": CONTENT})
    tools = api.tools()
    outputs = [
        await tools.read_exploit_file(ARTIFACT),
        await tools.read_exploit_file(ARTIFACT, path="exploit.py"),
        await tools.read_exploit_file(ARTIFACT),
    ]
    assert len(set(api.tokens)) == 3, "a cached token would outlive its grant"
    for token in api.tokens:
        assert all(token not in out for out in outputs)


async def test_token_echoed_back_in_unrendered_fields_does_not_reach_the_result():
    """The API echoing the grant back must not turn the render into a dict dump."""
    api = Recorder()
    api.routes = {
        "/api/v1/poc-files": {**FILES, "token": "PLACEHOLDER", "authorization": "PLACEHOLDER"},
        "/api/v1/poc-file": {**CONTENT, "token": "PLACEHOLDER", "access_token": "PLACEHOLDER"},
    }

    original = api.__call__

    def echoing(request: httpx2.Request) -> httpx2.Response:
        response = original(request)
        if request.url.path in api.routes and api.tokens:
            payload = json.loads(response.content)
            for key in ("token", "authorization", "access_token"):
                if key in payload:
                    payload[key] = api.token
            return httpx2.Response(200, json=payload)
        return response

    tools = EipTools(EipApiClient(SETTINGS, transport=httpx2.MockTransport(echoing)), SETTINGS)
    listing = await tools.read_exploit_file(ARTIFACT)
    content = await tools.read_exploit_file(ARTIFACT, path="exploit.py")
    for token in api.tokens:
        assert token not in listing
        assert token not in content


async def test_token_echoed_into_a_rendered_field_is_scrubbed_from_the_result():
    """The final defence, for an API that puts the grant somewhere it is rendered.

    Nothing in the render path reads the token, so this cannot happen against a
    correct API. It is here because the guarantee must not rest on which keys a
    formatter happens to read today.
    """
    api = Recorder()

    def echoing(request: httpx2.Request) -> httpx2.Response:
        response = api(request)
        if request.url.path == "/api/v1/poc-files":
            return httpx2.Response(
                200,
                json={
                    "artifact_id": api.token,
                    "items": [{"path": api.token, "size": 1, "viewable": True}],
                },
            )
        if request.url.path == "/api/v1/poc-file":
            return httpx2.Response(200, json={**CONTENT, "content": f"key = {api.token}\n"})
        return response

    tools = EipTools(EipApiClient(SETTINGS, transport=httpx2.MockTransport(echoing)), SETTINGS)
    listing = await tools.read_exploit_file(ARTIFACT)
    content = await tools.read_exploit_file(ARTIFACT, path="exploit.py")
    for token in api.tokens:
        assert token not in listing
        assert token not in content
    # Visibly redacted, not silently dropped: the anomaly must be reportable.
    assert "[redacted access token]" in listing
    assert "[redacted access token]" in content


# --------------------------------------------------------------------------
# The token must not reach a URL, an unrelated endpoint, or an error.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", [None, "exploit.py"])
async def test_token_is_never_placed_in_a_url(path):
    """Query strings and paths are logged by proxies; a token belongs in a body."""
    api = Recorder({"/api/v1/poc-files": FILES, "/api/v1/poc-file": CONTENT})
    await api.tools().read_exploit_file(ARTIFACT, path=path)
    for _, url, _ in api.requests:
        for token in api.tokens:
            assert token not in url


async def test_token_is_sent_only_to_the_two_content_endpoints():
    api = Recorder({"/api/v1/poc-files": FILES, "/api/v1/poc-file": CONTENT})
    tools = api.tools()
    await tools.read_exploit_file(ARTIFACT)
    await tools.read_exploit_file(ARTIFACT, path="exploit.py")
    carried = {path for path, _, body in api.requests if any(t in body for t in api.tokens)}
    assert carried == {"/api/v1/poc-files", "/api/v1/poc-file"}


@pytest.mark.parametrize(
    ("endpoint", "status", "path"),
    [
        ("/api/v1/poc-files", 403, None),
        ("/api/v1/poc-files", 500, None),
        ("/api/v1/poc-file", 403, "exploit.py"),
        ("/api/v1/poc-file", 409, "exploit.py"),
        ("/api/v1/poc-file", 404, "exploit.py"),
    ],
)
async def test_propagated_errors_carry_no_token(endpoint, status, path):
    """A rejected or failed grant must not smuggle the token out in the error."""
    api = Recorder({"/api/v1/poc-files": FILES}, failure=(endpoint, status))
    with pytest.raises(ApiError) as excinfo:
        await api.tools().read_exploit_file(ARTIFACT, path=path)
    rendered = "".join(traceback.format_exception(type(excinfo.value), excinfo.value, excinfo.tb))
    for token in api.tokens:
        assert token not in str(excinfo.value)
        assert token not in repr(excinfo.value)
        assert token not in rendered
        assert all(token not in str(arg) for arg in excinfo.value.args)
        assert token not in traceback_local_text(excinfo.value)


@pytest.mark.parametrize(
    ("endpoint", "path"),
    [("/api/v1/poc-files", None), ("/api/v1/poc-file", "exploit.py")],
)
async def test_an_api_error_that_names_the_token_is_scrubbed_before_it_escapes(endpoint, path):
    """The one leak route a *correct* API plausibly takes.

    Token-validation errors are exactly where a server names the offending token,
    and the client copies the API's ``detail`` verbatim into the exception message.
    ``_scrub`` only ever ran on rendered output, so ``str(exc)`` and the formatted
    traceback carried a live credential into the model's context and the session
    transcript. The tests above missed it because their detail was ``"refused"``.
    """
    api = Recorder(
        {"/api/v1/poc-files": FILES},
        failure=(endpoint, 403),
        detail="access token {token} is not valid",
    )
    with pytest.raises(ApiError) as excinfo:
        await api.tools().read_exploit_file(ARTIFACT, path=path)
    assert api.tokens, "no token was minted, so nothing was proven"
    rendered = "".join(traceback.format_exception(type(excinfo.value), excinfo.value, excinfo.tb))
    for token in api.tokens:
        assert token not in str(excinfo.value)
        assert token not in repr(excinfo.value)
        assert token not in rendered
        assert all(token not in str(arg) for arg in excinfo.value.args)
        assert token not in traceback_local_text(excinfo.value)
    # Redacted visibly rather than swallowed: the anomaly stays reportable, and
    # the rest of the API's message survives for the model to act on.
    assert "[redacted access token] is not valid" in str(excinfo.value)


async def test_transport_failure_drops_the_token_bearing_request_graph():
    """A clean message must not hide a live token in the chained Request body."""
    api = Recorder()

    def transport(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/api/v1/poc-files":
            raise httpx2.ConnectError("connection lost", request=request)
        return api(request)

    tools = EipTools(EipApiClient(SETTINGS, transport=httpx2.MockTransport(transport)), SETTINGS)
    with pytest.raises(ApiUnavailable) as excinfo:
        await tools.read_exploit_file(ARTIFACT)

    assert api.tokens, "no token was minted, so nothing was proven"
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__context__ is None
    for token in api.tokens:
        assert token not in reachable_text(excinfo.value, depth=10)
        assert token not in traceback_local_text(excinfo.value)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (403, ApiError),
        (404, ApiNotFound),
        (422, ApiInvalidRequest),
        (500, ApiUnavailable),
        (429, ApiUnavailable),
    ],
)
async def test_scrubbing_an_error_preserves_its_type(status, expected):
    """Callers dispatch on the ApiError hierarchy; only the message may change."""
    api = Recorder(
        {"/api/v1/poc-files": FILES},
        failure=("/api/v1/poc-file", status),
        detail="grant {token} rejected",
    )
    with pytest.raises(ApiError) as excinfo:
        await api.tools().read_exploit_file(ARTIFACT, path="exploit.py")
    assert type(excinfo.value) is expected
    for token in api.tokens:
        assert token not in "".join(
            traceback.format_exception(type(excinfo.value), excinfo.value, excinfo.tb)
        )


async def test_token_is_not_retained_anywhere_after_the_call():
    """Nothing caches the grant: a later repr of the tools or client cannot dump it."""
    api = Recorder({"/api/v1/poc-file": CONTENT})
    tools = api.tools()
    await tools.read_exploit_file(ARTIFACT, path="exploit.py")
    residue = reachable_text(tools)
    for token in api.tokens:
        assert token not in residue
        assert token not in repr(tools.__dict__)


# --------------------------------------------------------------------------
# No grant is minted for a request that was never going to be made.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_path",
    [
        "../../../etc/passwd",
        "sub/../../etc/passwd",
        "..",
        "/etc/passwd",
        "/",
        "exploit\x00.py",
        "",
        "   ",
        "a" * 4097,
    ],
)
async def test_rejected_paths_mint_no_token_and_make_no_request(bad_path):
    api = Recorder({"/api/v1/poc-files": FILES, "/api/v1/poc-file": CONTENT})
    with pytest.raises(ValueError, match="path"):
        await api.tools().read_exploit_file(ARTIFACT, path=bad_path)
    assert api.requests == []
    assert api.tokens == []


@pytest.mark.parametrize(
    "bad_id",
    ["../../etc/passwd", "", "   ", "abc 123", "abc\n123", "a/../../poc-download"],
)
async def test_rejected_artifact_ids_mint_no_token_and_make_no_request(bad_id):
    api = Recorder({"/api/v1/poc-files": FILES})
    with pytest.raises(ValueError, match="artifact_id"):
        await api.tools().read_exploit_file(bad_id)
    assert api.requests == []


@pytest.mark.parametrize(
    "smuggled", ["a/../../poc-download", "abc-123/../poc-download", "abc/def", "abc/"]
)
async def test_an_artifact_id_cannot_express_a_path_at_all(smuggled):
    """`a/../../poc-download` used to satisfy ARTIFACT_ID_RE and reach the client.

    It was refused there, by the path allowlist - a single layer, and one that
    lives in a different module from the parameter it was guarding. The identifier
    pattern no longer admits "/", so no path can be *expressed*; the allowlist
    below is now the second layer rather than the only one. Nothing in the
    recorded corpus needs a slash: artifact ids are UUIDs and numeric ids.
    """
    api = Recorder({})
    with pytest.raises(ValueError, match="artifact_id"):
        await api.tools().get_exploit(smuggled)
    assert api.requests == []


async def test_the_path_allowlist_still_refuses_a_smuggled_path():
    """The second layer, exercised directly now that the first rejects it earlier."""
    client = EipApiClient(SETTINGS, transport=httpx2.MockTransport(Recorder({})))
    with pytest.raises(ValueError, match="not allowed"):
        await client.get("/api/v1/pocs/a/../../poc-download")


async def test_an_over_long_path_is_told_it_is_too_long_not_that_it_is_empty():
    """A model retrying on "path must be non-empty" would resend what it just sent."""
    api = Recorder({"/api/v1/poc-files": FILES})
    with pytest.raises(ValueError, match="at most 4096 characters"):
        await api.tools().read_exploit_file(ARTIFACT, path="a" * 4097)
    assert api.requests == []
    assert api.tokens == []


# --------------------------------------------------------------------------
# A malformed grant must fail inside the ApiError hierarchy.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "grant",
    [{"expires_in": 300}, {"token": None}, {"token": ""}, {"token": "   "}, {"token": 12345}],
)
async def test_malformed_grant_raises_an_api_error(grant):
    """A KeyError or a literal "None" token would escape the handlers' catch."""
    api = Recorder({"/api/v1/poc-files": FILES}, access=grant)
    with pytest.raises(ApiError):
        await api.tools().read_exploit_file(ARTIFACT)
    assert not any(path == "/api/v1/poc-files" for path, _, _ in api.requests)


@pytest.mark.parametrize("short", ["tok", "abcdefg", "  tok  "])
async def test_a_grant_too_short_to_scrub_is_refused_before_it_is_used(short):
    """`_scrub` leaves values under 8 characters alone, so such a token would survive.

    Closed by construction rather than by documented exception: a grant that short
    is refused before it is ever sent, so no path below has to be trusted to
    redact it.
    """
    api = Recorder({"/api/v1/poc-files": FILES}, access={"token": short, "expires_in": 300})
    with pytest.raises(ApiUnavailable) as raised:
        await api.tools().read_exploit_file(ARTIFACT)
    assert not any(path == "/api/v1/poc-files" for path, _, _ in api.requests)
    assert short.strip() not in traceback_local_text(raised.value)


async def test_a_grant_at_the_scrubbable_length_is_accepted():
    """The boundary holds in the other direction: 8 characters is usable."""
    api = Recorder({"/api/v1/poc-files": FILES}, access={"token": "tok_1234", "expires_in": 300})
    out = await api.tools().read_exploit_file(ARTIFACT)
    assert "exploit.py" in out
    assert "tok_1234" not in out


async def test_unexpected_token_path_exception_is_contained_and_token_free():
    token = "tok_live_unexpected_2f8c1d9e4b7a6350"

    class UnexpectedApi:
        async def post(self, path, body):
            if path == "/api/v1/poc-access":
                return {"token": token, "expires_in": 300}
            raise RecursionError(f"failed while handling {token}")

    tools = EipTools(UnexpectedApi(), SETTINGS)
    with pytest.raises(ApiUnavailable) as raised:
        await tools.read_exploit_file(ARTIFACT)

    assert token not in str(raised.value)
    assert token not in traceback_local_text(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


async def test_forbidden_token_path_remains_a_loud_programming_error():
    api = Recorder({})
    tools = api.tools()

    with pytest.raises(ValueError, match="path is not allowed") as raised:
        await tools._post_for_artifact("/api/v1/poc-download", ARTIFACT)

    assert api.tokens, "the token path was never entered"
    for token in api.tokens:
        assert token not in str(raised.value)
        assert token not in traceback_local_text(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
