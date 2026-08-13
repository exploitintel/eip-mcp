import gzip

import anyio
import httpx2
import pytest

import eip_mcp_v3.api_client as api_client_module
from eip_mcp_v3 import __version__
from eip_mcp_v3.api_client import EipApiClient
from eip_mcp_v3.config import Settings
from eip_mcp_v3.errors import ApiError, ApiInvalidRequest, ApiNotFound, ApiUnavailable

SETTINGS = Settings(api_base_url="http://api.test", request_timeout_seconds=5.0)


def client_for(handler) -> EipApiClient:
    return EipApiClient(SETTINGS, transport=httpx2.MockTransport(handler))


def test_client_construction_does_not_require_an_async_backend():
    client = client_for(lambda request: httpx2.Response(200, json={}))
    assert client._request_slots is None
    anyio.run(client.aclose)


async def test_get_returns_json():
    def handler(request):
        assert request.url.path == "/api/v1/statistics"
        assert request.headers["accept-encoding"] == "identity"
        assert request.headers["user-agent"] == f"eip-mcp/{__version__}"
        return httpx2.Response(200, json={"vulnerabilities": 3})

    client = client_for(handler)
    assert await client.get("/api/v1/statistics") == {"vulnerabilities": 3}
    await client.aclose()


async def test_get_passes_params_and_drops_none():
    seen = {}

    def handler(request):
        seen["query"] = str(request.url.query, "utf-8")
        return httpx2.Response(200, json={})

    client = client_for(handler)
    await client.get("/api/v1/vulnerabilities", {"limit": 25, "q": None, "cisa_kev": True})
    await client.aclose()
    assert "limit=25" in seen["query"]
    assert "q=" not in seen["query"]
    assert "cisa_kev=true" in seen["query"]


async def test_404_raises_not_found():
    client = client_for(lambda request: httpx2.Response(404, json={"detail": "not found"}))
    with pytest.raises(ApiNotFound):
        await client.get("/api/v1/vulnerabilities/CVE-0000-0000")
    await client.aclose()


async def test_422_raises_invalid_request_with_detail():
    client = client_for(lambda request: httpx2.Response(422, json={"detail": "invalid CWE"}))
    with pytest.raises(ApiInvalidRequest, match="invalid CWE"):
        await client.get("/api/v1/vulnerabilities")
    await client.aclose()


async def test_503_raises_unavailable():
    client = client_for(
        lambda request: httpx2.Response(503, json={"detail": "code search unavailable"})
    )
    with pytest.raises(ApiUnavailable, match="code search unavailable"):
        await client.post("/api/v1/poc-code-search", {"q": "x"})
    await client.aclose()


async def test_timeout_raises_unavailable():
    def handler(request):
        raise httpx2.TimeoutException("timed out")

    client = client_for(handler)
    with pytest.raises(ApiUnavailable, match="timed out|unreachable"):
        await client.get("/api/v1/statistics")
    await client.aclose()


# --------------------------------------------------------------------------
# Audit V-01: a transport failure named no target.
#
# `EIP API unreachable: All connection attempts failed` identifies neither the URL
# tried nor the address family. During the v3 audit that made a client-side
# IPv4/IPv6 mismatch - config on 127.0.0.1, the only listener on [::1] -
# indistinguishable from the API being down: every tool failed while the tunnel was
# healthy the whole time.
# --------------------------------------------------------------------------

_ELSEWHERE = Settings(api_base_url="http://127.0.0.1:59999", request_timeout_seconds=5.0)


def _dead(exc: Exception):
    def handler(request):
        raise exc

    return EipApiClient(_ELSEWHERE, transport=httpx2.MockTransport(handler))


@pytest.mark.parametrize(
    "exc,verb",
    [
        (httpx2.ConnectError("All connection attempts failed"), "unreachable"),
        (httpx2.TimeoutException("timed out"), "timed out"),
    ],
)
async def test_a_transport_failure_names_the_endpoint_it_failed_against(exc, verb):
    client = _dead(exc)
    with pytest.raises(ApiUnavailable) as raised:
        await client.get("/api/v1/statistics")
    await client.aclose()
    message = str(raised.value)
    assert "http://127.0.0.1:59999" in message, message
    assert verb in message


async def test_a_transport_failure_with_no_message_still_says_what_happened():
    """httpx raises several connect/timeout errors whose `str()` is empty."""
    client = _dead(httpx2.ConnectTimeout(""))
    with pytest.raises(ApiUnavailable) as raised:
        await client.get("/api/v1/statistics")
    await client.aclose()
    assert str(raised.value).rstrip().endswith("ConnectTimeout")
    assert "http://127.0.0.1:59999" in str(raised.value)


async def test_the_endpoint_named_in_an_error_is_bounded():
    """`EIP_API_BASE_URL` is operator configuration, so trusted - but not unbounded."""
    long_url = "http://" + "h" * 4000 + ".test"
    client = EipApiClient(
        Settings(api_base_url=long_url),
        transport=httpx2.MockTransport(lambda request: (_ for _ in ()).throw(
            httpx2.ConnectError("refused")
        )),
    )
    with pytest.raises(ApiUnavailable) as raised:
        await client.get("/api/v1/statistics")
    await client.aclose()
    assert len(str(raised.value)) < 400


async def test_403_raises_api_error_with_detail():
    client = client_for(
        lambda request: httpx2.Response(403, json={"detail": "PoC access token rejected"})
    )
    with pytest.raises(ApiError, match="PoC access token rejected"):
        await client.get("/api/v1/artifacts/some-id")
    await client.aclose()


async def test_409_raises_api_error_with_detail():
    client = client_for(
        lambda request: httpx2.Response(
            409, json={"detail": "PoC content integrity check failed"}
        )
    )
    with pytest.raises(ApiError, match="PoC content integrity check failed"):
        await client.post("/api/v1/poc-code-search", {"q": "x"})
    await client.aclose()


async def test_200_with_non_json_body_raises_unavailable():
    client = client_for(
        lambda request: httpx2.Response(
            200, content=b"<html>not json</html>", headers={"content-type": "text/html"}
        )
    )
    with pytest.raises(ApiUnavailable, match="non-JSON"):
        await client.get("/api/v1/statistics")
    await client.aclose()


# --------------------------------------------------------------------------
# Review finding 3: a 200 body that is not a JSON object.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body", [b"[]", b'[{"id": 1}]', b'"a string"', b"7", b"1.5", b"true", b"null"]
)
async def test_200_with_a_non_object_body_raises_unavailable(body):
    """`.get()` downstream would raise AttributeError, outside the ApiError hierarchy."""
    client = client_for(
        lambda request: httpx2.Response(
            200, content=body, headers={"content-type": "application/json"}
        )
    )
    with pytest.raises(ApiUnavailable, match="unexpected body shape"):
        await client.get("/api/v1/vulnerabilities")
    await client.aclose()


async def test_200_with_an_object_body_still_returns_the_dict():
    client = client_for(lambda request: httpx2.Response(200, json={"total": 415}))
    assert await client.get("/api/v1/statistics") == {"total": 415}
    await client.aclose()


# --------------------------------------------------------------------------
# Audit F-A1: a successful upstream response must not be buffered without limit.
# --------------------------------------------------------------------------


async def test_declared_response_larger_than_the_safety_limit_is_refused(monkeypatch):
    monkeypatch.setattr(api_client_module, "_MAX_RESPONSE_BYTES", 8)
    client = client_for(
        lambda request: httpx2.Response(
            200,
            content=b"{}",
            headers={"content-length": "9", "content-type": "application/json"},
        )
    )

    with pytest.raises(ApiUnavailable, match="8-byte safety limit"):
        await client.get("/api/v1/statistics")
    await client.aclose()


async def test_chunked_response_larger_than_the_safety_limit_is_refused(monkeypatch):
    class Chunks(httpx2.AsyncByteStream):
        async def __aiter__(self):
            yield b"1234"
            yield b"56789"

    monkeypatch.setattr(api_client_module, "_MAX_RESPONSE_BYTES", 8)
    client = client_for(
        lambda request: httpx2.Response(
            200,
            stream=Chunks(),
            headers={"content-type": "application/json"},
        )
    )

    with pytest.raises(ApiUnavailable, match="8-byte safety limit"):
        await client.get("/api/v1/statistics")
    await client.aclose()


async def test_response_at_the_safety_limit_still_parses(monkeypatch):
    monkeypatch.setattr(api_client_module, "_MAX_RESPONSE_BYTES", 2)
    client = client_for(lambda request: httpx2.Response(200, content=b"{}"))

    assert await client.get("/api/v1/statistics") == {}
    await client.aclose()


async def test_encoded_response_is_refused_before_transport_decoding(monkeypatch):
    expanded = b'{"value":"' + b"x" * 1_000_000 + b'"}'
    compressed = gzip.compress(expanded)
    assert len(compressed) < len(expanded) // 100
    monkeypatch.setattr(api_client_module, "_MAX_RESPONSE_BYTES", 2_000_000)
    client = client_for(
        lambda request: httpx2.Response(
            200,
            content=compressed,
            headers={
                "content-type": "application/json",
                "content-encoding": "gzip",
            },
        )
    )

    with pytest.raises(ApiUnavailable, match="unsupported content encoding"):
        await client.get("/api/v1/statistics")
    await client.aclose()


# --------------------------------------------------------------------------
# Review finding 8: the read-only boundary is an allowlist, not a comment.
# --------------------------------------------------------------------------

ALLOWED_PATHS = [
    "/health/ready",
    "/api/v1/statistics",
    "/api/v1/statistics/trends",
    "/api/v1/vulnerabilities",
    "/api/v1/vulnerabilities/CVE-2021-44228",
    "/api/v1/vulnerabilities/CVE-2021-44228/stix",
    "/api/v1/vendors",
    "/api/v1/products",
    "/api/v1/ecosystems",
    "/api/v1/packages",
    "/api/v1/weaknesses",
    "/api/v1/weaknesses/CWE-79",
    "/api/v1/pocs",
    "/api/v1/pocs/6f1c2b7e",
    "/api/v1/artifacts/6f1c2b7e",
    "/api/v1/labs",
    "/api/v1/poc-access",
    "/api/v1/poc-files",
    "/api/v1/poc-file",
    "/api/v1/poc-code-search",
]

REFUSED_PATHS = [
    "/api/v1/poc-download",
    "/api/v1/poc-download/6f1c2b7e",
    "/api/v1/admin",
    "/api/v1/statistics/trends/extra",
    "/api/v1/vulnerabilities/CVE-2021-44228/pocs",
    "/docs",
    "/",
    "",
    "api/v1/statistics",
    "http://evil.test/api/v1/statistics",
    "/api/v1/statistics?redirect=1",
    "/api/v1/statistics#frag",
    "/api/v1/pocs/../poc-download",
    "/api/v1/pocs/..%2f..%2fpoc-download",
    "/api/v1/pocs/.",
]


@pytest.mark.parametrize("path", ALLOWED_PATHS)
async def test_allowlisted_paths_are_permitted(path):
    client = client_for(lambda request: httpx2.Response(200, json={"ok": True}))
    assert await client.get(path) == {"ok": True}
    await client.aclose()


@pytest.mark.parametrize("path", REFUSED_PATHS)
async def test_paths_outside_the_allowlist_are_refused(path):
    reached = []

    def handler(request):
        reached.append(request.url.path)
        return httpx2.Response(200, json={})

    client = client_for(handler)
    with pytest.raises(ValueError, match="not allowed"):
        await client.get(path)
    with pytest.raises(ValueError, match="not allowed"):
        await client.post(path, {"q": "x"})
    # Refused before a request is ever built, so nothing reaches the network.
    assert reached == []
    await client.aclose()


async def test_poc_download_refusal_is_not_swallowed_as_an_api_error():
    """Handlers catch ApiError; a forbidden endpoint must not fail quietly through it."""
    client = client_for(lambda request: httpx2.Response(200, json={}))
    with pytest.raises(ValueError) as excinfo:
        await client.post("/api/v1/poc-download", {"artifact_id": "6f1c2b7e"})
    assert not isinstance(excinfo.value, ApiError)
    assert "poc-download" in str(excinfo.value)
    await client.aclose()


# --------------------------------------------------------------------------
# Review finding 9: 429 is retryable, so it is ApiUnavailable, not bare ApiError.
# --------------------------------------------------------------------------


async def test_429_raises_unavailable_with_detail():
    client = client_for(lambda request: httpx2.Response(429, json={"detail": "slow down"}))
    with pytest.raises(ApiUnavailable, match="slow down"):
        await client.get("/api/v1/statistics")
    await client.aclose()


async def test_429_without_detail_says_rate_limit():
    client = client_for(lambda request: httpx2.Response(429))
    with pytest.raises(ApiUnavailable, match="rate limit"):
        await client.get("/api/v1/statistics")
    await client.aclose()


# --------------------------------------------------------------------------
# Round 3, minor: a FastAPI 422 `detail` is a list, not a string.
#
# `str(payload.get("detail"))` rendered a raw Python repr of the validation error
# list into the exception message, which reaches the model's context and the
# session transcript. It is unreadable, and it echoes the caller's own rejected
# value straight back - on a token-bearing endpoint, that value is the credential.
# --------------------------------------------------------------------------

VALIDATION_DETAIL = [
    {
        "type": "string_too_long",
        "loc": ["body", "q"],
        "msg": "String should have at most 200 characters",
        "input": "SECRET-VALUE-THE-CALLER-SENT",
        "ctx": {"max_length": 200},
    },
    {
        "type": "greater_than_equal",
        "loc": ["body", "limit"],
        "msg": "Input should be greater than or equal to 1",
        "input": 0,
    },
]


async def test_422_validation_list_renders_as_readable_field_messages():
    client = client_for(lambda request: httpx2.Response(422, json={"detail": VALIDATION_DETAIL}))
    with pytest.raises(ApiInvalidRequest) as excinfo:
        await client.get("/api/v1/statistics")
    message = str(excinfo.value)
    assert "body.q: String should have at most 200 characters" in message
    assert "body.limit: Input should be greater than or equal to 1" in message


async def test_422_validation_list_is_not_a_python_repr():
    client = client_for(lambda request: httpx2.Response(422, json={"detail": VALIDATION_DETAIL}))
    with pytest.raises(ApiInvalidRequest) as excinfo:
        await client.get("/api/v1/statistics")
    message = str(excinfo.value)
    assert "[{" not in message and "'type':" not in message


async def test_422_validation_list_does_not_echo_the_rejected_input():
    """The offending value can be arbitrarily large, and on /poc-file it is the token."""
    client = client_for(lambda request: httpx2.Response(422, json={"detail": VALIDATION_DETAIL}))
    with pytest.raises(ApiInvalidRequest) as excinfo:
        await client.get("/api/v1/statistics")
    assert "SECRET-VALUE-THE-CALLER-SENT" not in str(excinfo.value)


async def test_a_string_detail_is_still_passed_through_unchanged():
    client = client_for(
        lambda request: httpx2.Response(422, json={"detail": "invalid request value"})
    )
    with pytest.raises(ApiInvalidRequest, match="^invalid request value$"):
        await client.get("/api/v1/statistics")


async def test_a_cursor_error_explains_how_to_reuse_the_opaque_cursor():
    client = client_for(lambda request: httpx2.Response(422, json={"detail": "invalid cursor"}))
    with pytest.raises(ApiInvalidRequest) as raised:
        await client.get("/api/v1/statistics")
    message = str(raised.value)
    assert "next_cursor" in message
    assert "including limit" in message
    assert "unchanged" in message


async def test_an_empty_detail_list_falls_back_to_the_generic_message():
    client = client_for(lambda request: httpx2.Response(422, json={"detail": []}))
    with pytest.raises(ApiInvalidRequest, match="invalid request"):
        await client.get("/api/v1/statistics")


async def test_a_detail_of_an_unexpected_shape_still_reaches_the_caller():
    client = client_for(lambda request: httpx2.Response(400, json={"detail": {"code": 7}}))
    with pytest.raises(ApiInvalidRequest, match="code"):
        await client.get("/api/v1/statistics")


# `cap()` bounds a rendered page, but a failure is raised before any page exists -
# so these two upstream-controlled strings had nothing bounding them at all. A
# 400 KB `detail` produced a 400,159-char tool result against a 40,000 ceiling.
def test_an_enormous_upstream_detail_is_bounded():
    from eip_mcp_v3.api_client import _ERROR_TEXT_MAX, _detail

    for payload in (
        {"detail": "P" * 400_000},
        {"detail": [{"loc": ["query", "q"], "msg": "P" * 400_000}]},
        {"detail": ["P" * 400_000]},
    ):
        rendered = _detail(payload)
        assert len(rendered) < _ERROR_TEXT_MAX + 64, len(rendered)
        assert "truncated at" in rendered


def test_an_enormous_transport_reason_is_bounded():
    from eip_mcp_v3.api_client import _ERROR_TEXT_MAX, _reason

    rendered = _reason(RuntimeError("P" * 300_000))
    assert len(rendered) < _ERROR_TEXT_MAX + 64


def test_a_dict_shaped_detail_is_flattened_not_repr_ed():
    """The docstring says this function exists to keep Python reprs out of the
    model's context; a dict-shaped detail was the one shape still producing one."""
    from eip_mcp_v3.api_client import _detail

    rendered = _detail({"detail": {"weird": "shape"}})
    assert rendered == "weird: shape"
    assert "{" not in rendered and "'" not in rendered


async def test_a_response_that_never_completes_is_abandoned():
    """httpx times out per operation, so a byte-per-window drip never trips it.

    `config.py` refuses `inf` because "'inf' is a hang that never surfaces as an
    error". Without a total deadline a finite value produced the same hang.
    """
    import time

    import httpx2

    from eip_mcp_v3.api_client import EipApiClient

    async def never_finishes(request: httpx2.Request) -> httpx2.Response:
        # Bounded well above the deadline under test but far below any CI timeout:
        # an unbounded sleep meant that if the deadline regressed this HUNG rather
        # than failed, which hides the regression instead of reporting it.
        await anyio.sleep(30)
        raise AssertionError("the request was not abandoned; the deadline is gone")

    settings = Settings(api_base_url="http://api.test", request_timeout_seconds=0.25)
    client = EipApiClient(settings, transport=httpx2.MockTransport(never_finishes))
    started = time.monotonic()
    try:
        with pytest.raises(ApiUnavailable, match="did not complete in time"):
            await client.get("/api/v1/pocs")
    finally:
        await client.aclose()
    assert time.monotonic() - started < 30, "the call was not bounded at all"


async def test_client_bounds_parallel_api_fanout():
    active = 0
    maximum = 0

    async def handler(request):
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        await anyio.sleep(0.02)
        active -= 1
        return httpx2.Response(200, json={"ok": True})

    settings = Settings(
        api_base_url="http://api.test", max_concurrent_api_requests=2
    )
    client = EipApiClient(settings, transport=httpx2.MockTransport(handler))
    try:
        async with anyio.create_task_group() as tasks:
            for _ in range(12):
                tasks.start_soon(client.get, "/api/v1/statistics")
    finally:
        await client.aclose()
    assert maximum == 2


async def test_queued_request_shares_the_whole_call_deadline():
    entered = 0
    errors = []

    async def handler(request):
        nonlocal entered
        entered += 1
        await anyio.sleep(0.2)
        return httpx2.Response(200, json={"ok": True})

    async def call(client):
        try:
            await client.get("/api/v1/statistics")
        except ApiUnavailable as exc:
            errors.append(str(exc))

    settings = Settings(
        api_base_url="http://api.test",
        request_timeout_seconds=0.02,
        max_concurrent_api_requests=1,
    )
    client = EipApiClient(settings, transport=httpx2.MockTransport(handler))
    try:
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(call, client)
            tasks.start_soon(call, client)
    finally:
        await client.aclose()

    assert entered == 1, "the queued call bypassed the one-request capacity limit"
    assert len(errors) == 2
    assert all("did not complete in time" in error for error in errors)


# `_check_path` is documented as *the* boundary keeping /api/v1/poc-download out of
# reach. A control character in a path is not a traversal but a malformed URL, and
# httpx raises `InvalidURL` for it - not an `httpx2.HTTPError`, so it escaped the
# ApiError hierarchy and reached the client as a raw framework exception. A
# boundary that relies on its callers having already validated is not a boundary.
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/pocs/x\x00",
        "/api/v1/pocs/x\nX-Injected: 1",
        "/api/v1/pocs/x\r\nHost: evil",
        "/api/v1/pocs/x y",
        "/api/v1/pocs/\ttab",
        "/api/v1/pocs/x\x7f",
    ],
)
def test_a_path_carrying_a_control_character_is_refused_at_the_boundary(path):
    from eip_mcp_v3.api_client import _check_path

    with pytest.raises(ValueError, match="not allowed"):
        _check_path(path)


@pytest.mark.parametrize(
    "path",
    ["/api/v1/pocs", "/api/v1/vulnerabilities/CVE-2021-44228", "/health/ready",
     "/api/v1/poc-code-search", "/api/v1/authors", "/api/v1/authors/123"],
)
def test_an_ordinary_path_is_still_allowed(path):
    from eip_mcp_v3.api_client import _check_path

    _check_path(path)


async def test_a_control_character_never_reaches_the_transport():
    """The refusal must happen before a request is built, not inside httpx."""
    import httpx2

    from eip_mcp_v3.api_client import EipApiClient

    seen: list = []

    def handler(request):
        seen.append(request)
        return httpx2.Response(200, json={})

    client = EipApiClient(
        Settings(api_base_url="http://api.test"), transport=httpx2.MockTransport(handler)
    )
    try:
        with pytest.raises(ValueError, match="not allowed"):
            await client.get("/api/v1/pocs/x\x00")
    finally:
        await client.aclose()
    assert seen == [], "a malformed path reached the transport"
