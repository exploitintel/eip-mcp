"""Async HTTP client for the read-only EIP v3 public API."""

from __future__ import annotations

import json
import re
from typing import Any

import anyio
import httpx2

from . import __version__
from .config import Settings
from .errors import ApiError, ApiInvalidRequest, ApiNotFound, ApiUnavailable

_USER_AGENT = f"eip-mcp/{__version__}"
# A transport failure has to name the endpoint it failed against. "All connection
# attempts failed" says nothing a caller can act on, and during the v3 audit it made
# a client-side address-family mismatch - a config pointing at 127.0.0.1 while the
# only listener was on [::1] - indistinguishable from the API being down: every tool
# failed for an hour while the tunnel was healthy the whole time.
#
# The base URL comes from `EIP_API_BASE_URL`, which is operator configuration and not
# corpus data, so it is trusted text. It is still bounded: an environment variable is
# an arbitrary-length string, and a megabyte of it in an error message would reach
# the model's context and the session transcript.
_BASE_URL_MAX = 200

# The same reasoning, applied to the two strings that are actually upstream- rather
# than operator-controlled. `_detail` renders an error body the API sent and
# `_reason` an exception message built from it; neither passes through `cap()`,
# because a rejection is raised before any page is rendered. A 400 KB `detail`
# produced a 400,159-char tool result against a 40,000-char ceiling this server
# documents as absolute. A failure only has to be actionable, so both are cut far
# shorter than a page would be.
_ERROR_TEXT_MAX = 500

# The API owns bounded research pages, not bulk corpus transfer. Refuse an
# unexpectedly large decoded body before JSON parsing so a broken or hostile
# upstream cannot turn one MCP call into unbounded process memory. The limit is
# deliberately far above current API responses, including per-CVE STIX bundles.
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# The read-only boundary, enforced rather than described. Every endpoint this
# server is allowed to reach is listed here; anything else - most importantly
# /api/v1/poc-download, which this project explicitly refuses to expose - is a
# programming error in a later task and is refused before a request is built.
_ALLOWED_PATHS = tuple(
    re.compile(pattern)
    for pattern in (
        r"/health/ready",
        r"/api/v1/statistics",
        r"/api/v1/statistics/trends",
        r"/api/v1/vulnerabilities",
        r"/api/v1/vulnerabilities/[^/]+/stix",
        r"/api/v1/vulnerabilities/[^/]+",
        r"/api/v1/vendors",
        r"/api/v1/products",
        r"/api/v1/ecosystems",
        r"/api/v1/packages",
        r"/api/v1/weaknesses",
        r"/api/v1/weaknesses/[^/]+",
        r"/api/v1/authors",
        r"/api/v1/authors/[0-9]+",
        r"/api/v1/pocs",
        r"/api/v1/pocs/[^/]+",
        r"/api/v1/artifacts/[^/]+",
        r"/api/v1/labs",
        r"/api/v1/poc-access",
        r"/api/v1/poc-files",
        r"/api/v1/poc-file",
        r"/api/v1/poc-code-search",
    )
)
# A path segment may not smuggle a query, a fragment, or a traversal past the
# allowlist: "/api/v1/vulnerabilities/..%2f.." and "/api/v1/statistics?x" would
# otherwise satisfy a naive "[^/]+" segment match.
# Control characters are in the class for a different reason than the rest: a NUL
# or a newline in a path is not a traversal, it is a malformed URL, and httpx
# raises `InvalidURL` for it - which is not an `httpx2.HTTPError` and so escaped
# the ApiError hierarchy every tool relies on, reaching the client as a raw
# framework exception. Unreachable today because the identifier regexes gate every
# caller-supplied segment, but this function is documented as *the* boundary and a
# boundary that depends on its callers being careful is not one.
_SUSPICIOUS_PATH = re.compile(
    r"[?#]|(^|/)\.\.?(/|$)|%2f|%2e|[\x00-\x1f\x7f]|\s", re.IGNORECASE
)


def _detail(payload: Any) -> str:
    """Render an error body's ``detail`` as a sentence a caller can act on.

    FastAPI sends a *string* for the errors this server raises itself and a *list
    of objects* for every 422 its own validation produces. ``str()`` over the list
    put a raw Python repr into the model's context - ``[{'type': 'string_too_long',
    'loc': ['query', 'q'], 'msg': ..., 'input': '<the whole rejected value>'}]`` -
    which is unreadable and echoes the offending input straight back.

    Only ``loc`` and ``msg`` are kept. ``input`` is deliberately dropped: it is the
    caller's own value coming back, it can be arbitrarily large, and on a
    token-bearing endpoint it is the credential itself.
    """
    if not isinstance(payload, dict):
        return ""
    detail = payload.get("detail")
    if detail is None or detail == "" or detail == []:
        return ""
    if isinstance(detail, str):
        return _clip(detail)
    if not isinstance(detail, list):
        # A dict-shaped detail used to land here as a raw Python repr - the exact
        # thing the docstring above says this function exists to prevent - so it
        # is flattened to its own key/value pairs instead.
        if isinstance(detail, dict):
            return _clip(
                "; ".join(f"{key}: {value}" for key, value in detail.items())
            )
        return _clip(str(detail))
    parts = []
    for entry in detail:
        if not isinstance(entry, dict):
            parts.append(str(entry))
            continue
        location = ".".join(str(part) for part in entry.get("loc") or [] if part is not None)
        message = str(entry.get("msg") or entry.get("type") or "").strip()
        joined = ": ".join(part for part in (location, message) if part)
        if joined:
            parts.append(joined)
    return _clip("; ".join(parts))


def _target(base_url: str) -> str:
    """The configured endpoint, bounded, for a transport failure to name."""
    text = " ".join(str(base_url).split())
    return text[:_BASE_URL_MAX] if len(text) > _BASE_URL_MAX else text


def _reason(exc: Exception) -> str:
    """Why the transport failed, falling back to the exception's type.

    httpx raises several connect and timeout errors with an empty ``str()`` -
    ``ConnectTimeout()`` is the common one - and "EIP API timed out at http://…: "
    is a sentence that stops before it says anything.
    """
    return _clip(str(exc).strip() or type(exc).__name__)


def _number_of_seconds(seconds: float) -> str:
    """`30s`, not `30.0`: the unit is the whole point of the sentence."""
    return f"{seconds:g}s"


def _clip(text: str) -> str:
    """Bound upstream-controlled error text before it reaches the model."""
    if len(text) <= _ERROR_TEXT_MAX:
        return text
    return text[:_ERROR_TEXT_MAX] + f"… [truncated at {_ERROR_TEXT_MAX} chars]"


def _check_path(path: str) -> str:
    """Refuse any endpoint outside the read-only allowlist.

    Deliberately a ``ValueError`` and not an ``ApiError``: handlers catch the
    ``ApiError`` hierarchy and turn it into a friendly message, which would let a
    forbidden endpoint fail quietly. This must be loud, and it must fail before a
    request is ever built.
    """
    if not path.startswith("/") or _SUSPICIOUS_PATH.search(path):
        raise ValueError(f"EIP API path is not allowed: {path!r}")
    if not any(pattern.fullmatch(path) for pattern in _ALLOWED_PATHS):
        raise ValueError(f"EIP API path is not allowed: {path!r}")
    return path


def _encode(params: dict[str, Any] | None) -> dict[str, Any]:
    """Drop None values and render booleans the way FastAPI expects."""
    if not params:
        return {}
    encoded: dict[str, Any] = {}
    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, bool):
            encoded[key] = "true" if value else "false"
        elif isinstance(value, (list, tuple)):
            if value:
                encoded[key] = list(value)
        else:
            encoded[key] = value
    return encoded


class EipApiClient:
    """Thin async wrapper over the public API. Read-only by construction."""

    # How much longer than one operation a whole call may take. The per-operation
    # timeout is the right bound for a stalled socket; the total deadline exists
    # for an upstream that stays just inside it forever. The multiple is generous
    # so that a large, genuinely slow file read is never cut short - the deadline
    # is there to make a hang terminate at all, not to make it prompt.
    _DEADLINE_MULTIPLE = 4

    def __init__(self, settings: Settings, transport: Any | None = None) -> None:
        self._target = _target(settings.api_base_url)
        self._deadline_seconds = settings.request_timeout_seconds * self._DEADLINE_MULTIPLE
        self._request_capacity = settings.max_concurrent_api_requests
        self._request_slots: anyio.CapacityLimiter | None = None
        self._client = httpx2.AsyncClient(
            base_url=settings.api_base_url,
            timeout=settings.request_timeout_seconds,
            headers={
                "user-agent": _USER_AGENT,
                "accept": "application/json",
                # Enforce the response ceiling over bytes the transport actually
                # reads. httpx decodes gzip before `aiter_bytes()` yields a chunk,
                # so an encoded response could allocate its expanded chunk before
                # the length check below. This adapter needs no compression on its
                # bounded, local/API-facing responses.
                "accept-encoding": "identity",
            },
            transport=transport,
        )

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return await self._request("GET", path, params=_encode(params))

    async def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return await self._request("POST", path, json=body)

    def _limiter(self) -> anyio.CapacityLimiter:
        """Create the backend-bound limiter only after an async backend exists."""
        if self._request_slots is None:
            self._request_slots = anyio.CapacityLimiter(self._request_capacity)
        return self._request_slots

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        """One request, bounded in total elapsed time as well as per operation.

        httpx's timeouts are per *operation* - connect, read one chunk, write -
        so an upstream that keeps sending a byte just inside every read window
        never trips any of them. Three shapes did exactly that and ran forever: a
        slow status line, a chunked body that never terminates, and a
        Content-Length body dripped a byte at a time. `EIP_MCP_TIMEOUT_SECONDS`
        read as a bound on the call and was not one, and the never-terminating
        chunked case also buffers without limit while it hangs.

        `config.py` already refuses `inf` on the grounds that "'inf' is a hang
        that never surfaces as an error"; without a total deadline a finite value
        produced the same hang.
        """
        _check_path(path)
        try:
            # One enthusiastic MCP client can issue many parallel tool calls. The
            # public API and PostgreSQL remain shared resources, so bound this
            # adapter's fan-out and let excess calls wait instead of creating an
            # avoidable connection storm. The existing whole-call deadline also
            # bounds time spent waiting for a slot, so overload fails explicitly
            # instead of turning into an indefinitely queued MCP call.
            with anyio.fail_after(self._deadline_seconds):
                async with self._limiter():
                    async with self._client.stream(method, path, **kwargs) as response:
                        status_code = response.status_code
                        body = await self._bounded_body(response)
        except TimeoutError as exc:
            raise ApiUnavailable(
                f"EIP API exceeded {_number_of_seconds(self._deadline_seconds)} at "
                f"{self._target}: the request did not complete in time"
            ) from exc
        except httpx2.TimeoutException as exc:
            raise ApiUnavailable(f"EIP API timed out at {self._target}: {_reason(exc)}") from exc
        except httpx2.HTTPError as exc:
            raise ApiUnavailable(
                f"EIP API unreachable at {self._target}: {_reason(exc)}"
            ) from exc
        return self._parse(status_code, body)

    async def _bounded_body(self, response: httpx2.Response) -> bytes:
        """Read one decoded response body with a hard memory ceiling."""
        encoding = response.headers.get("content-encoding", "identity").strip().casefold()
        if encoding not in ("", "identity"):
            raise ApiUnavailable(
                f"EIP API response at {self._target} used unsupported content encoding"
            )
        declared = response.headers.get("content-length")
        if declared is not None:
            try:
                declared_size = int(declared)
            except ValueError:
                declared_size = -1
            if declared_size > _MAX_RESPONSE_BYTES:
                raise ApiUnavailable(
                    f"EIP API response at {self._target} exceeds the "
                    f"{_MAX_RESPONSE_BYTES:,}-byte safety limit"
                )

        body = bytearray()
        async for chunk in response.aiter_bytes():
            if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                raise ApiUnavailable(
                    f"EIP API response at {self._target} exceeds the "
                    f"{_MAX_RESPONSE_BYTES:,}-byte safety limit"
                )
            body.extend(chunk)
        return bytes(body)

    @staticmethod
    def _parse(status_code: int, body: bytes) -> dict[str, Any]:
        if status_code == 200:
            try:
                payload = json.loads(body)
            except ValueError as exc:
                raise ApiUnavailable(
                    "EIP API returned a non-JSON body on a 200 response"
                ) from exc
            # A JSON array or scalar would satisfy `response.json()` but not the
            # annotation, and every downstream formatter calls .get() on this. An
            # AttributeError there is outside the ApiError hierarchy handlers catch,
            # which is the exact failure that hierarchy exists to prevent.
            if not isinstance(payload, dict):
                raise ApiUnavailable(
                    "EIP API returned an unexpected body shape on a 200 response: "
                    f"expected a JSON object, got {type(payload).__name__}"
                )
            return payload
        detail = ""
        try:
            detail = _detail(json.loads(body))
        except ValueError:
            detail = ""
        if status_code == 404:
            raise ApiNotFound(detail or "not found")
        if status_code in (400, 422):
            message = detail or "invalid request"
            if "cursor" in message.casefold() and "next_cursor" not in message:
                message += (
                    ". Use only an opaque next_cursor returned by the previous page, "
                    "and repeat every other argument, including limit, unchanged"
                )
            raise ApiInvalidRequest(message)
        if status_code in (403, 409):
            raise ApiError(detail or f"request refused ({status_code})")
        # Rate limiting is a transient condition the caller should retry, which is
        # what ApiUnavailable means; a bare ApiError reads as permanent.
        if status_code == 429:
            raise ApiUnavailable(detail or "EIP API rate limit exceeded; retry shortly")
        if status_code >= 500:
            raise ApiUnavailable(detail or f"EIP API error ({status_code})")
        raise ApiError(detail or f"unexpected status {status_code}")

    async def aclose(self) -> None:
        await self._client.aclose()
