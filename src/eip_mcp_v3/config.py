"""Runtime configuration for the EIP MCP server."""

from __future__ import annotations

import math
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import urlparse

DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_CONCURRENT_API_REQUESTS = 8
DEFAULT_API_BASE_URL = "https://exploit-intel.com"
# A safety valve against a pathological response, not a page-size policy: page
# size is already bounded by `limit`, which the API itself validates. At 20_000 the
# documented maxima could not render - against the recorded fixtures both a 100-row
# PoC page and a 100-row vulnerability page overrun it - so the top of the accepted
# 1-100 range was unreachable. 40_000 clears both with headroom, and
# fixture-derived measurements are a lower bound for real rows.
#
# get_vulnerability is the one surface a caller can deliberately push past this:
# all sections at section_limit=50 is hundreds of items in one result, and it lands
# well over the ceiling. Every section at the default depth fits, and so does any
# single section at 50 - except `nuclei`, whose templates each carry a description,
# an impact, a remediation, tags, authors, a CVSS vector, CWEs, a CPE, recon queries,
# references and their provenance, so fifty of them do not. Beyond that the valve
# cuts and `cap()` says so, naming `section_limit` as the knob, which is the
# intended outcome for a request that asks for that much at once.
#
# No character counts are written here on purpose. The figures this comment used to
# carry were stale within a few commits of every rendering change, and AGENTS.md
# forbids pinning them: `tests/test_tools.py` asserts the properties instead.
DEFAULT_MAX_OUTPUT_CHARS = 40_000
MIN_MAX_OUTPUT_CHARS = 4_096
_ALLOWED_SCHEMES = ("http", "https")

# Loopback, because the HTTP transport is meant to sit behind a proxy that
# terminates TLS and applies rate limiting. Nothing in this repo authenticates a
# request, so a process bound to a routable address is an unauthenticated,
# unlimited endpoint on the open internet.
DEFAULT_HTTP_HOST = "127.0.0.1"
# The SDK's own default for `run_streamable_http_async`, carried over rather than
# replaced: this repo has no view on which port a deployment should use, and the
# systemd unit passes one explicitly.
DEFAULT_HTTP_PORT = 8000
DEFAULT_HTTP_PATH = "/mcp"

# Not a wildcard. The SDK gives `*` no special meaning on its own - only a `:*`
# suffix is special, and even that is a prefix test rather than a port wildcard.
_WILDCARD = "*"


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable server settings resolved from the environment."""

    api_base_url: str
    request_timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS
    max_concurrent_api_requests: int = DEFAULT_MAX_CONCURRENT_API_REQUESTS

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        source = os.environ if env is None else env
        base_url = (source.get("EIP_API_BASE_URL") or "").strip() or DEFAULT_API_BASE_URL
        _require_http_url(base_url)
        timeout = _number(source, "EIP_MCP_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS, float)
        # float() happily accepts "nan" and "inf"; neither is a timeout, and "inf"
        # is a hang that never surfaces as an error.
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("EIP_MCP_TIMEOUT_SECONDS must be a positive, finite number")
        max_chars = _number(source, "EIP_MCP_MAX_OUTPUT_CHARS", DEFAULT_MAX_OUTPUT_CHARS, int)
        if max_chars < MIN_MAX_OUTPUT_CHARS:
            raise ValueError(
                f"EIP_MCP_MAX_OUTPUT_CHARS must be at least {MIN_MAX_OUTPUT_CHARS}"
            )
        max_concurrent = _number(
            source,
            "EIP_MCP_MAX_CONCURRENT_API_REQUESTS",
            DEFAULT_MAX_CONCURRENT_API_REQUESTS,
            int,
        )
        if not 1 <= max_concurrent <= 64:
            raise ValueError(
                "EIP_MCP_MAX_CONCURRENT_API_REQUESTS must be between 1 and 64"
            )
        return cls(
            api_base_url=base_url.rstrip("/"),
            request_timeout_seconds=timeout,
            max_output_chars=max_chars,
            max_concurrent_api_requests=max_concurrent,
        )


@dataclass(frozen=True, slots=True)
class HttpTransportSettings:
    """Host and origin allowlists for the streamable-HTTP transport.

    Separate from ``Settings`` on purpose: these are resolved only when HTTP is the
    selected transport. Folding them in would make ``EIP_MCP_ALLOWED_HOSTS``
    mandatory for the stdio server too, which needs neither and is what ships in
    users' MCP configurations today.

    ``allowed_hosts`` is normalised, not merely split; see ``_normalize_host_entries``.
    """

    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...] = ()

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> HttpTransportSettings:
        """Resolve the allowlists, refusing to produce a permissive configuration.

        The SDK enables DNS-rebinding protection by default and rejects every
        ``Host`` when ``allowed_hosts`` is empty. That is closed but operationally
        opaque: the process can start while every request receives 421. Requiring
        the public host configuration at startup turns that unusable state into an
        explicit operator error.
        """
        source = os.environ if env is None else env
        hosts = _string_list(source, "EIP_MCP_ALLOWED_HOSTS")
        if not hosts:
            raise ValueError(
                "EIP_MCP_ALLOWED_HOSTS is required for --transport streamable-http. "
                "Set it to every Host header value this endpoint answers to, "
                "comma-separated, as explicit 'name' and 'name:port' entries. "
                "DNS-rebinding protection is always on; an empty SDK allowlist rejects "
                "every Host, so the server refuses to start rather than run unusably."
            )
        if _WILDCARD in hosts:
            # Safe today and completely broken: the SDK compares the Host header to
            # this string, so only a request whose Host is literally "*" would pass
            # and every real name would get 421 - while the operator believes they
            # switched the check off. Refusing is the only reading that matches what
            # they meant.
            raise ValueError(
                "EIP_MCP_ALLOWED_HOSTS contains a bare '*', which does not disable "
                "the Host check. The SDK matches '*' literally, so only a request "
                "whose Host header is exactly '*' would be accepted and every real "
                "name would get 421. List the Host header values this endpoint "
                "answers to instead, for example "
                "'mcp.example.com,mcp.example.com:443'."
            )
        return cls(
            allowed_hosts=_normalize_host_entries(hosts),
            allowed_origins=_string_list(source, "EIP_MCP_ALLOWED_ORIGINS"),
        )


def _normalize_host_entries(entries: tuple[str, ...]) -> tuple[str, ...]:
    """Lowercase each allowlist entry and register it with and without the root dot.

    The SDK compares the ``Host`` header to these strings with ``==`` (plus a
    ``startswith`` test for a ``:*`` suffix). Nothing here can make the *header*
    case-insensitive without replacing that matcher, which would be loosening a
    security control to fix an ergonomics complaint. What is ours to normalise is
    the list we hand it, and two things follow:

    * An operator who writes ``MCP.Example.COM`` gets the lowercase form the wire
      actually carries, instead of an allowlist that silently matches nothing.
    * ``example.com`` and ``example.com.`` name the same host, so each entry is
      registered both ways. A client or resolver that appends the root dot is not
      reaching a different server and must not get a 421 - and an operator who
      writes the absolute form gets a no-op rather than a changed deployment.

    Neither widens what an attacker can reach: both forms resolve to the name the
    operator already listed. A ``Host`` header in mixed case still fails closed;
    that requirement is documented in ``docs/self-hosting.md`` rather than
    papered over here.
    """
    normalized: list[str] = []
    for entry in entries:
        host, port = _split_host_port(entry.lower())
        bare = host.rstrip(".")
        # An entry of "." or "..": stripping every dot leaves a blank host, which
        # would be an allowlist member matching an absent value. Keep it verbatim
        # so it matches nothing instead.
        candidates = (host + port,) if not bare else (bare + port, f"{bare}.{port}")
        for candidate in candidates:
            if candidate not in normalized:
                normalized.append(candidate)
    return tuple(normalized)


def _split_host_port(entry: str) -> tuple[str, str]:
    """Split a trailing ``:port`` or ``:*`` off an allowlist entry.

    Deliberately conservative: anything that is not a decimal port or the SDK's
    ``*`` suffix stays part of the host, so a bracketed IPv6 literal (``[::1]``)
    and an entry with a colon in some other position both survive untouched.
    """
    head, sep, tail = entry.rpartition(":")
    if sep and head and (tail == _WILDCARD or (tail.isascii() and tail.isdigit())):
        return head, sep + tail
    return entry, ""


def _string_list(source: Mapping[str, str], name: str) -> tuple[str, ...]:
    """Split a comma-separated setting, dropping blanks.

    Blanks are dropped rather than kept because an empty entry would be an
    allowlist member that matches an absent header value, which is the one thing
    these lists exist to reject. ``"a,,b"`` and a trailing comma are therefore
    typos with no security consequence, not silent holes.
    """
    raw = source.get(name)
    if raw is None:
        return ()
    return tuple(item.strip() for item in str(raw).split(",") if item.strip())


def _require_http_url(base_url: str) -> None:
    """Reject anything that is not an absolute http(s) URL.

    Without this the client happily accepts ``/etc/passwd`` or ``file:///…`` as a
    base URL, which turns an operator typo - or an attacker who can set one
    environment variable - into a local-file read whose contents flow into the
    model's context.
    """
    parsed = urlparse(base_url)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES or not parsed.netloc:
        raise ValueError(
            f"EIP_API_BASE_URL must be an absolute http:// or https:// URL, got {base_url!r}"
        )
    # A query or fragment on the base silently *replaces* the path the client
    # builds, so `http://host/?x=1` sends every request to `/?limit=5`: the path
    # allowlist then validates a path that never goes on the wire, which is the
    # one check standing between this server and `/api/v1/poc-download`.
    if parsed.query or parsed.fragment:
        raise ValueError(
            "EIP_API_BASE_URL must not carry a query string or fragment; it is a base "
            f"URL that request paths are appended to, got {base_url!r}"
        )
    # Userinfo becomes an `Authorization: Basic` header on every request, and the
    # base URL is quoted back verbatim on any transport failure - so a password
    # here reaches the model's context and the transcript. Credentials belong in a
    # proxy or a header, never in a value this server echoes.
    if parsed.username or parsed.password:
        raise ValueError(
            "EIP_API_BASE_URL must not embed credentials: this value is quoted back "
            "in error messages that reach the model. Put auth in a reverse proxy."
        )
    # `urlparse` defers port parsing, so an out-of-range port raises `ValueError`
    # from deep inside the transport instead of here, escaping the ApiError
    # hierarchy every tool relies on.
    try:
        port = parsed.port
    except ValueError:
        raise ValueError(
            f"EIP_API_BASE_URL has an invalid port; it must be 0-65535, got {base_url!r}"
        ) from None
    # 1, not 0: port 0 means "any free port" to the OS and is never an address a
    # client can reach, which is the same reason `--port 0` is refused.
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(f"EIP_API_BASE_URL port must be 1-65535, got {base_url!r}")


def _number[T](
    source: Mapping[str, str], name: str, default: T, convert: Callable[[str], T]
) -> T:
    """Read a numeric setting, naming the variable when the value will not parse.

    A bare ``float()``/``int()`` raises ``could not convert string to float: 'soon'``,
    which never tells the operator which variable to fix.
    """
    raw = source.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return convert(str(raw).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc
