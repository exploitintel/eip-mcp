"""Command-line entrypoint. stdio by default, streamable HTTP behind a proxy.

Nothing here may write to stdout: under the stdio transport stdout carries the
JSON-RPC stream, and one stray byte corrupts the session. Diagnostics go to
stderr, which is also what MCP 2026-07-28 names as the migration for stdio
servers now that the protocol Logging feature is deprecated.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
from typing import Any

from mcp.server.transport_security import TransportSecuritySettings

from . import __version__
from .config import (
    DEFAULT_HTTP_HOST,
    DEFAULT_HTTP_PATH,
    DEFAULT_HTTP_PORT,
    HttpTransportSettings,
    Settings,
)
from .server import create_mcp_server

STDIO = "stdio"
STREAMABLE_HTTP = "streamable-http"

# `--host`, `--port` and `--path` default to None rather than to their values so
# that "not given" is distinguishable from "given the default". Under stdio they
# apply to nothing, and accepting them silently told an operator their flag had
# taken effect when it had not.
_HTTP_ONLY_FLAGS = (("--host", "host"), ("--port", "port"), ("--path", "path"))

# Names no resolver routes off-box. `localhost` is here because an operator types
# it far more often than 127.0.0.1 and it is not an address `ipaddress` can parse.
_LOOPBACK_NAMES = frozenset({"localhost", "ip6-localhost", "ip6-loopback"})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eip-mcp",
        description="MCP server for the Exploit Intelligence Platform v3 research API.",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"eip-mcp {__version__}",
    )
    parser.add_argument(
        "--api-base-url",
        default=None,
        help="Base URL of the EIP read API. Overrides EIP_API_BASE_URL.",
    )
    parser.add_argument(
        "--transport",
        default=STDIO,
        choices=[STDIO, STREAMABLE_HTTP],
        help=(
            "Transport to serve. stdio (default) is the local-process transport. "
            "streamable-http serves an HTTP endpoint and requires "
            "EIP_MCP_ALLOWED_HOSTS."
        ),
    )
    # The three below default to None so that `transport_kwargs` can tell an absent
    # flag from one set to its default value, and refuse them under stdio.
    parser.add_argument(
        "--host",
        default=None,
        help=(
            f"streamable-http only: address to bind. Default {DEFAULT_HTTP_HOST}. "
            "This server authenticates nothing; keep it on loopback behind a proxy."
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help=f"streamable-http only: port to bind. Default {DEFAULT_HTTP_PORT}.",
    )
    parser.add_argument(
        "--path",
        default=None,
        help=f"streamable-http only: HTTP path to serve MCP on. Default {DEFAULT_HTTP_PATH}.",
    )
    return parser


def transport_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    """Build the transport-specific keyword arguments for ``MCPServer.run``.

    stdio gets none. That is not an omission to tidy up later: stdio is what ships
    today and is registered in users' MCP configurations, so its call stays exactly
    the single-argument call it has always been.

    Raises ``ValueError`` with a message naming the variable or flag at fault, which
    ``main`` renders as a one-line configuration error.
    """
    if args.transport != STREAMABLE_HTTP:
        _reject_http_only_flags(args)
        return {}
    host = DEFAULT_HTTP_HOST if args.host is None else args.host
    port = DEFAULT_HTTP_PORT if args.port is None else args.port
    path = DEFAULT_HTTP_PATH if args.path is None else args.path
    if not path.startswith("/"):
        # Starlette asserts this deep inside routing, and an AssertionError here
        # would be a traceback on an operator typo. This codebase does not print
        # tracebacks: PoC access tokens live as frame locals elsewhere in it.
        raise ValueError(f"--path must start with '/', got {path!r}")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError(f"--port must be between 1 and 65535, got {port!r}")
    # `--path` was checked here from the start and `--port` was not, so the typo one
    # digit away from a valid port - `--port 130033` - went all the way into the
    # socket layer and came back as a multi-frame anyio/uvicorn traceback, which is
    # the outcome the comment above exists to prevent. `--port 0` was worse than a
    # traceback: it binds an *ephemeral* port and serves happily, so under
    # `Type=simple` the unit reports active while nothing can reach the address the
    # operator meant. Both are refused here.
    http = HttpTransportSettings.from_env()
    return {
        "host": host,
        "port": port,
        "streamable_http_path": path,
        # MCP 2026-07-28 removed protocol sessions, so there is no session state
        # worth keeping. Stateless also means a restart mid-conversation costs the
        # client nothing and no proxy needs session affinity.
        "stateless_http": True,
        "transport_security": TransportSecuritySettings(
            # Never disabled. Behind a proxy the Host header carries a name the
            # attacker may choose, and this middleware is the only thing that checks it.
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(http.allowed_hosts),
            allowed_origins=list(http.allowed_origins),
        ),
    }


def _reject_http_only_flags(args: argparse.Namespace) -> None:
    """Refuse ``--host``/``--port``/``--path`` when they cannot possibly apply.

    They were accepted and dropped on the floor, so ``--port 13003`` alongside the
    default transport looked like it had configured something. There is no socket
    under stdio, and a flag that does nothing is worse than one that errors.
    """
    given = [flag for flag, attribute in _HTTP_ONLY_FLAGS if getattr(args, attribute) is not None]
    if not given:
        return
    flags = given[0] if len(given) == 1 else f"{', '.join(given[:-1])} and {given[-1]}"
    applies = "applies" if len(given) == 1 else "apply"
    them = "it" if len(given) == 1 else "them"
    raise ValueError(
        f"{flags} {applies} only to --transport {STREAMABLE_HTTP}, but the transport "
        f"is {args.transport}. Drop {them}, or pass --transport {STREAMABLE_HTTP}."
    )


def _is_loopback(host: str) -> bool:
    """Is this bind address one that nothing off the machine can reach?

    Anything unrecognised is treated as routable. A hostname this function cannot
    parse may well resolve to a public address, and the failure worth having is a
    warning an operator did not need, not a silent public bind.
    """
    candidate = host.strip().strip("[]").rstrip(".").lower()
    if candidate in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def warn_if_not_loopback(host: str) -> None:
    """Say so on stderr - never stdout - when the bind is not loopback.

    Not a refusal: a container's network namespace makes ``0.0.0.0`` the correct
    and only workable choice. But the defaults, the systemd unit and the
    self-hosting guide are all loopback for a reason, and nothing else in the
    process signals that this particular run left that behind.
    """
    if _is_loopback(host):
        return
    print(
        f"warning: binding {host}, which is not a loopback address. This server "
        "authenticates nothing and applies no quota or rate limit, so the endpoint "
        "is reachable and unmetered on every network that address reaches. Bind "
        f"{DEFAULT_HTTP_HOST} and put a proxy in front of it unless the network "
        "itself is already restricted.",
        file=sys.stderr,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    env = None
    if args.api_base_url:
        # Overlay, not replacement. A bare {"EIP_API_BASE_URL": ...} is the whole
        # environment as far as Settings.from_env is concerned, so every sibling
        # variable silently reverts to its default: a deliberate
        # EIP_MCP_TIMEOUT_SECONDS=120 became 30 the moment an operator pointed
        # the server at a different backend with this flag.
        env = {**os.environ, "EIP_API_BASE_URL": args.api_base_url}
    try:
        settings = Settings.from_env(env)
        # Before the server is built, so a misconfigured allowlist costs no
        # connection pool and cannot half-start an endpoint that answers to any Host.
        run_kwargs = transport_kwargs(args)
    except ValueError as exc:
        # The message, never the stack: PoC access tokens live as frame locals
        # elsewhere in this codebase, and a rendered traceback carries them.
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    if args.transport == STREAMABLE_HTTP:
        # After the configuration gate, so this only ever precedes a run that is
        # actually about to bind something.
        warn_if_not_loopback(run_kwargs["host"])
    server = create_mcp_server(settings)
    if args.transport == STREAMABLE_HTTP:
        _refuse_slash_redirects(server)
    try:
        server.run(transport=args.transport, **run_kwargs)
    except OSError as exc:
        # A port already bound, or an address the host does not own. Operator
        # error, not a defect, and the same no-traceback rule applies - but a
        # different exit code from a configuration error, because the unit file
        # treats a configuration error as terminal and this one as retryable.
        # stdio passes no host or port, and an OSError there is about the pipes,
        # not an address - "cannot serve on None:None" named a socket that was
        # never involved.
        where = (
            f" on {run_kwargs['host']}:{run_kwargs['port']}"
            if "host" in run_kwargs and "port" in run_kwargs
            else ""
        )
        print(f"cannot serve{where}: {exc}", file=sys.stderr)
        return 3
    return 0


def _refuse_slash_redirects(server: Any) -> None:
    """Stop Starlette answering ``/mcp/`` before the Host allowlist is consulted.

    The SDK applies its DNS-rebinding check *inside* the endpoint, not as ASGI
    middleware - its own TODO says so - while Starlette's ``redirect_slashes``
    runs first, in routing. So ``POST /mcp/`` with any ``Host`` at all returned
    ``307`` with ``location: http://<that host>/mcp``: the allowlist bypassed, and
    an attacker-chosen name reflected verbatim into a redirect. ``POST /mcp``
    correctly gives ``421``, the invariant ``docs/self-hosting.md`` states.

    ``run()`` builds the app by calling ``self.streamable_http_app(...)``, so
    replacing that bound attribute lets the flag be cleared on the real app
    without reimplementing the transport's uvicorn setup. If a future SDK stops
    routing through this method the shim silently stops applying, so
    ``tests/test_entrypoint.py`` asserts the flag on the app it actually builds.
    """
    build = getattr(server, "streamable_http_app", None)
    if build is None:
        # A server that builds no Starlette app has no redirect to disable. Silently
        # skipping is safe *because* the behaviour is asserted directly on a real
        # server in tests/test_entrypoint.py - this branch cannot hide the fix
        # going missing, only avoid breaking a caller that never needed it.
        return

    def with_redirects_off(**kwargs: Any) -> Any:
        app = build(**kwargs)
        app.router.redirect_slashes = False
        return app

    server.streamable_http_app = with_redirects_off


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
