import pytest
from mcp.server.transport_security import TransportSecuritySettings

from eip_mcp_v3 import __version__
from eip_mcp_v3.__main__ import build_parser, entrypoint, main, transport_kwargs
from eip_mcp_v3.config import DEFAULT_API_BASE_URL


def test_parser_defaults_to_stdio():
    args = build_parser().parse_args([])
    assert args.transport == "stdio"


def test_version_uses_the_canonical_distribution_identity(capsys):
    with pytest.raises(SystemExit) as caught:
        build_parser().parse_args(["--version"])
    assert caught.value.code == 0
    assert capsys.readouterr().out == f"eip-mcp {__version__}\n"


def test_parser_accepts_api_base_url():
    args = build_parser().parse_args(["--api-base-url", "http://127.0.0.1:13002"])
    assert args.api_base_url == "http://127.0.0.1:13002"


def test_parser_accepts_streamable_http():
    args = build_parser().parse_args(["--transport", "streamable-http"])
    assert args.transport == "streamable-http"


def test_parser_rejects_an_unknown_transport():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--transport", "sse"])


def test_main_uses_the_public_api_without_configuration(monkeypatch):
    monkeypatch.delenv("EIP_API_BASE_URL", raising=False)
    recorded: dict[str, object] = {}

    class _Server:
        def run(self, transport):
            recorded["transport"] = transport

    def _create(settings):
        recorded["base_url"] = settings.api_base_url
        return _Server()

    monkeypatch.setattr("eip_mcp_v3.__main__.create_mcp_server", _create)

    assert main([]) == 0
    assert recorded == {"base_url": DEFAULT_API_BASE_URL, "transport": "stdio"}


def test_configuration_error_names_the_offending_variable(capsys, monkeypatch):
    """An operator sees this one line and nothing else, so it must name the variable."""
    monkeypatch.setenv("EIP_API_BASE_URL", "http://127.0.0.1:13002")
    monkeypatch.setenv("EIP_MCP_TIMEOUT_SECONDS", "soon")
    assert main([]) == 2
    assert "EIP_MCP_TIMEOUT_SECONDS" in capsys.readouterr().err


def test_configuration_error_writes_nothing_to_stdout_and_no_traceback(capsys, monkeypatch):
    """stdout is the JSON-RPC stream; a stray byte there corrupts the session.

    The traceback check is not cosmetic: PoC access tokens live as frame locals
    elsewhere in this codebase, so no error path may ever render a stack.
    """
    monkeypatch.setenv("EIP_API_BASE_URL", "file:///etc/passwd")
    assert main([]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Traceback" not in captured.err
    assert "File \"" not in captured.err


def test_main_runs_the_stdio_transport(monkeypatch):
    monkeypatch.setenv("EIP_API_BASE_URL", "http://127.0.0.1:13002")
    recorded: dict[str, object] = {}

    class _Server:
        def run(self, transport):
            recorded["transport"] = transport

    def _create(settings):
        recorded["base_url"] = settings.api_base_url
        return _Server()

    monkeypatch.setattr("eip_mcp_v3.__main__.create_mcp_server", _create)

    assert main([]) == 0
    assert recorded == {"base_url": "http://127.0.0.1:13002", "transport": "stdio"}


def test_api_base_url_flag_preserves_sibling_environment(monkeypatch):
    """The flag overrides one variable, not the whole environment.

    `env` is the entire environment as far as Settings.from_env is concerned, so
    passing {"EIP_API_BASE_URL": ...} alone silently reverted every sibling to its
    default: a deliberate 120-second timeout became 30 at exactly the moment an
    operator pointed the server at a different backend.
    """
    monkeypatch.setenv("EIP_API_BASE_URL", "http://from-environment.test")
    monkeypatch.setenv("EIP_MCP_TIMEOUT_SECONDS", "120")
    monkeypatch.setenv("EIP_MCP_MAX_OUTPUT_CHARS", "9999")
    recorded: dict[str, object] = {}

    class _Server:
        def run(self, transport):
            recorded["transport"] = transport

    def _create(settings):
        recorded["settings"] = settings
        return _Server()

    monkeypatch.setattr("eip_mcp_v3.__main__.create_mcp_server", _create)

    assert main(["--api-base-url", "http://from-flag.test:13002"]) == 0

    settings = recorded["settings"]
    assert settings.api_base_url == "http://from-flag.test:13002"
    assert settings.request_timeout_seconds == 120.0
    assert settings.max_output_chars == 9999


def test_entrypoint_exits_with_mains_status(monkeypatch):
    monkeypatch.setenv("EIP_API_BASE_URL", "file:///etc/passwd")
    with pytest.raises(SystemExit) as caught:
        entrypoint()
    assert caught.value.code == 2


# --------------------------------------------------------------------------
# Streamable HTTP.
#
# The tests below drive `main` against a recording stand-in for MCPServer, so what
# they assert is the argument list the SDK is actually called with - not that a flag
# parsed. `tests/test_live.py` runs the real process over a real socket and drives
# it with the SDK's own HTTP client; these cover the wiring that lands there.
# --------------------------------------------------------------------------


class _RecordingServer:
    """Stands in for MCPServer, capturing exactly how `run` was called."""

    def __init__(self, recorded: dict[str, object]) -> None:
        self._recorded = recorded

    def run(self, transport, **kwargs):
        self._recorded["transport"] = transport
        self._recorded["kwargs"] = kwargs


@pytest.fixture
def recorded_run(monkeypatch):
    """Point `main` at a server that records its `run` call and never serves."""
    recorded: dict[str, object] = {}
    monkeypatch.setattr(
        "eip_mcp_v3.__main__.create_mcp_server", lambda settings: _RecordingServer(recorded)
    )
    monkeypatch.setenv("EIP_API_BASE_URL", "http://127.0.0.1:13002")
    return recorded


@pytest.fixture
def allowlisted(monkeypatch):
    monkeypatch.setenv("EIP_MCP_ALLOWED_HOSTS", "mcp.example.test")
    monkeypatch.delenv("EIP_MCP_ALLOWED_ORIGINS", raising=False)


def test_stdio_is_still_run_with_no_transport_options(recorded_run, monkeypatch):
    """stdio's call must not grow arguments; it is what ships in users' configs.

    The allowlist is set here on purpose: stdio must not start reading HTTP
    settings, and must not start refusing to boot when they are absent either -
    the following test covers the absent half.
    """
    monkeypatch.setenv("EIP_MCP_ALLOWED_HOSTS", "mcp.example.test")
    assert main([]) == 0
    assert recorded_run["transport"] == "stdio"
    assert recorded_run["kwargs"] == {}


def test_stdio_starts_without_any_http_settings(recorded_run, monkeypatch):
    monkeypatch.delenv("EIP_MCP_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("EIP_MCP_ALLOWED_ORIGINS", raising=False)
    assert main([]) == 0
    assert recorded_run["transport"] == "stdio"


def test_http_transport_is_run_stateless_on_the_requested_socket(
    recorded_run, allowlisted
):
    assert (
        main(["--transport", "streamable-http", "--host", "127.0.0.1", "--port", "13003"]) == 0
    )
    assert recorded_run["transport"] == "streamable-http"
    kwargs = recorded_run["kwargs"]
    assert kwargs["host"] == "127.0.0.1"
    assert kwargs["port"] == 13003
    assert kwargs["streamable_http_path"] == "/mcp"
    # MCP 2026-07-28 has no protocol sessions; stateless is what matches the spec
    # and what lets a restart mid-conversation cost the client nothing.
    assert kwargs["stateless_http"] is True


def test_http_transport_defaults_to_loopback(recorded_run, allowlisted):
    """Nothing in this repo authenticates a request, so the default must not route."""
    assert main(["--transport", "streamable-http"]) == 0
    assert recorded_run["kwargs"]["host"] == "127.0.0.1"


def test_http_transport_accepts_a_custom_path(recorded_run, allowlisted):
    assert main(["--transport", "streamable-http", "--path", "/eip/mcp"]) == 0
    assert recorded_run["kwargs"]["streamable_http_path"] == "/eip/mcp"


def test_allowlists_reach_transport_security_settings(recorded_run, monkeypatch):
    monkeypatch.setenv("EIP_MCP_ALLOWED_HOSTS", "mcp.example.test, mcp.example.test:443")
    monkeypatch.setenv("EIP_MCP_ALLOWED_ORIGINS", "https://mcp.example.test")
    assert main(["--transport", "streamable-http"]) == 0
    security = recorded_run["kwargs"]["transport_security"]
    assert isinstance(security, TransportSecuritySettings)
    assert security.enable_dns_rebinding_protection is True
    # Each entry reaches the middleware in both its plain and root-dot forms;
    # `tests/test_config.py` covers why.
    assert security.allowed_hosts == [
        "mcp.example.test",
        "mcp.example.test.",
        "mcp.example.test:443",
        "mcp.example.test.:443",
    ]
    assert security.allowed_origins == ["https://mcp.example.test"]


def test_protection_stays_on_and_origins_may_be_empty(recorded_run, allowlisted):
    """An empty origin allowlist denies every cross-origin browser request.

    That is the safe direction - the SDK's middleware lets an *absent* Origin
    through, which is every non-browser MCP client, and refuses any Origin not on
    the list. So the variable is optional and its absence is a deny, while
    `allowed_hosts` empty denies every Host and is refused at startup so an
    unusable endpoint cannot present as a healthy process.
    """
    assert main(["--transport", "streamable-http"]) == 0
    security = recorded_run["kwargs"]["transport_security"]
    assert security.enable_dns_rebinding_protection is True
    assert security.allowed_origins == []


def test_http_refuses_to_start_without_an_allowlist(recorded_run, capsys, monkeypatch):
    """A deployment that would answer every Host with 421 must not boot."""
    monkeypatch.delenv("EIP_MCP_ALLOWED_HOSTS", raising=False)
    assert main(["--transport", "streamable-http"]) == 2
    captured = capsys.readouterr()
    assert "EIP_MCP_ALLOWED_HOSTS" in captured.err
    assert captured.out == ""
    assert "Traceback" not in captured.err
    # The server must never have been asked to run.
    assert recorded_run == {}


@pytest.mark.parametrize("value", ["", "   ", ",", " , ,"])
def test_http_refuses_an_allowlist_that_is_blank_or_only_separators(
    recorded_run, capsys, monkeypatch, value
):
    """A trailing comma or a blanked-out variable is not an allowlist entry."""
    monkeypatch.setenv("EIP_MCP_ALLOWED_HOSTS", value)
    assert main(["--transport", "streamable-http"]) == 2
    assert "EIP_MCP_ALLOWED_HOSTS" in capsys.readouterr().err
    assert recorded_run == {}


def test_http_refuses_a_path_that_is_not_absolute(recorded_run, allowlisted, capsys):
    """Starlette asserts this deep in routing; an operator typo must not print a stack."""
    assert main(["--transport", "streamable-http", "--path", "mcp"]) == 2
    captured = capsys.readouterr()
    assert "--path" in captured.err
    assert "Traceback" not in captured.err
    assert recorded_run == {}


def test_transport_kwargs_are_empty_for_stdio():
    args = build_parser().parse_args([])
    assert transport_kwargs(args) == {}


# --------------------------------------------------------------------------
# Review: HTTP-only flags were accepted and silently ignored under stdio.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["--host", "0.0.0.0"],
        ["--port", "13003"],
        ["--path", "/eip/mcp"],
        ["--host", "127.0.0.1", "--port", "13003"],
        ["--transport", "stdio", "--port", "13003"],
    ],
)
def test_http_only_flags_are_refused_under_stdio(recorded_run, capsys, argv):
    """They applied to nothing. Saying so beats pretending they took effect."""
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert "streamable-http" in captured.err
    assert captured.out == ""
    assert "Traceback" not in captured.err
    assert recorded_run == {}


def test_the_stdio_rejection_names_every_flag_that_was_given(recorded_run, capsys):
    assert main(["--host", "0.0.0.0", "--port", "13003", "--path", "/x"]) == 2
    err = capsys.readouterr().err
    assert "--host" in err
    assert "--port" in err
    assert "--path" in err


def test_stdio_still_starts_when_no_http_flag_is_given(recorded_run):
    """The rejection must key off the flag being supplied, not off its default."""
    assert main([]) == 0
    assert recorded_run["transport"] == "stdio"
    assert recorded_run["kwargs"] == {}


def test_http_defaults_are_unchanged_by_the_sentinel_defaults(recorded_run, allowlisted):
    assert main(["--transport", "streamable-http"]) == 0
    kwargs = recorded_run["kwargs"]
    assert kwargs["host"] == "127.0.0.1"
    assert kwargs["port"] == 8000
    assert kwargs["streamable_http_path"] == "/mcp"


# --------------------------------------------------------------------------
# Review: binding a public interface produced no signal at all.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.10", "mcp.example.test"])
def test_a_non_loopback_bind_warns_on_stderr(recorded_run, allowlisted, capsys, host):
    """Nothing here authenticates a request, so a routable bind must say so."""
    assert main(["--transport", "streamable-http", "--host", host]) == 0
    captured = capsys.readouterr()
    assert "warning" in captured.err.lower()
    assert host in captured.err
    # Never refused: a container legitimately needs 0.0.0.0.
    assert recorded_run["kwargs"]["host"] == host


def test_the_bind_warning_never_touches_stdout(recorded_run, allowlisted, capsys):
    """stdout is the JSON-RPC stream under stdio; no diagnostic may ever go there."""
    assert main(["--transport", "streamable-http", "--host", "0.0.0.0"]) == 0
    assert capsys.readouterr().out == ""


def test_the_bind_warning_says_what_is_missing(recorded_run, allowlisted, capsys):
    assert main(["--transport", "streamable-http", "--host", "0.0.0.0"]) == 0
    err = capsys.readouterr().err.lower()
    assert "authentic" in err
    assert "proxy" in err


@pytest.mark.parametrize(
    "host", ["127.0.0.1", "127.0.0.53", "localhost", "localhost.", "::1", "[::1]"]
)
def test_a_loopback_bind_warns_about_nothing(recorded_run, allowlisted, capsys, host):
    assert main(["--transport", "streamable-http", "--host", host]) == 0
    assert capsys.readouterr().err == ""


def test_stdio_never_warns_about_a_bind(recorded_run, capsys, monkeypatch):
    """There is no socket under stdio, so there is nothing to warn about."""
    monkeypatch.setenv("EIP_MCP_ALLOWED_HOSTS", "mcp.example.test")
    assert main([]) == 0
    assert capsys.readouterr().err == ""


def test_a_public_bind_with_a_broken_allowlist_still_fails_before_warning(
    recorded_run, capsys, monkeypatch
):
    """Configuration errors come first; the warning is for a run that will happen."""
    monkeypatch.delenv("EIP_MCP_ALLOWED_HOSTS", raising=False)
    assert main(["--transport", "streamable-http", "--host", "0.0.0.0"]) == 2
    assert "EIP_MCP_ALLOWED_HOSTS" in capsys.readouterr().err
    assert recorded_run == {}


# --------------------------------------------------------------------------
# Review: a bare `*` allowlist entry looks like "off" and is not.
# --------------------------------------------------------------------------


def test_http_refuses_a_bare_wildcard_allowlist(recorded_run, capsys, monkeypatch):
    monkeypatch.setenv("EIP_MCP_ALLOWED_HOSTS", "*")
    assert main(["--transport", "streamable-http"]) == 2
    captured = capsys.readouterr()
    assert "EIP_MCP_ALLOWED_HOSTS" in captured.err
    assert captured.out == ""
    assert "Traceback" not in captured.err
    assert recorded_run == {}


# `--path` was validated from the start and `--port` was not, so `--port 130033`
# - one digit off a real port - went into the socket layer and came back as a
# multi-frame anyio/uvicorn traceback. This codebase does not print tracebacks:
# PoC access tokens live as frame locals elsewhere in it.
@pytest.mark.parametrize("port", [-1, 0, 65536, 99999, 130033])
def test_a_port_outside_the_valid_range_is_a_configuration_error(monkeypatch, capsys, port):
    monkeypatch.setenv("EIP_API_BASE_URL", "http://api.test")
    monkeypatch.setenv("EIP_MCP_ALLOWED_HOSTS", "mcp.example.test")
    # If the `--port` guard regresses, `--port 0` binds an EPHEMERAL socket and
    # serves forever, so this hung instead of failing - a regression hiding behind
    # CI's own timeout rather than showing up as a red test. Serving is made
    # impossible so the only reachable outcomes are "refused" and "would have run".
    def must_not_run(self, **kwargs):
        raise AssertionError(f"the entrypoint tried to serve on port {port}")

    monkeypatch.setattr("mcp.server.MCPServer.run", must_not_run)
    status = main(["--transport", "streamable-http", "--port", str(port)])
    assert status == 2
    err = capsys.readouterr().err
    assert "--port must be between 1 and 65535" in err
    assert "Traceback" not in err
    assert err.count("\n") == 1, f"a configuration error is one line, got: {err!r}"


@pytest.mark.parametrize("port", [1, 1024, 13003, 65535])
def test_a_port_inside_the_range_is_accepted(monkeypatch, port):
    monkeypatch.setenv("EIP_API_BASE_URL", "http://api.test")
    monkeypatch.setenv("EIP_MCP_ALLOWED_HOSTS", "mcp.example.test")
    args = build_parser().parse_args(["--transport", "streamable-http", "--port", str(port)])
    assert transport_kwargs(args)["port"] == port


def test_a_configuration_error_and_a_bind_failure_have_different_exit_codes(monkeypatch, capsys):
    """The unit file treats one as terminal and the other as retryable.

    `RestartPreventExitStatus=2` stops a config error from becoming an endless
    silent restart loop, so the two must not share a code.
    """
    monkeypatch.setenv("EIP_API_BASE_URL", "http://api.test")
    monkeypatch.setenv("EIP_MCP_ALLOWED_HOSTS", "mcp.example.test")

    def refuse_to_bind(self, **kwargs):
        raise OSError(48, "address already in use")

    monkeypatch.setattr("mcp.server.MCPServer.run", refuse_to_bind)
    status = main(["--transport", "streamable-http", "--port", "13003"])
    assert status == 3
    err = capsys.readouterr().err
    assert "cannot serve on" in err
    assert "Traceback" not in err


# The SDK runs its DNS-rebinding check inside the endpoint, not as ASGI middleware,
# while Starlette's `redirect_slashes` runs first in routing. So `POST /mcp/` with
# ANY Host returned `307 location: http://<that host>/mcp` - the allowlist bypassed
# and an attacker-chosen name reflected verbatim - while `POST /mcp` correctly gave
# 421. Not fixable inside the SDK's app construction, so the built app is patched.
def test_the_streamable_http_app_does_not_redirect_a_trailing_slash(monkeypatch):
    monkeypatch.setenv("EIP_API_BASE_URL", "http://api.test")
    monkeypatch.setenv("EIP_MCP_ALLOWED_HOSTS", "mcp.example.test")

    from eip_mcp_v3.__main__ import _refuse_slash_redirects
    from eip_mcp_v3.config import Settings
    from eip_mcp_v3.server import create_mcp_server

    server = create_mcp_server(Settings(api_base_url="http://api.test"))
    _refuse_slash_redirects(server)
    app = server.streamable_http_app(streamable_http_path="/mcp")
    assert app.router.redirect_slashes is False


def test_an_unpatched_app_still_redirects(monkeypatch):
    """Pins the premise. If a future SDK stops redirecting, or stops routing
    through `streamable_http_app`, this fails and the shim can be re-examined
    rather than left silently doing nothing."""
    monkeypatch.setenv("EIP_API_BASE_URL", "http://api.test")

    from eip_mcp_v3.config import Settings
    from eip_mcp_v3.server import create_mcp_server

    app = create_mcp_server(Settings(api_base_url="http://api.test")).streamable_http_app(
        streamable_http_path="/mcp"
    )
    assert app.router.redirect_slashes is True, (
        "the SDK no longer redirects; the shim in __main__ may be obsolete"
    )


def test_the_shim_is_applied_on_the_http_path_only(monkeypatch, capsys):
    """stdio builds no Starlette app, so the shim must not run there."""
    monkeypatch.setenv("EIP_API_BASE_URL", "http://api.test")
    calls: list = []
    monkeypatch.setattr(
        "eip_mcp_v3.__main__._refuse_slash_redirects", lambda server: calls.append(server)
    )
    monkeypatch.setattr("mcp.server.MCPServer.run", lambda self, **kw: None)
    assert main([]) == 0
    assert calls == [], "the slash shim ran under stdio, where there is no app"



def test_main_wires_the_slash_redirect_fix_on_the_http_transport(monkeypatch):
    """Asserts the WIRING, not the helper.

    The helper had its own test that called `_refuse_slash_redirects(server)`
    directly, so deleting the call site in `main` left the entire suite green
    while silently restoring the Host-allowlist bypass on `POST /mcp/`.
    """
    monkeypatch.setenv("EIP_API_BASE_URL", "http://api.test")
    monkeypatch.setenv("EIP_MCP_ALLOWED_HOSTS", "mcp.example.test")

    built: list = []

    def capture(self, **kwargs):
        built.append(self.streamable_http_app(streamable_http_path="/mcp"))

    monkeypatch.setattr("mcp.server.MCPServer.run", capture)
    assert main(["--transport", "streamable-http", "--port", "13003"]) == 0
    assert built, "the server never ran"
    assert built[0].router.redirect_slashes is False, (
        "main() did not apply the slash-redirect fix; POST /mcp/ bypasses the "
        "Host allowlist and reflects the attacker's Host into a 307"
    )


def test_a_stdio_failure_names_no_socket_that_was_never_involved(monkeypatch, capsys):
    """stdio passes no host or port, so the bind handler printed `None:None`."""

    def refuse(self, **kwargs):
        raise OSError(9, "bad file descriptor")

    monkeypatch.setenv("EIP_API_BASE_URL", "http://api.test")
    monkeypatch.setattr("mcp.server.MCPServer.run", refuse)
    assert main([]) == 3
    err = capsys.readouterr().err
    assert "None" not in err, err
    assert "cannot serve:" in err


def test_an_http_bind_failure_still_names_the_address(monkeypatch, capsys):
    def refuse(self, **kwargs):
        raise OSError(48, "address already in use")

    monkeypatch.setenv("EIP_API_BASE_URL", "http://api.test")
    monkeypatch.setenv("EIP_MCP_ALLOWED_HOSTS", "mcp.example.test")
    monkeypatch.setattr("mcp.server.MCPServer.run", refuse)
    assert main(["--transport", "streamable-http", "--port", "13003"]) == 3
    assert "127.0.0.1:13003" in capsys.readouterr().err
