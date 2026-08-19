import pytest

from eip_mcp_v3.config import DEFAULT_API_BASE_URL, HttpTransportSettings, Settings


def test_from_env_uses_the_public_api_by_default():
    assert Settings.from_env({}).api_base_url == DEFAULT_API_BASE_URL


def test_from_env_treats_a_blank_override_as_absent():
    assert Settings.from_env({"EIP_API_BASE_URL": "   "}).api_base_url == DEFAULT_API_BASE_URL


def test_from_env_reads_base_url_and_strips_trailing_slash():
    settings = Settings.from_env({"EIP_API_BASE_URL": "http://127.0.0.1:13002/"})
    assert settings.api_base_url == "http://127.0.0.1:13002"


def test_from_env_defaults():
    settings = Settings.from_env({"EIP_API_BASE_URL": "http://127.0.0.1:13002"})
    assert settings.request_timeout_seconds == 30.0
    assert settings.max_output_chars == 40_000
    assert settings.max_concurrent_api_requests == 8


def test_from_env_overrides():
    settings = Settings.from_env(
        {
            "EIP_API_BASE_URL": "http://127.0.0.1:13002",
            "EIP_MCP_TIMEOUT_SECONDS": "5",
            "EIP_MCP_MAX_OUTPUT_CHARS": "4096",
            "EIP_MCP_MAX_CONCURRENT_API_REQUESTS": "3",
        }
    )
    assert settings.request_timeout_seconds == 5.0
    assert settings.max_output_chars == 4096
    assert settings.max_concurrent_api_requests == 3


def test_from_env_rejects_non_positive_timeout():
    with pytest.raises(ValueError, match="EIP_MCP_TIMEOUT_SECONDS"):
        Settings.from_env(
            {"EIP_API_BASE_URL": "http://127.0.0.1:13002", "EIP_MCP_TIMEOUT_SECONDS": "0"}
        )


def test_from_env_rejects_low_max_output_chars():
    with pytest.raises(ValueError, match="EIP_MCP_MAX_OUTPUT_CHARS"):
        Settings.from_env(
            {"EIP_API_BASE_URL": "http://127.0.0.1:13002", "EIP_MCP_MAX_OUTPUT_CHARS": "10"}
        )


def test_from_env_accepts_cursor_safe_output_floor_and_rejects_one_less():
    base = {"EIP_API_BASE_URL": "http://127.0.0.1:13002"}
    assert Settings.from_env({**base, "EIP_MCP_MAX_OUTPUT_CHARS": "4096"}).max_output_chars == 4096
    with pytest.raises(ValueError, match="at least 4096"):
        Settings.from_env({**base, "EIP_MCP_MAX_OUTPUT_CHARS": "4095"})


@pytest.mark.parametrize("value", ["0", "65", "-1", "many", "1.5"])
def test_from_env_rejects_invalid_api_concurrency(value):
    with pytest.raises(ValueError, match="EIP_MCP_MAX_CONCURRENT_API_REQUESTS"):
        Settings.from_env(
            {
                "EIP_API_BASE_URL": "http://127.0.0.1:13002",
                "EIP_MCP_MAX_CONCURRENT_API_REQUESTS": value,
            }
        )


# --------------------------------------------------------------------------
# Review finding 7: EIP_API_BASE_URL scheme, and numeric variables named on error.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "/etc/passwd",
        "file:///etc/passwd",
        "file://localhost/etc/passwd",
        "ftp://example.test/x",
        "javascript:alert(1)",
        "127.0.0.1:13002",
        "example.test",
        "http://",
        "https://",
        "http:///api",
    ],
)
def test_from_env_rejects_a_base_url_that_is_not_an_http_url(value):
    with pytest.raises(ValueError, match="EIP_API_BASE_URL"):
        Settings.from_env({"EIP_API_BASE_URL": value})


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://127.0.0.1:13002", "http://127.0.0.1:13002"),
        ("https://eip.example.test/", "https://eip.example.test"),
        ("HTTPS://eip.example.test", "HTTPS://eip.example.test"),
        ("https://eip.example.test/v3/", "https://eip.example.test/v3"),
    ],
)
def test_from_env_accepts_http_and_https_base_urls(value, expected):
    assert Settings.from_env({"EIP_API_BASE_URL": value}).api_base_url == expected


@pytest.mark.parametrize("value", ["soon", "5s", "30 seconds", "1/2", "", "  "])
def test_from_env_names_the_variable_for_an_unparsable_timeout(value):
    if not value.strip():
        # Blank falls back to the default rather than erroring.
        assert (
            Settings.from_env(
                {"EIP_API_BASE_URL": "http://127.0.0.1:13002", "EIP_MCP_TIMEOUT_SECONDS": value}
            ).request_timeout_seconds
            == 30.0
        )
        return
    with pytest.raises(ValueError, match="EIP_MCP_TIMEOUT_SECONDS"):
        Settings.from_env(
            {"EIP_API_BASE_URL": "http://127.0.0.1:13002", "EIP_MCP_TIMEOUT_SECONDS": value}
        )


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "Infinity"])
def test_from_env_rejects_non_finite_timeouts(value):
    with pytest.raises(ValueError, match="EIP_MCP_TIMEOUT_SECONDS"):
        Settings.from_env(
            {"EIP_API_BASE_URL": "http://127.0.0.1:13002", "EIP_MCP_TIMEOUT_SECONDS": value}
        )


@pytest.mark.parametrize("value", ["lots", "20k", "20_000.5", "1e5x"])
def test_from_env_names_the_variable_for_an_unparsable_max_output_chars(value):
    with pytest.raises(ValueError, match="EIP_MCP_MAX_OUTPUT_CHARS"):
        Settings.from_env(
            {"EIP_API_BASE_URL": "http://127.0.0.1:13002", "EIP_MCP_MAX_OUTPUT_CHARS": value}
        )


def test_from_env_error_for_an_unparsable_number_says_what_it_saw():
    with pytest.raises(ValueError, match="EIP_MCP_TIMEOUT_SECONDS must be a number"):
        Settings.from_env(
            {"EIP_API_BASE_URL": "http://127.0.0.1:13002", "EIP_MCP_TIMEOUT_SECONDS": "soon"}
        )


# --------------------------------------------------------------------------
# HTTP transport allowlists.
# --------------------------------------------------------------------------


def test_http_settings_require_an_allowed_hosts_list():
    with pytest.raises(ValueError, match="EIP_MCP_ALLOWED_HOSTS"):
        HttpTransportSettings.from_env({})


@pytest.mark.parametrize("value", ["", "   ", ",", ", ,", "\t"])
def test_http_settings_reject_an_allowlist_with_no_entries(value):
    """An empty list is deny-all, but explicit startup failure is easier to operate."""
    with pytest.raises(ValueError, match="EIP_MCP_ALLOWED_HOSTS"):
        HttpTransportSettings.from_env({"EIP_MCP_ALLOWED_HOSTS": value})


def test_http_settings_error_says_what_to_set():
    with pytest.raises(ValueError, match="streamable-http"):
        HttpTransportSettings.from_env({})


def test_http_settings_split_and_strip_both_lists():
    settings = HttpTransportSettings.from_env(
        {
            "EIP_MCP_ALLOWED_HOSTS": " mcp.example.test , mcp.example.test:443 ,",
            "EIP_MCP_ALLOWED_ORIGINS": "https://mcp.example.test , https://app.example.test",
        }
    )
    # Each entry also lands in its trailing-dot form; see the normalisation tests.
    assert settings.allowed_hosts == (
        "mcp.example.test",
        "mcp.example.test.",
        "mcp.example.test:443",
        "mcp.example.test.:443",
    )
    assert settings.allowed_origins == (
        "https://mcp.example.test",
        "https://app.example.test",
    )


def test_http_settings_allow_an_absent_origin_list():
    settings = HttpTransportSettings.from_env({"EIP_MCP_ALLOWED_HOSTS": "mcp.example.test"})
    assert settings.allowed_origins == ()


def test_http_settings_preserve_a_wildcard_port_pattern():
    """`:*` is the SDK middleware's own suffix form; it must survive parsing.

    What it actually matches is pinned in `tests/test_host_allowlist_matching.py`
    - it is a prefix test, not a port wildcard.
    """
    settings = HttpTransportSettings.from_env({"EIP_MCP_ALLOWED_HOSTS": "127.0.0.1:*"})
    assert settings.allowed_hosts == ("127.0.0.1:*", "127.0.0.1.:*")


# --------------------------------------------------------------------------
# Review: a bare `*` reads as "allow everything" and is not.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["*", " * ", "mcp.example.test, *", "*,mcp.example.test", "*, *"],
)
def test_http_settings_reject_a_bare_wildcard_entry(value):
    """It boots today and matches only a literal `*` Host, which no client sends.

    Everything else gets 421, so the deployment is safe and completely broken -
    while the operator believes they switched the check off. Refuse it instead.
    """
    with pytest.raises(ValueError, match="EIP_MCP_ALLOWED_HOSTS"):
        HttpTransportSettings.from_env({"EIP_MCP_ALLOWED_HOSTS": value})


def test_http_settings_wildcard_error_explains_and_names_the_alternative():
    with pytest.raises(ValueError) as caught:
        HttpTransportSettings.from_env({"EIP_MCP_ALLOWED_HOSTS": "*"})
    message = str(caught.value)
    assert "'*'" in message
    # It must say what the entry really does, not merely that it is refused.
    assert "literal" in message or "literally" in message
    assert "Host" in message


def test_http_settings_still_accept_a_star_inside_a_longer_entry():
    """Only the bare entry is refused; `:*` and `*.example` remain the SDK's problem."""
    settings = HttpTransportSettings.from_env(
        {"EIP_MCP_ALLOWED_HOSTS": "mcp.example.test:*, *.example.test"}
    )
    assert "mcp.example.test:*" in settings.allowed_hosts
    assert "*.example.test" in settings.allowed_hosts


# --------------------------------------------------------------------------
# Review: host matching is case-sensitive and rejects a trailing dot.
#
# The SDK compares the Host header to these strings with `==`, so nothing here
# can make the *header* case-insensitive - only the entries we hand it are ours
# to normalise. A mixed-case Host header still fails closed, which is documented
# rather than papered over.
# --------------------------------------------------------------------------


def test_http_settings_lowercase_allowlist_entries():
    """An operator who copies a name out of a ticket in mixed case still matches."""
    settings = HttpTransportSettings.from_env(
        {"EIP_MCP_ALLOWED_HOSTS": "MCP.Example.Test, MCP.EXAMPLE.TEST:8443"}
    )
    assert settings.allowed_hosts == (
        "mcp.example.test",
        "mcp.example.test.",
        "mcp.example.test:8443",
        "mcp.example.test.:8443",
    )


def test_http_settings_accept_each_entry_with_and_without_the_root_dot():
    """`example.test` and `example.test.` name the same host; both must match."""
    settings = HttpTransportSettings.from_env({"EIP_MCP_ALLOWED_HOSTS": "mcp.example.test"})
    assert settings.allowed_hosts == ("mcp.example.test", "mcp.example.test.")


def test_http_settings_treat_an_operators_trailing_dot_as_a_no_op():
    """Writing the absolute form must not change which requests are accepted."""
    dotted = HttpTransportSettings.from_env({"EIP_MCP_ALLOWED_HOSTS": "mcp.example.test."})
    plain = HttpTransportSettings.from_env({"EIP_MCP_ALLOWED_HOSTS": "mcp.example.test"})
    assert dotted.allowed_hosts == plain.allowed_hosts


def test_http_settings_normalise_a_wildcard_entry_before_the_port_suffix():
    settings = HttpTransportSettings.from_env({"EIP_MCP_ALLOWED_HOSTS": "MCP.Example.Test:*"})
    assert settings.allowed_hosts == ("mcp.example.test:*", "mcp.example.test.:*")


def test_http_settings_leave_an_ipv6_literal_intact():
    settings = HttpTransportSettings.from_env({"EIP_MCP_ALLOWED_HOSTS": "[::1]:13003"})
    assert "[::1]:13003" in settings.allowed_hosts


def test_http_settings_do_not_widen_an_entry_that_is_only_dots():
    """Stripping every dot off `.` would leave a blank entry that matches nothing safe."""
    settings = HttpTransportSettings.from_env({"EIP_MCP_ALLOWED_HOSTS": "."})
    assert "" not in settings.allowed_hosts


# A base URL is operator configuration, but three shapes of it are dangerous in
# ways that are invisible until something else fails.
BAD_BASE_URLS = [
    # A query or fragment REPLACES the path the client builds, so every request
    # goes somewhere the path allowlist never saw. That allowlist is the only
    # thing keeping /api/v1/poc-download unreachable.
    ("http://api.test/?x=1", "query string or fragment"),
    ("http://api.test/#frag", "query string or fragment"),
    ("http://api.test/api?a=b", "query string or fragment"),
    # Userinfo becomes an Authorization header AND is quoted back verbatim in
    # every transport error, which reaches the model's context and the transcript.
    ("http://user:sup3rsecret@api.test", "must not embed credentials"),
    ("http://user@api.test", "must not embed credentials"),
    # An out-of-range port raises ValueError from inside the transport, escaping
    # the ApiError hierarchy every tool depends on.
    ("http://api.test:99999", "port"),
    ("http://api.test:-1", "port"),
]


@pytest.mark.parametrize("url,expected", BAD_BASE_URLS)
def test_a_dangerous_base_url_is_refused_at_startup(url, expected):
    with pytest.raises(ValueError, match=expected):
        Settings.from_env({"EIP_API_BASE_URL": url})


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:13002",
        "https://api.example.com",
        "https://api.example.com/base/path",
        "http://api.test:8080/",
    ],
)
def test_an_ordinary_base_url_is_still_accepted(url):
    assert Settings.from_env({"EIP_API_BASE_URL": url}).api_base_url


def test_a_base_url_on_port_zero_is_refused():
    """Port 0 means "any free port" to the OS and is never an address a client can
    reach - the same reason `--port 0` is refused in the entrypoint."""
    with pytest.raises(ValueError, match="port must be 1-65535"):
        Settings.from_env({"EIP_API_BASE_URL": "http://api.test:0"})
