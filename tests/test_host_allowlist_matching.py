"""What an `EIP_MCP_ALLOWED_HOSTS` entry actually matches, pinned against the SDK.

The docs used to say that a `:*` suffix "matches any port". It does not. The SDK's
middleware tests `host.startswith(base + ":")`, so `mcp.example.test:*` accepts
`mcp.example.test:8080.evil.com` and `mcp.example.test:x@evil.com` as readily as
`mcp.example.test:8080`. Behind a `Host`-normalising proxy that costs little in
practice, but documentation that steers an operator toward a pattern it describes
incorrectly is worse than documentation that says nothing.

These tests drive the SDK's own matcher with the allowlist `HttpTransportSettings`
actually produces, so the behaviour is pinned where the claim is made: if the SDK
tightens `:*` into a real port wildcard, or loosens an exact entry, something here
goes red and the prose gets revisited. The last test guards the prose directly.
"""

from pathlib import Path

import pytest
from mcp.server.transport_security import (
    TransportSecurityMiddleware,
    TransportSecuritySettings,
)

from eip_mcp_v3.config import HttpTransportSettings

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_THAT_DESCRIBE_THE_ALLOWLIST = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "AGENTS.md",
    REPO_ROOT / "docs" / "self-hosting.md",
    REPO_ROOT / "deploy" / "systemd" / "eip-mcp-v3.env.example",
    REPO_ROOT / "src" / "eip_mcp_v3" / "config.py",
)


def accepts(allowlist: str, host: str) -> bool:
    """Would a request carrying `host` get past the middleware we configure?"""
    settings = HttpTransportSettings.from_env({"EIP_MCP_ALLOWED_HOSTS": allowlist})
    middleware = TransportSecurityMiddleware(
        TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(settings.allowed_hosts),
        )
    )
    return middleware._validate_host(host)


def test_the_pinned_sdk_treats_an_empty_allowlist_as_deny_all():
    middleware = TransportSecurityMiddleware(
        TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[],
        )
    )
    assert middleware._validate_host("mcp.example.test") is False
    assert middleware._validate_host("127.0.0.1:13003") is False


@pytest.mark.parametrize(
    "host",
    [
        "mcp.example.test:8080",
        # Not ports. Both were confirmed with live POSTs returning 200.
        "mcp.example.test:8080.evil.com",
        "mcp.example.test:x@evil.com",
        "mcp.example.test:anything at all",
    ],
)
def test_a_port_wildcard_is_a_prefix_test_and_not_a_port_wildcard(host):
    """`:*` accepts everything after the colon, which is not what "any port" means."""
    assert accepts("mcp.example.test:*", host) is True


def test_a_port_wildcard_does_not_match_the_bare_host():
    """The SDK requires the colon, so `:*` alone is not a superset of the plain name."""
    assert accepts("mcp.example.test:*", "mcp.example.test") is False


def test_a_port_wildcard_does_not_match_a_different_name():
    assert accepts("mcp.example.test:*", "evil.com:8080") is False
    assert accepts("mcp.example.test:*", "notmcp.example.test:8080") is False


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("mcp.example.test:443", True),
        ("mcp.example.test:8443", False),
        ("mcp.example.test", False),
        ("mcp.example.test:443.evil.com", False),
    ],
)
def test_an_explicit_host_port_entry_matches_that_host_port_and_nothing_else(host, expected):
    """The pattern the docs now recommend: exact, and boringly so."""
    assert accepts("mcp.example.test:443", host) is expected


def test_listing_both_forms_is_how_you_cover_port_and_no_port():
    allowlist = "mcp.example.test, mcp.example.test:443"
    assert accepts(allowlist, "mcp.example.test") is True
    assert accepts(allowlist, "mcp.example.test:443") is True
    assert accepts(allowlist, "mcp.example.test:443.evil.com") is False


def test_a_star_is_not_a_wildcard_anywhere_but_the_port_suffix():
    """`*.example.test` reads as a subdomain wildcard and is matched literally.

    A bare `*` is refused at startup for the same reason; this covers the form
    that is still accepted, so the docs' claim that it is not a wildcard holds.
    """
    assert accepts("*.example.test", "mcp.example.test") is False
    assert accepts("*.example.test", "*.example.test") is True


@pytest.mark.parametrize("doc", DOCS_THAT_DESCRIBE_THE_ALLOWLIST)
def test_the_docs_do_not_repeat_the_any_port_claim(doc):
    """The claim the tests above disprove must not come back into the docs."""
    text = doc.read_text(encoding="utf-8")
    assert "matches any port" not in text
    assert "match any port" not in text
    assert "accept any Host" not in text


def test_the_self_hosting_guide_describes_the_prefix_behaviour_it_used_to_get_wrong():
    text = (REPO_ROOT / "docs" / "self-hosting.md").read_text(encoding="utf-8")
    assert ":*" in text
    assert "prefix" in text
