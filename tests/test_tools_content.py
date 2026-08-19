import httpx2
import pytest

from eip_mcp_v3.api_client import EipApiClient
from eip_mcp_v3.config import Settings
from eip_mcp_v3.errors import ApiUnavailable
from eip_mcp_v3.tools import EipTools

# Artifact ids are minted only by eip-loader-v3's `artifact_id()`, which returns a
# uuid5. `tools.py` now requires that shape, so a stand-in must have it too.
ARTIFACT = "abc12300-0000-5000-8000-000000000123"

SETTINGS = Settings(api_base_url="http://api.test", max_output_chars=50_000)

SECRET_TOKEN = "tok_SECRET_DO_NOT_LEAK"
FILES = {
    "artifact_id": ARTIFACT,
    "items": [
        {"path": "exploit.py", "size": 100, "sha256": "sha256:aa", "viewable": True},
        {"path": "blob.bin", "size": 900, "sha256": "sha256:bb", "viewable": False},
    ],
}
CONTENT = {
    "artifact_id": ARTIFACT,
    "path": "exploit.py",
    "sha256": "sha256:aa",
    "content": "print('hello')",
}


def tools_for(routes: dict, record: list | None = None) -> EipTools:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if record is not None:
            record.append(request.url.path)
        path = request.url.path
        if path == "/api/v1/poc-access":
            return httpx2.Response(200, json={"token": SECRET_TOKEN, "expires_in": 300})
        if path not in routes:
            return httpx2.Response(404, json={"detail": "not found"})
        return httpx2.Response(200, json=routes[path])

    return EipTools(EipApiClient(SETTINGS, transport=httpx2.MockTransport(handler)), SETTINGS)


async def test_code_search_renders(codesearch_jndi):
    tools = tools_for({"/api/v1/poc-code-search": codesearch_jndi})
    out = await tools.search_exploit_code("jndi ldap")
    assert "582" in out


async def test_code_search_rejects_short_query():
    tools = tools_for({})
    with pytest.raises(ValueError, match="at least 2"):
        await tools.search_exploit_code("x")


async def test_code_search_rejects_bad_limit():
    tools = tools_for({})
    with pytest.raises(ValueError, match="limit"):
        await tools.search_exploit_code("jndi", limit=200)


async def test_code_search_propagates_unavailable():
    def handler(request):
        return httpx2.Response(503, json={"detail": "code search unavailable"})

    tools = EipTools(EipApiClient(SETTINGS, transport=httpx2.MockTransport(handler)), SETTINGS)
    with pytest.raises(ApiUnavailable):
        await tools.search_exploit_code("jndi")


async def test_code_search_forwards_one_exact_scope_and_rejects_two(codesearch_jndi):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx2.Response(200, json=codesearch_jndi)

    tools = EipTools(EipApiClient(SETTINGS, transport=httpx2.MockTransport(handler)), SETTINGS)
    await tools.search_exploit_code("jndi ldap", public_id=3505014494080483)
    assert b'"public_id":3505014494080483' in seen[-1].content

    await tools.search_exploit_code("jndi ldap", vulnerability_id=" ghsa-jfh8-c2jp-5v3q ")
    assert b'"vulnerability_id":"ghsa-jfh8-c2jp-5v3q"' in seen[-1].content

    long_alternate = "Mixed/" + "x" * 500
    await tools.search_exploit_code("jndi ldap", vulnerability_id=f" {long_alternate} ")
    assert f'"vulnerability_id":"{long_alternate}"'.encode() in seen[-1].content

    with pytest.raises(ValueError, match="control characters"):
        await tools.search_exploit_code("jndi ldap", vulnerability_id="CVE-2026-\u202e1234")

    with pytest.raises(ValueError, match="cannot be used together"):
        await tools.search_exploit_code(
            "jndi ldap", public_id=3505014494080483, vulnerability_id="CVE-2021-44228"
        )


async def test_get_exploit_renders(poc_trojan):
    tools = tools_for({"/api/v1/pocs/e4a4436d-7161-52d9-bda8-d099b7b8f581": poc_trojan})
    out = await tools.get_exploit("e4a4436d-7161-52d9-bda8-d099b7b8f581")
    assert "trojan" in out.lower()


async def test_get_exploit_rejects_bad_artifact_id():
    tools = tools_for({})
    with pytest.raises(ValueError, match="artifact_id"):
        await tools.get_exploit("../../etc/passwd")


async def test_read_file_without_path_lists_files():
    tools = tools_for({"/api/v1/poc-files": FILES})
    out = await tools.read_exploit_file(ARTIFACT)
    assert "exploit.py" in out
    assert "not viewable" in out


async def test_read_file_with_path_returns_content():
    tools = tools_for({"/api/v1/poc-files": FILES, "/api/v1/poc-file": CONTENT})
    out = await tools.read_exploit_file(ARTIFACT, path="exploit.py")
    assert "print('hello')" in out


async def test_token_never_appears_in_listing_output():
    tools = tools_for({"/api/v1/poc-files": FILES})
    out = await tools.read_exploit_file(ARTIFACT)
    assert SECRET_TOKEN not in out


async def test_token_never_appears_in_content_output():
    tools = tools_for({"/api/v1/poc-files": FILES, "/api/v1/poc-file": CONTENT})
    out = await tools.read_exploit_file(ARTIFACT, path="exploit.py")
    assert SECRET_TOKEN not in out


async def test_read_file_acquires_token_before_listing():
    seen: list[str] = []
    tools = tools_for({"/api/v1/poc-files": FILES}, record=seen)
    await tools.read_exploit_file(ARTIFACT)
    assert seen[0] == "/api/v1/poc-access"
    assert seen[1] == "/api/v1/poc-files"


async def test_read_file_rejects_path_traversal():
    tools = tools_for({"/api/v1/poc-files": FILES})
    with pytest.raises(ValueError, match="path"):
        await tools.read_exploit_file(ARTIFACT, path="../../../etc/passwd")


async def test_no_download_tool_exists():
    assert not hasattr(EipTools, "download_exploit_archive")
    assert not any("download" in name for name in dir(EipTools))
