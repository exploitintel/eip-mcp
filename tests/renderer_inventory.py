"""Authoritative inventory of every public tool-result renderer.

The runtime mapping is asserted from ``tools.py`` in ``test_format_poc.py``. Keep
one row per formatter function even when one tool selects between variants.
"""

from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from typing import Any

from eip_mcp_v3 import format as fmt
from eip_mcp_v3.format_artifact import format_artifact
from eip_mcp_v3.format_discovery import (
    format_author,
    format_author_page,
    format_ecosystem_page,
    format_package_page,
    format_product_page,
    format_vendor_page,
    format_weakness,
    format_weakness_page,
)
from eip_mcp_v3.format_labs import format_lab_page
from eip_mcp_v3.format_stix import format_stix_bundle
from eip_mcp_v3.format_system import (
    format_file_content,
    format_file_list,
    format_readiness,
    format_statistics,
)

Renderer = Callable[[dict[str, Any]], str]


@dataclass(frozen=True)
class RendererCase:
    name: str
    renderer: Renderer
    payload: str | dict[str, Any]
    hostile_payload: dict[str, Any]
    note: str
    accepts_empty: bool = True


HOSTILE = "PWNED [link](https://evil.test/) ![](https://evil.test/p.png)\n## forged heading"


def _statistics(payload: dict[str, Any]) -> str:
    """Adapt the statistics tool's two responses into one renderer fixture."""
    totals = payload.get("totals")
    if not isinstance(totals, dict):
        totals = {}
    trends = payload.get("trends")
    if not isinstance(trends, dict):
        trends = None
    series = payload.get("series")
    if not isinstance(series, str):
        series = "none"
    return format_statistics(totals, trends, series)


def _weakness(description: str) -> dict[str, Any]:
    return {
        "cwe_id": "CWE-79",
        "record_type": "weakness",
        "name": "Improper Neutralization of Input During Web Page Generation",
        "description": description,
        "status": "Stable",
        "provenance": {"source": "cwe", "native_id": "weakness:79"},
    }


def _author(display_name: str) -> dict[str, Any]:
    return {
        "public_id": 123456,
        "display_name": display_name,
        "source_scope": "github",
        "external_id": "researcher",
        "roles": ["owner"],
    }


PROSE_RENDERERS = (
    RendererCase(
        "format_vulnerability",
        fmt.format_vulnerability,
        "log4shell",
        {"identifier": HOSTILE},
        "full",
    ),
    RendererCase(
        "format_poc_detail", fmt.format_poc_detail, "poc_trojan", {"artifact_id": HOSTILE}, "full"
    ),
    RendererCase(
        "format_poc_page",
        fmt.format_poc_page,
        "pocs_page",
        {"items": [{"public_id": HOSTILE}]},
        "full",
    ),
    RendererCase(
        "format_search_page",
        fmt.format_search_page,
        "search_kev",
        {"items": [{"identifier": HOSTILE}]},
        "full",
    ),
    RendererCase(
        "format_code_search",
        fmt.format_code_search,
        "codesearch_jndi",
        {"items": [{"path": HOSTILE, "snippet": HOSTILE}]},
        "full",
    ),
    RendererCase(
        "format_file_list",
        format_file_list,
        {"artifact_id": "a", "items": [{"path": "p", "size": 1}]},
        {"artifact_id": HOSTILE, "items": [{"path": HOSTILE}]},
        "full",
    ),
    RendererCase(
        "format_file_content",
        format_file_content,
        {"artifact_id": "a", "path": "p", "content": "x"},
        {"artifact_id": HOSTILE, "path": HOSTILE, "content": HOSTILE},
        "full",
    ),
    RendererCase(
        "format_artifact",
        format_artifact,
        {"artifact_id": "123456", "description": "Observed prose."},
        {"artifact_id": HOSTILE, "description": HOSTILE},
        "full",
    ),
    RendererCase(
        "format_lab_page",
        partial(format_lab_page, include_analysis=True),
        {"items": []},
        {
            "items": [
                {
                    "public_id": 123456,
                    "owner": {"title": HOSTILE},
                    "analysis_status": "available",
                    "analysis": {"lab_assessment": {"description": HOSTILE}},
                }
            ]
        },
        "full",
    ),
    RendererCase(
        "format_stix_bundle",
        format_stix_bundle,
        {"type": "bundle", "id": "bundle--1", "objects": []},
        {"type": "bundle", "id": "bundle--1", "objects": [{"name": HOSTILE}]},
        "full",
    ),
    RendererCase(
        "format_weakness",
        format_weakness,
        _weakness("Observed prose."),
        _weakness(HOSTILE),
        "full",
        accepts_empty=False,
    ),
)


VALUE_RENDERERS = (
    RendererCase(
        "format_statistics",
        _statistics,
        {"totals": {"vulnerabilities": 376720}},
        {
            "totals": {"vulnerabilities": 1},
            "trends": {
                "as_of": "2026-08-04",
                "cve_published": {
                    "label": HOSTILE,
                    "points": [{"period": HOSTILE, "count": 1}],
                },
            },
            "series": "cve_published",
        },
        "short",
    ),
    RendererCase("format_readiness", format_readiness, "readiness", {"status": HOSTILE}, "short"),
    RendererCase(
        "format_vendor_page", format_vendor_page, {}, {"items": [{"vendor": HOSTILE}]}, "short"
    ),
    RendererCase(
        "format_product_page",
        format_product_page,
        {},
        {"items": [{"product": HOSTILE, "vendor": HOSTILE}]},
        "short",
    ),
    RendererCase(
        "format_ecosystem_page",
        format_ecosystem_page,
        {},
        {"items": [{"ecosystem": HOSTILE}]},
        "short",
    ),
    RendererCase(
        "format_package_page",
        format_package_page,
        {},
        {"items": [{"package_name": HOSTILE, "ecosystem": HOSTILE}]},
        "short",
    ),
    RendererCase(
        "format_weakness_page",
        format_weakness_page,
        {},
        {"items": [{**_weakness("Observed prose."), "name": HOSTILE}]},
        "short",
    ),
    RendererCase(
        "format_author_page", format_author_page, {}, {"items": [_author(HOSTILE)]}, "short"
    ),
    RendererCase(
        "format_author",
        format_author,
        _author("Researcher"),
        _author(HOSTILE),
        "short",
        accepts_empty=False,
    ),
)

ALL_RENDERERS = PROSE_RENDERERS + VALUE_RENDERERS
