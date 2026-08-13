"""Bounded presentation for the API-owned per-vulnerability STIX bundle."""

from __future__ import annotations

import json
from typing import Any

from .text import UNTRUSTED_NOTE, code_block, inline

_MARKDOWN_JSON_LIMIT = 32_000


def format_stix_bundle(bundle: dict[str, Any]) -> str:
    """Render the deterministic bundle without interpreting its objects."""
    bundle_id = inline(bundle.get("id"), max_len=160) or "`(bundle id unavailable)`"
    objects = bundle.get("objects") if isinstance(bundle.get("objects"), list) else []
    lines = [
        f"# STIX 2.1 bundle {bundle_id}",
        "",
        f"Objects returned: {len(objects):,}. This is the API's canonical current "
        "`eip-stix-v1` bundle, not an MCP-derived mapping.",
        "",
        UNTRUSTED_NOTE,
        "",
    ]
    # The Markdown brief passes through corpus-text sanitation before fencing. JSON
    # ASCII escaping keeps that safety boundary while preserving every string value
    # through a JSON parse, including Unicode separators and decomposed characters
    # that sanitation deliberately removes or normalizes in ordinary prose.
    payload = json.dumps(bundle, ensure_ascii=True, separators=(",", ":"))
    if len(payload) > _MARKDOWN_JSON_LIMIT:
        lines.extend(
            [
                "The Markdown JSON below is a truncated excerpt, not a complete bundle, "
                "and may not parse. The structured result reports its own truncation state.",
                "",
            ]
        )
    lines.extend(code_block(payload, language="json", max_len=_MARKDOWN_JSON_LIMIT))
    return "\n".join(lines)
