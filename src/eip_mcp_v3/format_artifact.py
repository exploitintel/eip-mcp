"""Concise rendering for one non-PoC artifact."""

from __future__ import annotations

from typing import Any

from .text import UNTRUSTED_NOTE, inline, untrusted_block

_VULNERABILITY_LINK_LIMIT = 50


def _items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("items"), list):
        return []
    return [item for item in value["items"] if isinstance(item, dict)]


def format_artifact(data: dict[str, Any]) -> str:
    """Render metadata and vulnerability links for an arbitrary API artifact."""
    artifact_id = inline(data.get("artifact_id"), max_len=128) or "`(unidentified)`"
    lines = [f"# Artifact {artifact_id}", "", UNTRUSTED_NOTE, ""]

    if data.get("title"):
        lines.append(f"Title: {inline(data['title'], max_len=300)}")
    identity = [
        inline(data.get("source"), max_len=48),
        inline(data.get("kind"), max_len=48),
        inline(data.get("native_id"), max_len=160),
    ]
    if rendered := " · ".join(value for value in identity if value):
        lines.append(rendered)
    provider = [
        inline(data.get("provider_type"), max_len=48),
        inline(data.get("provider_host"), max_len=120),
    ]
    if rendered := " · ".join(value for value in provider if value):
        lines.append(f"Provider: {rendered}")
    if data.get("author"):
        lines.append(f"Author: {inline(data['author'], max_len=120)}")
    if data.get("owner_name"):
        lines.append(f"Owner: {inline(data['owner_name'], max_len=120)}")
    if data.get("language"):
        lines.append(f"Language: {inline(data['language'], max_len=64)}")
    if data.get("published_at"):
        lines.append(f"Source date: {inline(data['published_at'], max_len=48)}")
    if data.get("url"):
        lines.append(f"Source URL: {inline(data['url'], max_len=400)}")
    if data.get("description"):
        lines.extend(("", *untrusted_block("Description", data["description"], max_len=1200)))

    links = data.get("vulnerabilities")
    items = _items(links)
    if not isinstance(links, dict):
        lines.extend(("", "## Linked vulnerabilities"))
        lines.append("Vulnerability links were not returned for this artifact.")
        return "\n".join(lines)
    total = links.get("total")
    shown_total = total if isinstance(total, int) and not isinstance(total, bool) else len(items)
    lines.extend(("", f"## Linked vulnerabilities ({shown_total})"))
    if not items:
        lines.append("No linked vulnerabilities are returned for this artifact.")
    visible_items = items[:_VULNERABILITY_LINK_LIMIT]
    for item in visible_items:
        identifier = inline(item.get("identifier"), max_len=64) or "`(unidentified)`"
        provider_name = inline(item.get("provider"), max_len=80)
        pointer = inline(item.get("pointer"), max_len=500)
        suffix = "".join(
            part
            for part in (
                f" - provider {provider_name}" if provider_name else "",
                f", pointer {pointer}" if pointer else "",
            )
        )
        lines.append(f"- {identifier}{suffix}")
    if len(items) > len(visible_items):
        lines.append(
            f"{len(items) - len(visible_items):,} additional linked vulnerability "
            "record(s) omitted from this brief."
        )
    if links.get("truncated"):
        lines.append("The API truncated this vulnerability-link collection.")
    return "\n".join(lines)
