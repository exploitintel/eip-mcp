"""Bounded catalog rendering for Docker lab units."""

from __future__ import annotations

from typing import Any

from .format_common import _cursor_line
from .text import UNTRUSTED_NOTE, inline, untrusted_block

_SUSPICIOUS_INDICATOR_LIMIT = 8


def _items(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _count(value: Any) -> str:
    return f"{value:,}" if isinstance(value, int) and not isinstance(value, bool) else "unknown"


def _evidence(lines: list[str], claim: Any) -> None:
    """Render bounded packet citations for one selected model claim."""
    if not isinstance(claim, dict):
        return
    citations = _items(claim.get("evidence"))
    if not citations:
        return
    rendered = []
    for citation in citations[:8]:
        path = inline(citation.get("path"), max_len=320)
        if not path:
            continue
        start = citation.get("line_start")
        end = citation.get("line_end")
        if isinstance(start, int) and isinstance(end, int):
            suffix = f" lines {start}-{end}"
        elif isinstance(start, int):
            suffix = f" line {start}"
        else:
            suffix = ""
        rendered.append(f"{path}{suffix}")
    if rendered:
        lines.append("Evidence: " + "; ".join(rendered))
    if len(citations) > 8:
        lines.append(f"{len(citations) - 8} more evidence citation(s) omitted.")


def _analysis(lines: list[str], analysis: Any) -> None:
    if not isinstance(analysis, dict):
        return
    assessment = analysis.get("lab_assessment")
    environment = analysis.get("environment_summary")
    safety = inline(analysis.get("safety_verdict"), max_len=80)
    if safety:
        lines.append(f"Model-reported safety review: {safety}")
    safety_reason = analysis.get("safety_reason")
    if isinstance(safety_reason, dict) and safety_reason.get("description"):
        lines.extend(
            untrusted_block(
                "Model safety reasoning", safety_reason["description"], max_len=1000
            )
        )
        _evidence(lines, safety_reason)
    if isinstance(assessment, dict):
        classification = inline(assessment.get("classification"), max_len=80)
        if classification:
            lines.append(f"Model-reported classification: {classification}")
        if assessment.get("description"):
            lines.extend(
                untrusted_block("Model assessment", assessment["description"], max_len=1000)
            )
            _evidence(lines, assessment)
    if isinstance(environment, dict) and environment.get("description"):
        lines.extend(
            untrusted_block("Model environment summary", environment["description"], max_len=1000)
        )
        _evidence(lines, environment)
    limitations = [str(item) for item in _items_or_scalars(analysis.get("limitations"))]
    if limitations:
        lines.append("Model-stated limitations (untrusted corpus text):")
        lines.extend(f"- {inline(item, max_len=400)}" for item in limitations[:10])
        if len(limitations) > 10:
            lines.append(f"- {len(limitations) - 10} more limitation(s) omitted.")
    suspicious = _items(analysis.get("suspicious_indicators"))
    if suspicious:
        lines.append(f"Model-reported suspicious indicators: {_count(len(suspicious))}")
        for index, indicator in enumerate(suspicious[:_SUSPICIOUS_INDICATOR_LIMIT], start=1):
            description = indicator.get("description")
            if description:
                lines.extend(
                    untrusted_block(
                        f"Model suspicious indicator {index}",
                        description,
                        max_len=1000,
                    )
                )
            _evidence(lines, indicator)
        if len(suspicious) > _SUSPICIOUS_INDICATOR_LIMIT:
            lines.append(
                f"{len(suspicious) - _SUSPICIOUS_INDICATOR_LIMIT} more model-reported "
                "suspicious indicator(s) omitted."
            )


def _items_or_scalars(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def format_lab_page(data: dict[str, Any], *, include_analysis: bool = False) -> str:
    """Render one API-ordered page from the first-class lab catalog."""
    items = _items(data.get("items"))
    statistics = data.get("statistics") if isinstance(data.get("statistics"), dict) else {}
    lines = [
        f"# Docker lab catalog - {_count(len(items))} result(s) on this page",
        "",
        UNTRUSTED_NOTE,
        "",
    ]
    if statistics:
        lines.append(
            "Corpus totals: "
            f"{_count(statistics.get('total'))} labs · "
            f"{_count(statistics.get('cve_linked'))} CVE-linked · "
            f"{_count(statistics.get('analyzed'))} with stored analysis · "
            f"{_count(statistics.get('screenshots'))} with screenshots · "
            f"{_count(statistics.get('compose_units'))} Compose units"
        )
    if not items:
        lines.append("No matching lab units.")
    for item in items:
        owner = item.get("owner") if isinstance(item.get("owner"), dict) else {}
        public_id = inline(item.get("public_id"), max_len=32) or "`(no public id)`"
        title = inline(owner.get("title"), max_len=240) or "`(untitled repository)`"
        lines.extend(("", f"## Lab #{public_id} - {title}"))
        identity = [
            inline(item.get("anchor_kind"), max_len=80),
            inline(item.get("shape"), max_len=80),
            (
                f"{_count(item.get('service_count'))} service(s)"
                if item.get("service_count") is not None
                else ""
            ),
            f"{_count(item.get('compose_manifest_count'))} Compose manifest(s)",
            f"{_count(item.get('dockerfile_count'))} Dockerfile(s)",
        ]
        lines.append(" · ".join(value for value in identity if value))
        if cves := [inline(value, max_len=32) for value in _items_or_scalars(item.get("cve_ids"))]:
            lines.append(f"Linked vulnerabilities: {', '.join(cves)}")
        else:
            lines.append("Linked vulnerabilities: none returned")
        raw_status = item.get("analysis_status")
        status = inline(raw_status, max_len=32) or "`unknown`"
        analysis_available = (
            isinstance(raw_status, str)
            and raw_status.strip().casefold() == "available"
        )
        model = inline(item.get("analysis_model"), max_len=120)
        lines.append(f"Stored analysis: {status}" + (f" · model {model}" if model else ""))
        if item.get("screenshot"):
            lines.append("Screenshot: available through the public WebUI/API")
        omissions = []
        for key, label in (
            ("text_files_omitted", "text files omitted"),
            ("binary_files_uninspected", "binary files uninspected"),
        ):
            if isinstance(item.get(key), int) and item[key] > 0:
                omissions.append(f"{item[key]:,} {label}")
        if omissions:
            lines.append("Evidence omissions: " + ", ".join(omissions))
        if owner.get("url"):
            lines.append(f"Source URL: {inline(owner['url'], max_len=400)}")
        if owner.get("published_at"):
            lines.append(f"Repository source date: {inline(owner['published_at'], max_len=48)}")
        if include_analysis:
            if analysis_available and isinstance(item.get("analysis"), dict):
                provenance = [
                    (
                        "model",
                        inline(item.get("analysis_model"), max_len=120),
                    ),
                    (
                        "contract",
                        inline(item.get("analysis_contract"), max_len=120),
                    ),
                    (
                        "analyzed at",
                        inline(item.get("analyzed_at"), max_len=64),
                    ),
                ]
                rendered = [f"{label} {value}" for label, value in provenance if value]
                if rendered:
                    lines.append("Stored-analysis provenance: " + " · ".join(rendered))
                before_analysis = len(lines)
                _analysis(lines, item["analysis"])
                if len(lines) == before_analysis:
                    lines.append(
                        "Stored analysis envelope contains no model verdict or assessment."
                    )
            else:
                lines.append("No current stored lab analysis is available for this unit.")

    lines.extend(_cursor_line(data))
    return "\n".join(lines)
