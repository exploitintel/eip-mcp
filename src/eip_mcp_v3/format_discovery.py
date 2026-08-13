"""Vendor, product, ecosystem, package, CWE and author presentation."""

from __future__ import annotations

from typing import Any

from .format_common import (
    _AUTHOR_ROLE_LABELS,
    _cursor_line,
    _mapping,
    _number,
    _objects,
    _plain,
    _quantity,
    _sequence,
    format_provenance,
)
from .text import UNTRUSTED_NOTE, UNTRUSTED_NOTE_SHORT, inline, untrusted_block

# --------------------------------------------------------------------------
# Vendor and product directories.
# --------------------------------------------------------------------------


def format_vendor_page(data: dict[str, Any]) -> str:
    """Render one count-ranked vendor page without interpreting source names."""
    data = _mapping(data)
    items = [
        (item, vendor)
        for item in _objects(data.get("items"))
        if (vendor := inline(item.get("vendor"), max_len=256))
    ]
    lines = [
        f"# Vendor directory - {_number(len(items))} result(s) on this page",
        "",
        UNTRUSTED_NOTE_SHORT,
        "",
    ]
    if not items:
        lines.append("No matching vendors.")
        return "\n".join(lines)
    for item, vendor in items:
        lines.extend(
            [
                f"## Vendor {vendor}",
                ", ".join(
                    filter(
                        None,
                        (
                            _quantity(
                                item.get("vulnerability_count"),
                                "vulnerabilities",
                                "vulnerability",
                            ),
                            _quantity(item.get("product_count"), "products", "product"),
                        ),
                    )
                ),
            ]
        )
    lines.extend(_cursor_line(data))
    return "\n".join(lines)


def format_product_page(data: dict[str, Any]) -> str:
    """Render one count-ranked product page in the API's returned order."""
    data = _mapping(data)
    items = [
        (item, product)
        for item in _objects(data.get("items"))
        if (product := inline(item.get("product"), max_len=2048))
    ]
    lines = [
        f"# Product directory - {_number(len(items))} result(s) on this page",
        "",
        UNTRUSTED_NOTE_SHORT,
        "",
    ]
    if not items:
        lines.append("No matching products for this vendor.")
        return "\n".join(lines)
    for item, product in items:
        vendor = inline(item.get("vendor"), max_len=256)
        lines.extend(["", f"## Product {product}"])
        if vendor:
            lines.append(f"Vendor: {vendor}")
        if count := _quantity(item.get("vulnerability_count"), "vulnerabilities", "vulnerability"):
            lines.append(count)
    lines.extend(_cursor_line(data))
    return "\n".join(lines)


def format_ecosystem_page(data: dict[str, Any]) -> str:
    """Render one count-ranked source-native ecosystem page."""
    data = _mapping(data)
    items = [
        (item, ecosystem)
        for item in _objects(data.get("items"))
        if (ecosystem := inline(item.get("ecosystem"), max_len=128))
    ]
    lines = [
        f"# Ecosystem directory - {_number(len(items))} result(s) on this page",
        "",
        UNTRUSTED_NOTE_SHORT,
        "",
    ]
    if not items:
        lines.append("No matching ecosystems.")
        return "\n".join(lines)
    for item, ecosystem in items:
        lines.extend(
            [
                f"## Ecosystem {ecosystem}",
                ", ".join(
                    filter(
                        None,
                        (
                            _quantity(
                                item.get("vulnerability_count"),
                                "vulnerabilities",
                                "vulnerability",
                            ),
                            _quantity(item.get("package_count"), "packages", "package"),
                        ),
                    )
                ),
            ]
        )
    lines.extend(_cursor_line(data))
    return "\n".join(lines)


def format_package_page(data: dict[str, Any]) -> str:
    """Render exact source-native packages in the API's returned order."""
    data = _mapping(data)
    items = [
        (item, package)
        for item in _objects(data.get("items"))
        if (package := inline(item.get("package_name"), max_len=2048))
    ]
    lines = [
        f"# Package directory - {_number(len(items))} result(s) on this page",
        "",
        UNTRUSTED_NOTE_SHORT,
        "",
    ]
    if not items:
        lines.append("No matching packages for this ecosystem.")
        return "\n".join(lines)
    for item, package in items:
        ecosystem = inline(item.get("ecosystem"), max_len=128)
        lines.extend(["", f"## Package {package}"])
        if ecosystem:
            lines.append(f"Ecosystem: {ecosystem}")
        if count := _quantity(item.get("vulnerability_count"), "vulnerabilities", "vulnerability"):
            lines.append(count)
    lines.extend(_cursor_line(data))
    return "\n".join(lines)


_CWE_RECORD_LABELS = {
    "weakness": "Weakness",
    "category": "Category",
    "view": "View",
}
_CWE_DESCRIPTION_LABELS = {
    "weakness": "Source weakness definition",
    "category": "Source category summary",
    "view": "Source view objective",
}


def _required_cwe_text(item: dict[str, Any], field: str, *, max_len: int) -> str:
    value = inline(item.get(field), max_len=max_len)
    if not value:
        raise ValueError("CWE catalog record is incomplete")
    return value


def _required_cwe_type(item: dict[str, Any]) -> str:
    value = item.get("record_type")
    if not isinstance(value, str) or value not in _CWE_RECORD_LABELS:
        raise ValueError("CWE catalog record is incomplete")
    return value


def format_weakness_page(data: dict[str, Any]) -> str:
    """Render a source-backed CWE catalog in the API's returned order."""
    data = _mapping(data)
    items = []
    for item in _objects(data.get("items")):
        items.append(
            (
                item,
                _required_cwe_text(item, "cwe_id", max_len=32),
                _required_cwe_type(item),
                _required_cwe_text(item, "name", max_len=300),
                _required_cwe_text(item, "status", max_len=80),
            )
        )
    lines = [
        f"# CWE catalog - {_number(len(items))} result(s) on this page",
        "",
        UNTRUSTED_NOTE_SHORT,
        "",
    ]
    if not items:
        lines.append("No matching CWE records.")
        return "\n".join(lines)
    for item, cwe_id, record_type, name, status in items:
        label = _CWE_RECORD_LABELS[record_type]
        lines.extend(["", f"## {label} {cwe_id}"])
        lines.append(f"Name: {name}")
        facts = filter(
            None,
            (
                _quantity(
                    item.get("vulnerability_count"),
                    "vulnerabilities",
                    "vulnerability",
                ),
                f"status {status}",
                (
                    f"abstraction {abstraction}"
                    if (abstraction := inline(item.get("abstraction"), max_len=80))
                    else ""
                ),
            ),
        )
        if line := ", ".join(facts):
            lines.append(line)
    lines.extend(_cursor_line(data))
    return "\n".join(lines)


def format_weakness(data: dict[str, Any]) -> str:
    """Render one complete official CWE record."""
    data = _mapping(data)
    cwe_id = _required_cwe_text(data, "cwe_id", max_len=32)
    name = _required_cwe_text(data, "name", max_len=300)
    status = _required_cwe_text(data, "status", max_len=80)
    key = _required_cwe_type(data)
    label = _CWE_RECORD_LABELS[key]
    description_label = _CWE_DESCRIPTION_LABELS[key]
    description = data.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ValueError("CWE catalog record is incomplete")
    provenance = format_provenance(data.get("provenance"))
    if not provenance:
        raise ValueError("CWE catalog record is incomplete")
    lines = [
        f"# CWE {label} {cwe_id}",
        "",
        UNTRUSTED_NOTE,
        "",
        f"Name: {name}",
    ]
    if count := _quantity(
        data.get("vulnerability_count"), "associated vulnerabilities", "associated vulnerability"
    ):
        lines.append(count)
    lines.append(f"Status: {status}")
    if abstraction := inline(data.get("abstraction"), max_len=80):
        lines.append(f"Abstraction: {abstraction}")
    lines.extend(["", *untrusted_block(description_label, description, max_len=4000)])
    lines.extend(["", f"Catalog record provenance{provenance}"])
    lines.extend(
        [
            "",
            "To browse associated records, call `search_vulnerabilities` with the "
            f"`cwe` argument set to {cwe_id}.",
        ]
    )
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Exploit author and repository-owner directory.
# --------------------------------------------------------------------------


def _required_author_text(item: dict[str, Any], field: str, *, max_len: int) -> str:
    value = inline(item.get(field), max_len=max_len)
    if not value:
        raise ValueError("author record is incomplete")
    return value


def _author_roles(item: dict[str, Any]) -> str:
    roles = []
    for role in _sequence(item.get("roles")):
        if isinstance(role, str) and role in _AUTHOR_ROLE_LABELS:
            roles.append(_AUTHOR_ROLE_LABELS[role])
    if not roles:
        raise ValueError("author record is incomplete")
    return " / ".join(dict.fromkeys(roles))


def format_author_page(data: dict[str, Any]) -> str:
    """Render source-scoped PoC contributors in the API's returned order."""
    data = _mapping(data)
    items = _objects(data.get("items"))
    lines = [
        f"# Exploit author directory - {_number(len(items))} result(s) on this page",
        "",
        UNTRUSTED_NOTE_SHORT,
        "",
        "Identities are source-scoped and are not merged merely because names match.",
    ]
    if not items:
        lines.extend(["", "No matching exploit authors or repository owners."])
        return "\n".join(lines)
    for item in items:
        public_id = _plain(item.get("public_id"))
        display_name = _required_author_text(item, "display_name", max_len=300)
        source_scope = _required_author_text(item, "source_scope", max_len=80)
        external_id = _required_author_text(item, "external_id", max_len=300)
        if not public_id:
            raise ValueError("author record is incomplete")
        lines.extend(["", f"## Exploit contributor {display_name} · #{public_id}"])
        lines.append(
            f"{_author_roles(item)} · source {source_scope} · source identity {external_id}"
        )
        counts = ", ".join(
            filter(
                None,
                (
                    _quantity(item.get("poc_count"), "PoCs", "PoC"),
                    _quantity(
                        item.get("vulnerability_count"),
                        "linked vulnerabilities",
                        "linked vulnerability",
                    ),
                ),
            )
        )
        if counts:
            lines.append(counts)
    lines.extend(_cursor_line(data))
    return "\n".join(lines)


def format_author(data: dict[str, Any]) -> str:
    """Render one source-scoped contributor without interpreting its identity."""
    data = _mapping(data)
    public_id = _plain(data.get("public_id"))
    display_name = _required_author_text(data, "display_name", max_len=300)
    source_scope = _required_author_text(data, "source_scope", max_len=80)
    external_id = _required_author_text(data, "external_id", max_len=300)
    if not public_id:
        raise ValueError("author record is incomplete")
    lines = [
        f"# Exploit contributor {display_name}",
        "",
        UNTRUSTED_NOTE_SHORT,
        "",
        f"public_id: #{public_id}",
        f"Role: {_author_roles(data)}",
        f"Source: {source_scope}",
        f"Source identity: {external_id}",
    ]
    counts = ", ".join(
        filter(
            None,
            (
                _quantity(data.get("poc_count"), "PoCs", "PoC"),
                _quantity(
                    data.get("vulnerability_count"),
                    "linked vulnerabilities",
                    "linked vulnerability",
                ),
            ),
        )
    )
    if counts:
        lines.append(counts)
    if profile_url := inline(data.get("profile_url"), max_len=500):
        lines.append(f"Source profile: {profile_url}")
    lines.extend(
        [
            "",
            "To browse this contributor's artifacts, call `search_exploits` with "
            f"`author_id={public_id}`.",
        ]
    )
    return "\n".join(lines)
