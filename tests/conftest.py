import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def log4shell() -> dict:
    return load_fixture("vuln_log4shell.json")


@pytest.fixture
def research() -> dict:
    """A record whose research HAS been run: one analyst writeup, six claims.

    Recorded whole from the live API. `vuln_log4shell.json` carries
    `research_resources: {total: 0}` - research not yet run for it - which is
    what made the collection look empty and kept it unrendered for so long.
    """
    return load_fixture("vuln_research.json")


@pytest.fixture
def rejected_vuln() -> dict:
    return load_fixture("vuln_rejected.json")


@pytest.fixture
def poc_trojan() -> dict:
    return load_fixture("poc_trojan.json")


@pytest.fixture
def poc_unlinked() -> dict:
    return load_fixture("poc_unlinked.json")


@pytest.fixture
def pocs_page() -> dict:
    return load_fixture("pocs_page.json")


@pytest.fixture
def search_kev() -> dict:
    return load_fixture("search_kev.json")


@pytest.fixture
def codesearch_jndi() -> dict:
    return load_fixture("codesearch_jndi.json")


@pytest.fixture
def statistics() -> dict:
    return load_fixture("statistics.json")


@pytest.fixture
def trends() -> dict:
    return load_fixture("trends.json")


@pytest.fixture
def readiness() -> dict:
    return load_fixture("readiness.json")
