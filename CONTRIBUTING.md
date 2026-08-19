# Contributing to eip-mcp

Contributions must preserve the read-only API boundary and the product rules in
[AGENTS.md](https://github.com/exploitintel/eip-mcp/blob/main/AGENTS.md).

## Development setup

Python 3.12 or newer is required:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pip install -e .
```

Run the hermetic quality suite before opening a pull request:

```sh
! git grep -n -I -P '[\x{2013}\x{2014}]' -- .   # CI rejects en/em dashes
ruff check src tests
ruff format --check src tests
mypy
pytest -q --cov=eip_mcp_v3 --cov-fail-under=96
python -m build
python -m twine check dist/*
```

CI runs `ruff` and `pytest` on Python 3.12 and 3.14, so an interpreter-specific
failure is invisible in a single local run. The build and `twine check` steps
run once, on 3.12.

Every skip in the default test run must be a live test waiting on
`EIP_MCP_TEST_API_BASE_URL`, with one exception: the `code_search` leg of
`test_a_rendered_verdict_is_always_attributed_to_a_model` skips because that
surface renders no verdict for the shape under test. It runs, and enforces the
attribution rule, the moment that surface does render one. No other test is
allowed to skip silently.

## Live verification

Live tests are opt-in, sequential, and bounded:

```sh
EIP_MCP_TEST_API_BASE_URL=https://exploit-intel.com \
  pytest tests/test_live.py tests/test_live_parameter_effects.py -v
```

They must verify the meaning of returned parameters and fields, not merely a
successful HTTP status.

## Pull requests

- Preserve API ordering, identifiers, attribution, and opaque cursors.
- Treat every corpus value as hostile model input.
- Do not add ranking, inferred verification, PoC downloads, write paths, or
  direct data-store access.
- Keep stdio free of every non-protocol stdout byte.
- Add behavior-focused tests for changed tools, arguments, rendering, bounds,
  and error paths.
- Update the user or self-hosting guide when public behavior changes.

Package publication and deployment remain explicit maintainer actions.
