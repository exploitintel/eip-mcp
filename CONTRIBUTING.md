# Contributing to eip-mcp

Contributions must preserve the read-only API boundary and the product rules in
[AGENTS.md](AGENTS.md).

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
ruff check src tests
pytest -q --cov=eip_mcp_v3 --cov-fail-under=95
python -m build
python -m twine check dist/*
```

Every skip in the default test run must be a live test waiting on
`EIP_MCP_TEST_API_BASE_URL`; no other test is allowed to skip silently.

## Live verification

Live tests are opt-in, sequential, and bounded:

```sh
EIP_MCP_TEST_API_BASE_URL=http://127.0.0.1:13002 \
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
