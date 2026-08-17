# eip-mcp-v3

The public source repository, PyPI distribution, and canonical executable are
all `eip-mcp`. The Python import package is `eip_mcp_v3`. Version 3 begins at
`3.0.0` and releases only from a matching `v*` tag on `main`. Do not publish or
tag without explicit operator authorization.

## Boundary

This repository is an MCP adapter over the **public read-only EIP v3 API**. It is a
peer of the WebUI, not part of the API or the pipeline.

It must not:

- connect to PostgreSQL, read the source corpus, or read the code-search index;
- acquire, parse, or execute source feeds or PoC code;
- call an LLM or expose unstored model output;
- invent EIP scores, confidence, reliability, or exploitation claims;
- import from any other Exploit Intel repository.

Its only dependency on EIP is the public HTTP API contract.

## Correctness rules

- Render only what the API returned, in the order it returned it. Never re-sort,
  re-rank, or score. `src/eip_mcp_v3/format.py` and the focused `format_*.py`
  modules implement this rule.
- Never derive any output from Metasploit reliability rank, the ExploitDB `verified`
  flag, or GitHub stars. `tests/test_no_derived_judgments.py` enforces this: it greps
  the formatter source for banned ranking inputs and the rendered output for banned
  phrases. The banned-token list names the **data fields** (`stars`, `verified`,
  `"rank"`), not helper names, so renaming derived-score code cannot bypass the
  boundary. Do not weaken it.
- Never claim an exploit or lab works, is verified, reliable, ranked, or safe.
- Stored analysis is cited model interpretation with its model and dates. Absent
  analysis renders as absent - never "clean". An unrecognised backdoor verdict fails
  closed: only the one documented benign verdict renders quietly, everything else
  renders loudly.
- Model self-reported confidence is provenance only, never an EIP score.
- Missing values are omitted, never fabricated defaults.
- All corpus text is hostile. Every corpus value that reaches output must pass
  through a primitive in `src/eip_mcp_v3/text.py` - `inline()` for a value on a
  trusted line, `untrusted_block()` for multi-line prose, `code_block()` for source,
  `cap()` for the finished result. Never interpolate a corpus value into Markdown
  directly, and never hand-roll escaping: the primitives size their own fences and
  delimiters against the body so hostile backticks cannot close them early.
- PoC access tokens live as frame locals for the duration of one call. They must
  never reach a tool result, a log line, or a traceback. Errors raised from a
  token-bearing call are re-raised with the token scrubbed and with the original
  dropped from the exception chain, because a chained traceback renders the
  unscrubbed message. `tests/test_token_containment.py` checks the property - a
  fresh token per request, every recorded request line, every rendered byte, every
  propagated error, and the object graph left behind.
- Never surface a traceback that carries frame locals. The entrypoint prints the
  configuration error message and not the stack, for this reason.
- No download tool. `POST /api/v1/poc-download` is absent from the API client's path
  allowlist, and `_check_path` raises `ValueError` - deliberately outside the
  `ApiError` hierarchy the handlers catch - so a forbidden endpoint cannot fail
  quietly.
- Every tool is annotated read-only.
- Every tool returns both a concise contained text brief and a validated generic
  `eip-mcp-result-v1` source-payload envelope. One hard ceiling covers the complete
  serialized result across both forms. The envelope validates its version, kind,
  truncation state, and object-valued data; it does not duplicate the API as a second
  per-tool schema. It always marks `data_trust=untrusted-api-data`; the structured
  projection preserves API types and values while they fit the shared output budget
  but must never be executed or treated as instructions. When `truncated=true`, long
  values, fields, list items, or collections may be clipped or omitted. The
  API-minted opaque `next_cursor` must remain byte-for-byte reusable.
  Structured content is not an escape hatch around output bounds or PoC access-token
  scrubbing.
- Nothing may write to stdout. Under the stdio transport stdout carries the JSON-RPC
  stream and one stray byte corrupts the session. Diagnostics go to stderr.

## Protocol

MCP spec `2026-07-28`, SDK `mcp>=2.0.0,<3`. Use `MCPServer`; `FastMCP` does not exist
in v2. `ToolAnnotations` fields are snake_case.

`--transport` accepts `stdio` (the default, and what is registered in users' MCP
configurations) and `streamable-http`. stdio's `run` call takes no transport
arguments and must stay that way. HTTP runs stateless - MCP `2026-07-28` has no
protocol sessions - binds loopback by default, and is deliberately unauthenticated
and unmetered: the corpus is free and anonymous, and rate limiting belongs at the edge
proxy, not here. Do not add authentication, quotas, metrics, or a health endpoint.
The API client applies bounded concurrency as backpressure; that protects shared
capacity and is not a caller quota or an edge rate limit.

DNS-rebinding protection is never disabled, and `EIP_MCP_ALLOWED_HOSTS` is required
whenever HTTP is selected. The SDK's empty allowlist rejects every `Host`, which is
closed but operationally opaque: the process can start while every request receives
421. The entrypoint refuses to start so the missing public-host configuration is
explicit. Do not add a default hostname to make that error go away. A bare `*` entry
is refused for the same reason in reverse: it looks like "allow everything", matches
only a literal `*` `Host`, and would 421 every real client while the operator believed
the check was off.

`:*` is the SDK's own suffix form and is a **prefix test, not a port wildcard** -
`host.startswith(base + ":")`, so `mcp.example.test:*` accepts
`mcp.example.test:8080.evil.com`. Never describe it as matching any port;
`docs/self-hosting.md` states what it does and
`tests/test_host_allowlist_matching.py` pins that against the SDK. Allowlist
entries are lowercased and registered with and without the root dot,
which normalises *our* list only. Do not make the SDK's `Host` comparison
case-insensitive to close the remaining gap - a mixed-case `Host` failing closed is
the documented behaviour, not a bug to trade a security control for.

`--host`, `--port` and `--path` are errors under `--transport stdio`, where they apply
to nothing. A non-loopback `--host` is warned about on **stderr** and never refused:
containers need `0.0.0.0`.

## Verification

Unit tests run against recorded real API payloads in `tests/fixtures/`. Live tests in
`tests/test_live.py` and `tests/test_live_parameter_effects.py` run against a real API
and are required before claiming any behavior works. **A fixture-only pass is not
verification.** The cursor round trip is the standing example: pagination was
unreachable by following the output's own instruction, on all three paginated tools,
and no fixture could have caught it because the rejection came from the API's own
cursor decoder.

`test_live_parameter_effects.py` is the second standing example, and it exists because
"the call returned a well-formed page" proves nothing about the arguments that produced
it. Every declared parameter is tied to an observable consequence - a filter must hold
on *every* row, a sort must be monotonic across the page, a cursor must yield a disjoint
page. A search carrying an *undeclared* filter rendered a confident, unfiltered page for
weeks, because the SDK drops unknown arguments (`extra="ignore"`); `declared_arguments.py`
closes that, and `tests/test_declared_arguments.py` holds the ledger tying every declared
parameter to an effect test, so coverage here is a count and not an impression.

```sh
pytest -q                                                     # no failures; see CONTRIBUTING.md on skips
# live run: no failures; skips must be the corpus-conditional ones only
EIP_MCP_TEST_API_BASE_URL=<url> pytest tests/test_live.py tests/test_live_parameter_effects.py -v
ruff check src tests
```

Do not pin exact pass counts here or in the README. Every commit that adds a test
invalidates them, they were stale twice in a row, and a stale count is worse than
none: it teaches the next reader to ignore the line. The invariants above - zero
failures, and skips confined to the live group plus the one exception
`CONTRIBUTING.md` names - are what a reader can actually check, and they hold
across every commit.

The zero-match code-search live check must remain a successful empty-page assertion;
an empty result is not service degradation.

### Known limitation: injection containment is CommonMark-specific

The containment tests - the formatter suites and `tests/test_text.py` -
parse rendered output with CommonMark (`markdown_it`), which is the norm MCP clients
follow, and under it every corpus value is inert. **The guarantee is CommonMark's, not
Markdown's in general.** Review found that under `python-markdown`, a different and
non-CommonMark implementation, a description containing inline backtick runs can
escape the blockquoted fence of `untrusted_block()` and emit a live `<a href>`. Plain
beacon payloads (`![](http://evil/p.png)`, raw HTML, autolinks) stay contained under
both renderers.

`python-markdown` is not a dependency of this repo and nothing in this suite
re-checks that result, so treat it as a recorded review finding rather than a pinned
test. It is recorded and not fixed on purpose: the fences and span delimiters are
sized by CommonMark's backtick-run rule, and parsing to a second renderer's rules
would mean giving that up. A maintainer should know where the guarantee ends rather
than read the tests as universal. If a client that renders with `python-markdown`
ever becomes a target, that is a redesign, not a patch.

## Documents

`README.md`, `docs/user-guide.md`, `docs/self-hosting.md` and this file describe
the server as shipped and must match the code; a wrong claim in any of them is a
defect, because this repository is built to be published. Caller-visible
limitations belong in the guide that owns the surface - the HTTP `Host` and
`421` behaviour in `docs/self-hosting.md`, tool and pagination bounds in
`docs/user-guide.md` - rather than in dated audit journals or comparison prompts
that become stale as the API and tool surface evolve.

## Development

Never commit secrets or concrete host details. `EIP_API_BASE_URL` overrides the
public default in `config.py` and belongs in the environment.

Use a short-lived `agent/*` branch and a pull request for behavioral changes. Run
the quality suite in `CONTRIBUTING.md` before publishing; CI runs it, plus
wheel and sdist smoke tests.
