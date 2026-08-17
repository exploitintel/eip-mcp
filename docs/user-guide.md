# eip-mcp user guide

`eip-mcp` exposes a read-only Exploit Intelligence Platform API, the public one
by default, to MCP clients. Most users should connect directly to the hosted
endpoint. Install the Python package for a client that requires a local stdio
command, or to self-host the HTTP transport.

## Connection options

### Recommended: hosted Streamable HTTP

Use this endpoint in a client that supports remote MCP servers:

```text
https://exploit-intel.com/mcp
```

Add that URL as a remote Streamable HTTP server named `EIP`. If an MCP-capable
assistant can configure integrations for you, this is a suitable instruction:

> Add `https://exploit-intel.com/mcp` as a Streamable HTTP MCP server named
> `EIP`, then call `get_corpus_readiness` to verify the connection.

The hosted service requires no local package, API key, or EIP account.

### Optional: local stdio

Python 3.12 or newer is required:

```sh
pipx install eip-mcp
eip-mcp --version
```

A typical client definition is:

```json
{
  "mcpServers": {
    "eip": {
      "command": "eip-mcp"
    }
  }
}
```

If the client does not inherit your shell `PATH`, replace the command with the
absolute path returned by `command -v eip-mcp`.

The local server connects to `https://exploit-intel.com`; users do not need to
set an API URL.

### Optional: Docker stdio

Build the image from a source checkout:

```sh
docker build -t eip-mcp .
docker run --rm -i eip-mcp
```

The image runs as an unprivileged user. A Docker-backed client definition is:

```json
{
  "mcpServers": {
    "eip": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "eip-mcp"]
    }
  }
}
```

For Streamable HTTP, follow the container example in the
[self-hosting guide](self-hosting.md#docker).

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `EIP_API_BASE_URL` | `https://exploit-intel.com` | API origin the server reads from; the `--api-base-url` flag overrides it |
| `EIP_MCP_TIMEOUT_SECONDS` | `30` | Positive, finite per-operation upstream timeout; each upstream request is bounded in total at four times this value, and a tool may issue more than one |
| `EIP_MCP_MAX_OUTPUT_CHARS` | `40000` | Complete serialized result ceiling; minimum `4096` |
| `EIP_MCP_MAX_CONCURRENT_API_REQUESTS` | `8` | Per-process upstream concurrency bound from `1` to `64` |

HTTP-transport settings are documented separately in the
[self-hosting guide](self-hosting.md).

## Tool reference

| Tool | Purpose |
|---|---|
| `get_corpus_readiness` | Corpus freshness, policy revision, checkpoint, build time, and code-search readiness |
| `get_corpus_statistics` | Corpus totals and an optional pre-aggregated trend series |
| `search_vulnerabilities` | Full-text vulnerability search with severity, CWE, product, package, exploitation, artifact, sort, and cursor controls |
| `get_vulnerability` | Attributed vulnerability brief returning a default set of bounded sections; `sections` narrows it |
| `get_vulnerability_stix` | API-owned current STIX 2.1 bundle for one vulnerability |
| `browse_vendors` | Source-native vendor directory |
| `browse_products` | Source-native products for one exact vendor |
| `browse_ecosystems` | Source-native package ecosystem directory |
| `browse_packages` | Exact package names for one ecosystem |
| `browse_weaknesses` | Complete official CWE catalog with type, status, abstraction, and counts |
| `get_weakness` | One source-backed official CWE record |
| `browse_authors` | Source-scoped exploit contributor directory |
| `get_author` | One source-scoped contributor and contribution counts |
| `search_exploits` | PoC catalog, including CVE-unlinked artifacts |
| `get_exploit` | Exploit metadata, associations, and stored technical/backdoor analysis |
| `get_artifact` | Generic artifact metadata and vulnerability links |
| `search_exploit_code` | Token-term search over eligible readable PoC paths and text |
| `read_exploit_file` | List files or read one API-verified UTF-8 text file |
| `search_labs` | Docker/Compose lab discovery with association and analysis controls |

The server also exports four prompts - `triage-cve`, `hunt-technique`,
`screen-exploit-safety`, and `corpus-report` - and the
`eip://research/usage-guide` resource.

### Vulnerability sections

`get_vulnerability` accepts any combination of these sections:

```text
pocs  artifacts  related_artifacts  nuclei  labs  references  writeups
affected  weaknesses  lifecycle  research
```

Each section is independently bounded. Without `sections`, the tool returns
`pocs`, `nuclei`, `research`, `writeups`, `references`, `affected`,
`weaknesses`, and `lifecycle`; passing `[]` returns the brief with no expanded
sections. `section_limit` defaults to `10` and accepts up to `50`. A high
`section_limit` can still cross the complete output ceiling, especially for
metadata-rich Nuclei templates; the response discloses that cut and identifies
the narrowing control.

### PoC groups and counts

The `pocs` section presents API-returned artifacts under these source-backed
catalog groups:

| Group | `catalog_kind` |
|---|---|
| Catalogued exploits | `exploitdb-exploit`, `metasploit-exploit`, `metasploit-auxiliary` |
| Curated repository PoCs | `repository-poc` |
| Repository PoC candidates | `repository-candidate` |
| Other PoC artifacts | Any other or missing kind |

This grouping is presentation, not ranking. `poc_count` means all linked public
PoCs. Nuclei is a separate population. `artifact_count` covers every linked
artifact, and `artifact_links` counts provider assertions rather than unique
artifacts.

## Pagination

Collection tools return one bounded page. `limit` defaults to `25` and accepts
up to `100`, except `search_exploit_code`, which accepts up to `50`. If
`next_cursor` is present, repeat the tool call with that cursor and every other
argument - including `limit` - kept unchanged. Cursors are opaque and bound to
the complete query.

The MCP server does not automatically traverse an unbounded corpus. Assistants
should narrow broad requests before asking for additional pages.

## Results and trust

Every tool result contains:

1. a bounded Markdown brief; and
2. a validated `eip-mcp-result-v1` structured envelope.

The envelope preserves API types and values while they fit the shared output
budget and marks them `data_trust: untrusted-api-data`. When `truncated` is
true, long fields or collection members may be clipped or omitted. An opaque
`next_cursor` is kept atomically so it remains usable.

Corpus text, source code, author names, and stored analysis are attacker- or
third-party-authored data. The Markdown formatter contains them under
CommonMark rules, but clients must still treat them as untrusted data rather
than instructions.

EIP does not claim that any exploit works, is verified, reliable, ranked, or
safe. Stored analysis is cited model interpretation. Missing analysis means
unanalyzed, pending, or stale - not reviewed and clean.

## Deliberate exclusions

- There is no PoC download tool.
- Lab screenshots remain presentation assets rather than MCP research data.
- TAXII remains a standards-native service and is not duplicated as MCP tools.
- `/health/live` is omitted because readiness provides the useful research
  state.

## Troubleshooting

### The local server does not start

Run `eip-mcp --version` and then start the command in a terminal. Configuration
and bind errors are printed to stderr without a traceback.

### The client cannot find `eip-mcp`

Use `command -v eip-mcp` and place that absolute path in the client
configuration.

### The API cannot be reached

Run `get_corpus_readiness` to distinguish a service problem from a valid empty
result. Connection errors identify the configured API origin without
including access tokens.

### A page cursor is rejected

Repeat the same tool with the same query, filters, sort, and limit. Copy
`next_cursor` exactly.

### The output says it was truncated

Lower `limit`, request fewer vulnerability sections, or lower `section_limit`.
Do not raise the global output ceiling as the first response to an overly broad
query.
