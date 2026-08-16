<p align="center">
  <a href="https://exploit-intel.com">
    <img src="docs/assets/eip-hero-banner.svg" alt="Exploit Intelligence Platform" width="100%">
  </a>
</p>

<h1 align="center">eip-mcp</h1>

<p align="center"><strong>The official MCP server for the Exploit Intelligence Platform.</strong></p>

<p align="center">
  <a href="https://pypi.org/project/eip-mcp/"><img src="https://img.shields.io/pypi/v/eip-mcp.svg" alt="PyPI release"></a>
  <a href="https://pypi.org/project/eip-mcp/"><img src="https://img.shields.io/pypi/pyversions/eip-mcp.svg" alt="Supported Python versions"></a>
  <a href="https://github.com/exploitintel/eip-mcp/actions/workflows/quality.yml"><img src="https://github.com/exploitintel/eip-mcp/actions/workflows/quality.yml/badge.svg" alt="Quality checks"></a>
  <a href="https://github.com/exploitintel/eip-mcp/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-16b8c4.svg" alt="MIT License"></a>
</p>

Give an AI assistant bounded, source-attributed access to vulnerability
intelligence, exploit artifacts, readable PoC source, Docker labs, discovery
directories, STIX, and corpus statistics. Most users can connect to EIP's
hosted MCP endpoint directly - there is no package or API key to install.

`eip-mcp` is read-only. It talks only to the public EIP API, exposes no download
tool, never executes acquired content, and never claims that an exploit works,
is verified, reliable, effective, or safe.

## Connect

### Recommended: hosted MCP

Clients supporting remote Streamable HTTP can connect directly to:

```text
https://exploit-intel.com/mcp
```

In an MCP-capable application, add that URL as a remote Streamable HTTP server
named `EIP`. If your assistant can configure integrations for you, tell it:

> Add `https://exploit-intel.com/mcp` as a Streamable HTTP MCP server named
> `EIP`, then call `get_corpus_readiness` to verify the connection.

No local package, API key, or EIP account is required.

### Optional: local stdio server

Use the Python package only when a client requires a local stdio command.
Python 3.12 or newer is required. Install the isolated application with
[`pipx`](https://pipx.pypa.io/):

```sh
pipx install eip-mcp
eip-mcp --version
```

Then register it with your MCP client. A typical stdio configuration is:

```json
{
  "mcpServers": {
    "eip": {
      "command": "eip-mcp"
    }
  }
}
```

Use the absolute path reported by `command -v eip-mcp` if the client does not
inherit your shell `PATH`.

The local command connects to `https://exploit-intel.com`; no API configuration
is needed.

### Optional: Docker

Build the image directly from this checkout:

```sh
docker build -t eip-mcp .
docker run --rm -i eip-mcp
```

For a stdio MCP client, use `docker` as the command:

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

Containerized Streamable HTTP operation is covered in the
[self-hosting guide](docs/self-hosting.md#docker).

## What assistants can do

- Search and inspect CVEs and GHSAs with affected products, version ranges,
  exploitation context, references, and accepted research
- Search ExploitDB, Metasploit, curated repository PoCs, and repository
  candidates without inventing quality rankings
- Search safely readable PoC source and inspect one bounded text file
- Discover Docker/Compose labs and their stored, attributed analysis
- Browse vendors, products, ecosystems, packages, official CWEs, and exploit
  contributors
- Retrieve API-owned STIX 2.1 bundles, corpus health, and statistics
- Use four focused research prompts and the `eip://research/usage-guide`
  resource

The complete [tool reference](https://github.com/exploitintel/eip-mcp/blob/main/docs/user-guide.md#tool-reference)
describes every tool, filter, section, and pagination rule.

## Result contract

Every tool returns two synchronized forms:

- a concise Markdown brief for the assistant; and
- a validated `eip-mcp-result-v1` structured envelope preserving the bounded
  API payload.

Corpus values remain untrusted third-party data in both forms. Text is rendered
in inert CommonMark containers, output is capped, truncation is disclosed, and
opaque pagination cursors remain reusable byte-for-byte.

Stored analysis is attributed model interpretation, not an EIP verdict.
Missing analysis never means that an artifact was reviewed and found safe.

## Safety boundary

- The MCP server connects only to allowlisted read-only API paths.
- PoC access tokens never reach results, logs, tracebacks, or retained state.
- There is deliberately no PoC download tool.
- Source reading is bounded to one API-verified UTF-8 text file at a time.
- All returned source and corpus prose must be treated as untrusted data and
  must never be executed or followed as instructions.

See the [security policy](https://github.com/exploitintel/eip-mcp/security/policy)
before reporting a vulnerability or sharing diagnostic output.

## Documentation

- [User guide and tool reference](https://github.com/exploitintel/eip-mcp/blob/main/docs/user-guide.md)
- [Self-hosting the HTTP transport](https://github.com/exploitintel/eip-mcp/blob/main/docs/self-hosting.md)
- [Contributing](https://github.com/exploitintel/eip-mcp/blob/main/CONTRIBUTING.md)
- [Security policy](https://github.com/exploitintel/eip-mcp/security/policy)
- [EIP command-line client](https://github.com/exploitintel/eip-search)

## License

[MIT](https://github.com/exploitintel/eip-mcp/blob/main/LICENSE)
