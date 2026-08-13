# Security policy

## Supported versions

The latest `eip-mcp` 3.x release receives security fixes.

## Reporting a vulnerability

Use this repository's
[private vulnerability reporting](https://github.com/exploitintel/eip-mcp/security/advisories/new).
Do not disclose a suspected vulnerability in a public issue.

Include the affected version, reproduction steps with secrets and PoC access
tokens removed, the security impact, and any suggested remediation. Never put
private API responses, credentials, access tokens, or non-public corpus
material in a report.

## Security boundary

The server treats API and corpus content as hostile model input. It must remain
read-only, must not expose PoC downloads or retained access tokens, and must not
be bound publicly without an independently controlled reverse proxy and edge
policy.
