# Self-hosting eip-mcp over HTTP

The local package defaults to stdio. This guide is for operators publishing the
same tools through Streamable HTTP.

## Start on loopback

```sh
EIP_MCP_ALLOWED_HOSTS=mcp.example.com,mcp.example.com:443 \
eip-mcp --transport streamable-http \
  --host 127.0.0.1 \
  --port 13003 \
  --path /mcp
```

| Option | Default | Notes |
|---|---:|---|
| `--transport` | `stdio` | Select `streamable-http` to serve HTTP |
| `--host` | `127.0.0.1` | HTTP only; keep behind a reverse proxy |
| `--port` | `8000` | HTTP only |
| `--path` | `/mcp` | HTTP only; must begin with `/` |

Passing HTTP-only options under stdio is a configuration error. HTTP is always
stateless.

## Docker

Build and start the HTTP transport from a source checkout:

```sh
docker build -t eip-mcp .
docker run --rm \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -p 127.0.0.1:8000:8000 \
  -e EIP_MCP_ALLOWED_HOSTS=localhost:8000,127.0.0.1:8000 \
  eip-mcp \
  --transport streamable-http \
  --host 0.0.0.0 \
  --port 8000 \
  --path /mcp
```

The container runs as an unprivileged user. Binding the published port to
`127.0.0.1` keeps it local to the host. A public deployment still requires the
reverse proxy, TLS, host validation, and edge controls described below.

## Network boundary

The process provides no authentication, caller quotas, or rate limiting. Keep
it on loopback behind a reverse proxy that supplies TLS and edge controls. A
non-loopback bind is allowed for container networking but produces a warning.

If a CDN fronts the proxy, restrict the origin firewall to the CDN's source
ranges. Otherwise direct traffic can bypass edge policy.

## Host and origin validation

`EIP_MCP_ALLOWED_HOSTS` is required for HTTP. The process refuses to start
without it rather than serving an endpoint where every request receives `421`.
DNS-rebinding protection is never disabled.

List the public `Host` values forwarded by the proxy, not the loopback bind
address. Use explicit host and port entries:

```sh
EIP_MCP_ALLOWED_HOSTS=mcp.example.com,mcp.example.com:443
```

Important matching rules:

- `:*` is the upstream SDK's prefix form, not a safe port wildcard. Prefer
  explicit ports.
- `*` and `*.example.com` are not wildcards. A bare `*` is rejected at startup.
- Entries are normalized to lowercase and registered with and without a root
  dot. Incoming `Host` comparison remains byte-for-byte, so clients should send
  ordinary lowercase hostnames.

`EIP_MCP_ALLOWED_ORIGINS` is optional. An empty value accepts clients that omit
`Origin` and rejects browser requests that send an unlisted origin.

## Reverse proxy requirements

The proxy must:

- preserve the public `Host` header;
- forward the long-lived Streamable HTTP response without buffering it into a
  single completed body;
- use a read timeout suitable for MCP calls; and
- expose only the intended `/mcp` path.

For Apache, preserve the host with `ProxyPreserveHost On`. For nginx, use
`proxy_set_header Host $host`.

## systemd example

The repository includes a hardened unit and environment template under
[`deploy/systemd/`](../deploy/systemd/). These files are not installed by the
Python package.

From a source checkout:

```sh
install -m 0644 deploy/systemd/eip-mcp-v3.service /etc/systemd/system/
install -m 0600 deploy/systemd/eip-mcp-v3.env.example /etc/eip-v3/eip-mcp-v3.env
# Set EIP_MCP_ALLOWED_HOSTS in the environment file.
systemctl daemon-reload
systemctl enable --now eip-mcp-v3.service
```

The supplied unit uses `DynamicUser=true`, has no state directory, and confines
network access to loopback. Inspect logs with:

```sh
journalctl -u eip-mcp-v3
```

The SDK does not expose a separate health endpoint. Verify the MCP handshake
and call `get_corpus_readiness` through an MCP client.
