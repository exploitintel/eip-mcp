FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="eip-mcp" \
      org.opencontainers.image.description="MCP server for the Exploit Intelligence Platform" \
      org.opencontainers.image.source="https://github.com/exploitintel/eip-mcp" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/eip-mcp

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip install --no-cache-dir . \
    && groupadd --system eip \
    && useradd --system --gid eip --create-home eip

USER eip
WORKDIR /home/eip

ENTRYPOINT ["eip-mcp"]
