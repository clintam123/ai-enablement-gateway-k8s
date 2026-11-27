FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.9.18 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_DEV=1 \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

COPY pyproject.toml uv.lock ./
COPY packages/platform-common/pyproject.toml packages/platform-common/pyproject.toml
COPY packages/gateway-sdk/pyproject.toml packages/gateway-sdk/pyproject.toml
COPY services/gateway-api/pyproject.toml services/gateway-api/pyproject.toml
COPY services/mock-llm/pyproject.toml services/mock-llm/pyproject.toml
COPY services/mcp-runtime/pyproject.toml services/mcp-runtime/pyproject.toml

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable --no-install-workspace --package gateway-api

COPY packages/platform-common packages/platform-common
COPY services/gateway-api services/gateway-api

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable --package gateway-api

FROM python:3.12-slim AS runtime

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

RUN groupadd --gid 10001 app && \
    useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY policies/policy-bundle.yaml /app/policies/policy-bundle.yaml

RUN chmod -R a+rX /app

USER 10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/.venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

CMD ["uvicorn", "gateway_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
