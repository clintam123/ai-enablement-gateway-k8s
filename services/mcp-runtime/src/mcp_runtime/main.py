"""ASGI entrypoint for running the Guarded MCP Runtime under uvicorn."""

from mcp_runtime.app import create_app

app = create_app()
