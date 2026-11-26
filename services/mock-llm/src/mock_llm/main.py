"""ASGI entrypoint for running the Mock Provider under uvicorn."""

from mock_llm.app import create_app

app = create_app()
