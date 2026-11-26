"""ASGI entrypoint for running the Control Plane under uvicorn."""

from gateway_api.app import create_app

app = create_app()
