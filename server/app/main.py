"""ASGI entrypoint kept for backward compatibility."""

from app import create_app

app = create_app()
