"""Shared FastAPI dependencies."""

from __future__ import annotations

from fastapi import Request

from unishield.api.state import AppContext


def get_context(request: Request) -> AppContext:
    return request.app.state.ctx
