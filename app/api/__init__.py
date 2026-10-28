"""API routes module."""

from .status import router as status_router
from .actions import router as actions_router
from .oauth import router as oauth_router

__all__ = ["status_router", "actions_router", "oauth_router"]
