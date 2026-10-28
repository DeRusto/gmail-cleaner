"""OAuth callback route for reverse-proxy setups.

When OAUTH_SCHEME=https, the OAuth callback is served by the web UI
itself (instead of the standalone callback server on the OAuth port),
so a TLS reverse proxy can route it with no extra port: register
https://<OAUTH_HOST><OAUTH_CALLBACK_PATH> as the redirect URI.
"""

import logging
from urllib.parse import parse_qs, urlparse

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.core import settings, state
from app.services.auth_handlers import verify_oauth_state

router = APIRouter(tags=["OAuth"])
logger = logging.getLogger(__name__)


@router.get(settings.oauth_callback_path, include_in_schema=False)
async def oauth_callback(request: Request):
    """Handle the OAuth2 callback on the web UI server."""
    with state.oauth_callback_lock:
        if state.oauth_callback_event.is_set():
            return HTMLResponse(
                "<html><body><h1>Callback already processed</h1><p>You can close this window.</p></body></html>"
            )

    query_params = parse_qs(urlparse(str(request.url)).query)

    state_error = verify_oauth_state(query_params)
    if state_error is not None:
        with state.oauth_callback_lock:
            state.oauth_callback_data["error"] = state_error
            state.oauth_callback_event.set()
        return HTMLResponse(
            "<html><body><h1>Security Error</h1><p>Authentication state mismatch. Please try signing in again.</p></body></html>",
            status_code=403,
        )

    if "code" in query_params:
        code_list = query_params["code"]
        if code_list and len(code_list) > 0:
            with state.oauth_callback_lock:
                state.oauth_callback_data["code"] = code_list[0]
                with state.oauth_state_lock:
                    state.oauth_state["state"] = None
                state.oauth_callback_event.set()
            return HTMLResponse(
                "<html><body><h1>Authentication successful!</h1><p>You can close this window.</p></body></html>"
            )
        with state.oauth_callback_lock:
            state.oauth_callback_data["error"] = "Empty authorization code"
            state.oauth_callback_data["code"] = None
            with state.oauth_state_lock:
                state.oauth_state["state"] = None
            state.oauth_callback_event.set()
        logger.warning("OAuth callback received empty code parameter")
        return HTMLResponse(
            "<html><body><h1>Invalid request - empty authorization code</h1><p>You can close this window.</p></body></html>",
            status_code=400,
        )

    if "error" in query_params:
        error_list = query_params["error"]
        if error_list and len(error_list) > 0:
            error_message = error_list[0]
            error_description = query_params.get("error_description", [""])
            error_description = error_description[0] if error_description else ""
            full_error = error_message + (
                f" - {error_description}" if error_description else ""
            )
            with state.oauth_callback_lock:
                state.oauth_callback_data["error"] = full_error
                with state.oauth_state_lock:
                    state.oauth_state["state"] = None
                state.oauth_callback_event.set()
            logger.error(f"OAuth callback error: {full_error}")
            return HTMLResponse(
                "<html><body><h1>Authentication failed!</h1><p>You can close this window.</p></body></html>",
                status_code=400,
            )
        with state.oauth_callback_lock:
            state.oauth_callback_data["error"] = "Empty error parameter received"
            state.oauth_callback_data["code"] = None
            with state.oauth_state_lock:
                state.oauth_state["state"] = None
            state.oauth_callback_event.set()
        logger.warning("OAuth callback received empty error parameter")
        return HTMLResponse(
            "<html><body><h1>Invalid request - empty error parameter</h1><p>You can close this window.</p></body></html>",
            status_code=400,
        )

    # Invalid request - don't mark as received to allow retry
    return HTMLResponse(
        "<html><body><h1>Invalid request</h1><p>You can close this window.</p></body></html>",
        status_code=400,
    )
