"""
Tests for UI-served OAuth callbacks (reverse-proxy mode)
---------------------------------------------------------
Covers the shared CSRF state check and the FastAPI callback route
used when OAUTH_SCHEME=https (see app/api/oauth.py).
"""

import pytest

from app.core import state
from app.services.auth_handlers import verify_oauth_state


@pytest.fixture
def clean_oauth_state():
    """Reset shared OAuth state before and after each test."""
    with state.oauth_state_lock:
        state.oauth_state["state"] = None
    with state.oauth_callback_lock:
        state.oauth_callback_data["code"] = None
        state.oauth_callback_data["error"] = None
        state.oauth_callback_event.clear()
    yield
    with state.oauth_state_lock:
        state.oauth_state["state"] = None
    with state.oauth_callback_lock:
        state.oauth_callback_data["code"] = None
        state.oauth_callback_data["error"] = None
        state.oauth_callback_event.clear()


class TestVerifyOauthState:
    """Tests for the shared CSRF state check."""

    def test_valid_state_returns_none_and_keeps_state(self, clean_oauth_state):
        with state.oauth_state_lock:
            state.oauth_state["state"] = "abc123"
        assert verify_oauth_state({"state": ["abc123"]}) is None
        with state.oauth_state_lock:
            assert state.oauth_state["state"] == "abc123"

    def test_no_stored_state_returns_error(self, clean_oauth_state):
        error = verify_oauth_state({"state": ["abc123"]})
        assert error is not None
        assert "no stored state" in error

    def test_missing_state_param_returns_error(self, clean_oauth_state):
        with state.oauth_state_lock:
            state.oauth_state["state"] = "abc123"
        error = verify_oauth_state({})
        assert error is not None
        assert "missing state" in error

    def test_mismatch_returns_error_and_clears_state(self, clean_oauth_state):
        with state.oauth_state_lock:
            state.oauth_state["state"] = "abc123"
        error = verify_oauth_state({"state": ["wrong"]})
        assert error is not None
        assert "mismatch" in error
        with state.oauth_state_lock:
            assert state.oauth_state["state"] is None


class TestUiCallbackRoute:
    """Tests for GET /oauth/callback on the web UI server."""

    def test_success_sets_code_and_event(self, client, clean_oauth_state):
        with state.oauth_state_lock:
            state.oauth_state["state"] = "abc123"
        response = client.get("/oauth/callback?code=authcode&state=abc123")
        assert response.status_code == 200
        assert "Authentication successful" in response.text
        with state.oauth_callback_lock:
            assert state.oauth_callback_data["code"] == "authcode"
            assert state.oauth_callback_event.is_set()

    def test_wrong_state_returns_403(self, client, clean_oauth_state):
        with state.oauth_state_lock:
            state.oauth_state["state"] = "abc123"
        response = client.get("/oauth/callback?code=authcode&state=wrong")
        assert response.status_code == 403
        with state.oauth_callback_lock:
            assert state.oauth_callback_data["error"] is not None
            assert state.oauth_callback_event.is_set()

    def test_error_param_sets_error(self, client, clean_oauth_state):
        with state.oauth_state_lock:
            state.oauth_state["state"] = "abc123"
        response = client.get(
            "/oauth/callback?error=access_denied&state=abc123"
        )
        assert response.status_code == 400
        with state.oauth_callback_lock:
            assert state.oauth_callback_data["error"] == "access_denied"
            assert state.oauth_callback_event.is_set()

    def test_neither_code_nor_error_does_not_set_event(
        self, client, clean_oauth_state
    ):
        with state.oauth_state_lock:
            state.oauth_state["state"] = "abc123"
        response = client.get("/oauth/callback?state=abc123")
        assert response.status_code == 400
        with state.oauth_callback_lock:
            assert not state.oauth_callback_event.is_set()

    def test_second_callback_reports_already_processed(
        self, client, clean_oauth_state
    ):
        with state.oauth_state_lock:
            state.oauth_state["state"] = "abc123"
        first = client.get("/oauth/callback?code=authcode&state=abc123")
        assert first.status_code == 200
        second = client.get("/oauth/callback?code=other&state=abc123")
        assert second.status_code == 200
        assert "already processed" in second.text
        with state.oauth_callback_lock:
            assert state.oauth_callback_data["code"] == "authcode"
