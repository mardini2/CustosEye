"""
Tests for dashboard.auth_routes - Authentication route functionality
Tests Flask routes for login, signup, logout, 2FA, and password management.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

# Set required environment variables before importing
os.environ.setdefault("CUSTOSEYE_SESSION_SECRET", "test_session_secret_key_for_testing_only")
os.environ.setdefault("CUSTOSEYE_PASSWORD_PEPPER", "test_password_pepper_for_testing_only")

from dashboard.auth_routes import (
    _get_csrf_token,
    _verify_csrf_token,
    register_auth_routes,
    require_admin,
    require_auth,
)


class TestCSRFToken:
    """Tests for CSRF token functions"""

    def test_get_csrf_token_generates_token(self):
        """Test that _get_csrf_token generates a token"""
        from flask import Flask

        app = Flask(__name__)
        app.secret_key = "test_secret"

        with app.test_request_context():
            token = _get_csrf_token()
            assert token is not None
            assert len(token) == 64  # 32 bytes hex = 64 chars

    def test_get_csrf_token_reuses_existing(self):
        """Test that _get_csrf_token reuses existing token"""
        from flask import Flask

        app = Flask(__name__)
        app.secret_key = "test_secret"

        with app.test_request_context():
            token1 = _get_csrf_token()
            token2 = _get_csrf_token()
            assert token1 == token2

    def test_verify_csrf_token_valid(self):
        """Test that _verify_csrf_token verifies valid token"""
        from flask import Flask

        app = Flask(__name__)
        app.secret_key = "test_secret"

        with app.test_request_context():
            token = _get_csrf_token()
            assert _verify_csrf_token(token) is True

    def test_verify_csrf_token_invalid(self):
        """Test that _verify_csrf_token rejects invalid token"""
        from flask import Flask

        app = Flask(__name__)
        app.secret_key = "test_secret"

        with app.test_request_context():
            _get_csrf_token()
            assert _verify_csrf_token("invalid_token") is False

    def test_verify_csrf_token_empty(self):
        """Test that _verify_csrf_token handles empty token"""
        from flask import Flask

        app = Flask(__name__)
        app.secret_key = "test_secret"

        with app.test_request_context():
            assert _verify_csrf_token("") is False
            assert _verify_csrf_token(None) is False


class TestRequireAuth:
    """Tests for require_auth decorator"""

    def test_require_auth_allows_authenticated(self):
        """Test that require_auth allows authenticated users"""
        from flask import Flask

        app = Flask(__name__)
        app.secret_key = "test_secret"

        @app.route("/test")
        @require_auth
        def test_route():
            return "success"

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["username"] = "testuser"
            response = client.get("/test")
            assert response.status_code == 200

    def test_require_auth_redirects_unauthenticated(self):
        """Test that require_auth redirects unauthenticated users"""
        from flask import Flask

        app = Flask(__name__)
        app.secret_key = "test_secret"

        # Register auth routes so url_for works
        register_auth_routes(app)

        @app.route("/test")
        @require_auth
        def test_route():
            return "success"

        with app.test_client() as client:
            response = client.get("/test")
            assert response.status_code == 302  # Redirect

    def test_require_auth_returns_json_for_api(self):
        """Test that require_auth returns JSON for API requests"""
        from flask import Flask

        app = Flask(__name__)
        app.secret_key = "test_secret"

        @app.route("/api/test")
        @require_auth
        def test_route():
            return {"success": True}

        with app.test_client() as client:
            response = client.get("/api/test", headers={"Content-Type": "application/json"})
            assert response.status_code == 401
            assert response.is_json


class TestRequireAdmin:
    """Tests for require_admin decorator"""

    @patch("dashboard.auth_routes.is_admin")
    def test_require_admin_allows_admin(self, mock_is_admin):
        """Test that require_admin allows admin users"""
        from flask import Flask

        app = Flask(__name__)
        app.secret_key = "test_secret"
        mock_is_admin.return_value = True

        @app.route("/admin")
        @require_admin
        def admin_route():
            return "admin"

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["username"] = "admin"
            response = client.get("/admin")
            assert response.status_code == 200

    @patch("dashboard.auth_routes.is_admin")
    def test_require_admin_denies_non_admin(self, mock_is_admin):
        """Test that require_admin denies non-admin users"""
        from flask import Flask

        app = Flask(__name__)
        app.secret_key = "test_secret"
        mock_is_admin.return_value = False

        # Register auth routes so url_for works
        register_auth_routes(app)

        # Add index route that require_admin redirects to
        @app.route("/")
        def index():
            return "index"

        @app.route("/admin")
        @require_admin
        def admin_route():
            return "admin"

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["username"] = "user"
            response = client.get("/admin")
            assert response.status_code == 302  # Redirect

    @patch("dashboard.auth_routes.is_admin")
    def test_require_admin_returns_json_for_api(self, mock_is_admin):
        """Test that require_admin returns JSON for API requests"""
        from flask import Flask

        app = Flask(__name__)
        app.secret_key = "test_secret"
        mock_is_admin.return_value = False

        @app.route("/api/admin")
        @require_admin
        def admin_route():
            return {"success": True}

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["username"] = "user"
            response = client.get("/api/admin", headers={"Content-Type": "application/json"})
            assert response.status_code == 403
            assert response.is_json


class TestAuthRoutes:
    """Tests for authentication routes"""

    @pytest.fixture
    def app(self):
        """Create Flask app with auth routes"""
        from flask import Flask

        app = Flask(__name__)
        app.secret_key = os.getenv("CUSTOSEYE_SESSION_SECRET", "test_secret")
        app.config["TESTING"] = True

        # Add index route that auth routes redirect to
        @app.route("/")
        def index():
            return "index"

        register_auth_routes(app)
        return app

    @pytest.fixture
    def client(self, app):
        """Create test client"""
        return app.test_client()

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    @patch("dashboard.auth_routes.render_template")
    def test_login_get_renders_template(self, mock_render, client):
        """Test that GET /auth/login renders template"""
        mock_render.return_value = "rendered"
        response = client.get("/auth/login")
        assert response.status_code == 200
        mock_render.assert_called_once()

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_login_post_valid_credentials(self, client, tmp_path, monkeypatch):
        """Test that POST /auth/login works with valid credentials"""
        from dashboard import auth

        users_file = tmp_path / "users.json"
        users_file.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(auth, "USERS_DB_PATH", users_file)

        # Create user
        from dashboard.auth import create_user

        create_user("testuser", "TestPass1!")

        # Get CSRF token by making a request first (mock template to avoid TemplateNotFound)
        with patch("dashboard.auth_routes.render_template", return_value="rendered"):
            client.get("/auth/login")  # This generates CSRF token in session
        with client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token", "test_token")

        # Login
        response = client.post(
            "/auth/login",
            json={"username": "testuser", "password": "TestPass1!", "csrf_token": csrf_token},
        )
        assert response.status_code == 200
        assert response.is_json

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_login_post_invalid_credentials(self, client, tmp_path, monkeypatch):
        """Test that POST /auth/login rejects invalid credentials"""
        from dashboard import auth

        users_file = tmp_path / "users.json"
        users_file.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(auth, "USERS_DB_PATH", users_file)

        # Get CSRF token by making a request first (mock template to avoid TemplateNotFound)
        with patch("dashboard.auth_routes.render_template", return_value="rendered"):
            client.get("/auth/login")  # This generates CSRF token in session
        with client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token", "test_token")

        # Try to login with invalid credentials
        response = client.post(
            "/auth/login",
            json={"username": "testuser", "password": "WrongPass1!", "csrf_token": csrf_token},
        )
        assert response.status_code == 401

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    @patch("dashboard.auth_routes.render_template")
    def test_signup_get_renders_template(self, mock_render, client, tmp_path, monkeypatch):
        """Test that GET /auth/signup renders template"""
        from dashboard import auth

        users_file = tmp_path / "users.json"
        users_file.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(auth, "USERS_DB_PATH", users_file)

        mock_render.return_value = "rendered"
        response = client.get("/auth/signup")
        assert response.status_code == 200
        mock_render.assert_called_once()

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_signup_post_creates_user(self, client, tmp_path, monkeypatch):
        """Test that POST /auth/signup creates user"""
        from dashboard import auth

        users_file = tmp_path / "users.json"
        users_file.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(auth, "USERS_DB_PATH", users_file)

        # Get CSRF token by making a request first (mock template to avoid TemplateNotFound)
        with patch("dashboard.auth_routes.render_template", return_value="rendered"):
            client.get("/auth/signup")  # This generates CSRF token in session
            with client.session_transaction() as sess:
                csrf_token = sess.get("csrf_token", "test_token")

        # Signup
        response = client.post(
            "/auth/signup",
            json={
                "username": "newuser",
                "password": "TestPass1!",
                "confirmPassword": "TestPass1!",
                "csrf_token": csrf_token,
            },
        )
        assert response.status_code == 200
        assert response.is_json

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_logout_clears_session(self, client):
        """Test that POST /auth/logout clears session"""
        with client.session_transaction() as sess:
            sess["username"] = "testuser"

        # Get CSRF token by making a request first (mock template to avoid TemplateNotFound)
        with patch("dashboard.auth_routes.render_template", return_value="rendered"):
            client.get("/auth/login")  # This generates CSRF token in session
        with client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token", "test_token")

        response = client.post("/auth/logout", json={"csrf_token": csrf_token})
        assert response.status_code == 200

        # Verify session is cleared
        with client.session_transaction() as sess:
            assert "username" not in sess

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    @patch("dashboard.auth_routes.render_template")
    def test_enable_2fa_get_renders_template(self, mock_render, client, tmp_path, monkeypatch):
        """Test that GET /auth/enable-2fa renders template"""
        from dashboard import auth

        users_file = tmp_path / "users.json"
        users_file.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(auth, "USERS_DB_PATH", users_file)

        from dashboard.auth import create_user

        create_user("testuser", "TestPass1!")

        with client.session_transaction() as sess:
            sess["username"] = "testuser"

        mock_render.return_value = "rendered"
        response = client.get("/auth/enable-2fa")
        assert response.status_code == 200
        mock_render.assert_called_once()

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    @patch("dashboard.auth_routes.render_template")
    def test_forgot_password_get_renders_template(self, mock_render, client):
        """Test that GET /auth/forgot-password renders template"""
        mock_render.return_value = "rendered"
        response = client.get("/auth/forgot-password")
        assert response.status_code == 200
        mock_render.assert_called_once()

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    @patch("dashboard.auth_routes.render_template")
    def test_forgot_username_get_renders_template(self, mock_render, client):
        """Test that GET /auth/forgot-username renders template"""
        mock_render.return_value = "rendered"
        response = client.get("/auth/forgot-username")
        assert response.status_code == 200
        mock_render.assert_called_once()
