# SPDX-License-Identifier: GPL-3.0-or-later
"""
goal: authentication routes for CustosEye. handles login, signup, logout, 2FA setup, and password reset.
      protects routes with CSRF tokens and enforces authentication requirements.

expects these environment variables:
- CUSTOSEYE_SESSION_SECRET: secret key for Flask sessions (required)
- CUSTOSEYE_PASSWORD_PEPPER: additional secret for password hashing (required)
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from functools import wraps
from typing import Any

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from dashboard.auth import (
    change_password,
    create_user,
    disable_2fa,
    enable_2fa,
    find_user_by_2fa_token,
    generate_qr_code,
    generate_totp_secret,
    get_totp_uri,
    get_user,
    is_admin,
    reset_password_with_2fa,
    verify_2fa,
    verify_user,
)


def _get_csrf_token() -> str:
    """get or generate CSRF token for current session"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def _verify_csrf_token(token: str) -> bool:
    """verify CSRF token"""
    if not token:
        return False
    return token == session.get("csrf_token")


def require_auth(f: Callable) -> Callable:
    """decorator to require authentication"""

    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if not session.get("username"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("auth_login"))
        return f(*args, **kwargs)

    return decorated_function


def require_admin(f: Callable) -> Callable:
    """decorator to require admin privileges"""

    @wraps(f)
    @require_auth
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        username = session.get("username")
        if not username or not is_admin(username):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Admin privileges required"}), 403
            return redirect(url_for("index"))
        return f(*args, **kwargs)

    return decorated_function


def register_auth_routes(app: Flask) -> None:
    """register all authentication routes"""

    @app.route("/auth/login", methods=["GET", "POST"])
    def auth_login():
        """login page and handler"""
        if request.method == "GET":
            # if already logged in, redirect to dashboard
            if session.get("username"):
                return redirect(url_for("index"))
            # check if any account exists - if yes, hide signup link
            from dashboard.auth import _load_users

            users = _load_users()
            account_exists = len(users) > 0
            return render_template(
                "auth/login.html", csrf_token=_get_csrf_token(), account_exists=account_exists
            )

        # POST: handle login
        data = request.get_json() if request.is_json else request.form
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        csrf_token = data.get("csrf_token") or ""

        # verify CSRF
        if not _verify_csrf_token(csrf_token):
            return jsonify({"error": "Invalid CSRF token"}), 400

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        # normalize username to lowercase for case-insensitive authentication
        from dashboard.auth import _normalize_username

        username_normalized = _normalize_username(username)

        # verify user
        valid, error = verify_user(username_normalized, password)
        if not valid:
            return jsonify({"error": error or "Invalid credentials"}), 401

        # check if 2FA is enabled
        user = get_user(username_normalized)
        used_2fa = False
        if user and user.get("totp_enabled"):
            # require 2FA token
            token = data.get("totp_token") or ""
            if not token:
                return jsonify({"requires_2fa": True, "username": username_normalized}), 200

            # verify 2FA
            valid_2fa, error_2fa = verify_2fa(username_normalized, token)
            if not valid_2fa:
                return jsonify({"error": error_2fa or "Invalid 2FA code"}), 401

            used_2fa = True

        # successful login (non-persistent session - expires when browser closes)
        # store normalized username in session for consistency
        session["username"] = username_normalized
        session["is_admin"] = is_admin(username_normalized)
        # do not set session.permanent = True - we want session-only cookies
        # this makes sure users must login again when they restart the program

        # log successful login with 2FA status
        from dashboard.auth import auth_logger

        if used_2fa:
            auth_logger.info(f"✓ User {username_normalized} logged in successfully including 2FA")
        else:
            auth_logger.info(f"✓ User {username_normalized} logged in successfully")

        return jsonify({"success": True, "redirect": url_for("index")})

    @app.route("/auth/signup", methods=["GET", "POST"])
    def auth_signup():
        """signup page and handler"""
        if request.method == "GET":
            # if already logged in, redirect to dashboard
            if session.get("username"):
                return redirect(url_for("index"))
            # check if account already exists - if yes, redirect to login
            from dashboard.auth import _load_users

            users = _load_users()
            if len(users) > 0:
                # redirect to login with error message
                return redirect(url_for("auth_login") + "?error=account_exists")
            return render_template("auth/signup.html", csrf_token=_get_csrf_token())

        # POST: handle signup
        data = request.get_json() if request.is_json else request.form
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        confirm_password = data.get("confirmPassword") or ""
        csrf_token = data.get("csrf_token") or ""

        # verify CSRF
        if not _verify_csrf_token(csrf_token):
            return jsonify({"error": "Invalid CSRF token"}), 400

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        # check if passwords match (if confirmPassword was provided)
        if confirm_password and password != confirm_password:
            return jsonify({"error": "Passwords do not match"}), 400

        # create user (create_user will normalize username to lowercase)
        success, message = create_user(username, password)
        if not success:
            return jsonify({"error": message}), 400

        # normalize username for session storage
        from dashboard.auth import _normalize_username

        username_normalized = _normalize_username(username)

        # auto-login after signup (non-persistent session)
        # store normalized username in session for consistency
        session["username"] = username_normalized
        session["is_admin"] = is_admin(username_normalized)
        # do not set session.permanent = True - we want session-only cookies

        return jsonify({"success": True, "redirect": url_for("index")})

    @app.route("/auth/logout", methods=["POST"])
    def auth_logout():
        """logout handler - clears session and optionally shuts down the server"""
        username = session.get("username")
        session.clear()

        # check if user wants to shutdown the program
        data = request.get_json() if request.is_json else request.form
        shutdown_val = data.get("shutdown", "false")
        # handle both string and boolean values
        if isinstance(shutdown_val, bool):
            shutdown = shutdown_val
        else:
            shutdown = str(shutdown_val).lower() in ("true", "1", "yes")

        if username:
            from dashboard.auth import auth_logger

            if shutdown:
                auth_logger.info(f"✓ User {username} logged out\n\nShutting down CustosEye...\n")
            else:
                auth_logger.info(f"✓ User {username} logged out")

        if shutdown:
            # shutdown the Flask app (will stop the server)
            import os
            import threading

            # schedule shutdown in a separate thread to allow response to be sent
            def shutdown_server():
                import time

                time.sleep(0.5)  # give time for response to be sent
                # force exit the entire process (this will stop all threads including the dashboard)
                os._exit(0)

            threading.Thread(target=shutdown_server, daemon=False).start()
            return jsonify(
                {
                    "success": True,
                    "shutdown": True,
                    "message": "Shutting down CustosEye... Goodbye!",
                }
            )

        return jsonify({"success": True, "redirect": url_for("auth_login")})

    @app.route("/auth/shutdown", methods=["POST"])
    def auth_shutdown():
        """shutdown handler - shuts down the server without requiring authentication"""
        from dashboard.auth import auth_logger

        auth_logger.info("\nShutting down CustosEye...\n")
        # schedule shutdown in a separate thread to allow response to be sent
        import os
        import threading

        def shutdown_server():
            import time

            time.sleep(0.5)  # give time for response to be sent
            # force exit the entire process (this will stop all threads including the dashboard)
            os._exit(0)

        threading.Thread(target=shutdown_server, daemon=False).start()
        return jsonify(
            {"success": True, "shutdown": True, "message": "Shutting down CustosEye... Goodbye!"}
        )

    @app.route("/auth/enable-2fa", methods=["GET", "POST"])
    @require_auth
    def auth_enable_2fa():
        """enable 2FA page and handler. shows setup if not enabled, status if already enabled."""
        username = session.get("username")
        if not username:
            return redirect(url_for("auth_login"))

        user = get_user(username)
        if not user:
            return redirect(url_for("auth_login"))

        if request.method == "GET":
            # check if 2FA is already enabled
            totp_enabled = user.get("totp_enabled", False)

            if totp_enabled:
                # 2FA is already enabled - show status/verification page
                return render_template(
                    "auth/enable-2fa.html",
                    csrf_token=_get_csrf_token(),
                    qr_code=None,
                    secret=None,
                    totp_enabled=True,
                )

            # 2FA not enabled - show setup page
            secret = generate_totp_secret(username)
            uri = get_totp_uri(username, secret)
            qr_code = generate_qr_code(uri)
            # store secret temporarily in session for verification step
            session["pending_totp_secret"] = secret

            return render_template(
                "auth/enable-2fa.html",
                csrf_token=_get_csrf_token(),
                qr_code=qr_code,
                secret=secret,
                totp_enabled=False,
            )

        # POST: verify and enable 2FA
        data = request.get_json() if request.is_json else request.form
        token = (data.get("token") or "").strip()
        csrf_token = data.get("csrf_token") or ""

        # verify CSRF
        if not _verify_csrf_token(csrf_token):
            return jsonify({"error": "Invalid CSRF token"}), 400

        # check if token is empty before processing
        if not token:
            return (
                jsonify(
                    {
                        "error": "Verification code is required. Please enter the 6-digit code from your authenticator app."
                    }
                ),
                400,
            )

        # get secret from session (where we stored it during GET request)
        secret = session.get("pending_totp_secret")
        if not secret:
            # if no pending secret, generate a new one (shouldn't happen, but handle gracefully)
            secret = generate_totp_secret(username)
            session["pending_totp_secret"] = secret

        # enable 2FA
        success, message = enable_2fa(username, secret, token)
        if not success:
            return jsonify({"error": message}), 400

        # clear pending secret
        session.pop("pending_totp_secret", None)

        # get backup codes
        user = get_user(username)
        backup_codes = user.get("backup_codes", []) if user else []

        return jsonify(
            {
                "success": True,
                "backup_codes": backup_codes,
                "redirect": url_for("auth_backup_codes"),
            }
        )

    @app.route("/auth/verify-2fa", methods=["POST"])
    @require_auth
    def auth_verify_2fa():
        """verify 2FA token for users who already have 2FA enabled"""
        username = session.get("username")
        if not username:
            return jsonify({"error": "Not authenticated"}), 401

        data = request.get_json() if request.is_json else request.form
        token = data.get("token") or ""
        csrf_token = data.get("csrf_token") or ""

        # verify CSRF
        if not _verify_csrf_token(csrf_token):
            return jsonify({"error": "Invalid CSRF token"}), 400

        if not token:
            return jsonify({"error": "2FA code is required"}), 400

        # verify 2FA
        valid, error = verify_2fa(username, token)
        if not valid:
            return jsonify({"error": error or "Invalid 2FA code"}), 400

        return jsonify({"success": True, "message": "2FA verification successful"})

    @app.route("/auth/disable-2fa", methods=["POST"])
    @require_auth
    def auth_disable_2fa():
        """disable 2FA handler - requires double confirmation and 2FA code verification"""
        username = session.get("username")
        if not username:
            return jsonify({"error": "Not authenticated"}), 401

        user = get_user(username)
        if not user:
            return jsonify({"error": "User not found"}), 404

        if not user.get("totp_enabled"):
            return jsonify({"error": "2FA is not enabled"}), 400

        data = request.get_json() if request.is_json else request.form
        token = data.get("token") or ""
        csrf_token = data.get("csrf_token") or ""
        confirmed = data.get("confirmed", "false").lower() in ("true", "1", "yes")

        # verify CSRF
        if not _verify_csrf_token(csrf_token):
            return jsonify({"error": "Invalid CSRF token"}), 400

        if not confirmed:
            # first confirmation - return success but require token
            if not token:
                return (
                    jsonify(
                        {
                            "requires_confirmation": True,
                            "message": "Please enter your 2FA code to confirm disabling 2FA",
                        }
                    ),
                    200,
                )
            # if token provided but not confirmed, return error asking for confirmation
            return jsonify({"error": "Please confirm that you want to disable 2FA"}), 400

        if not token:
            return jsonify({"error": "2FA code is required to disable 2FA"}), 400

        # disable 2FA with token verification
        success, message = disable_2fa(username, token)
        if not success:
            return jsonify({"error": message}), 400

        return jsonify({"success": True, "message": "2FA has been disabled successfully"})

    @app.route("/auth/backup-codes", methods=["GET"])
    @require_auth
    def auth_backup_codes():
        """display backup codes after enabling 2FA"""
        username = session.get("username")
        if not username:
            return redirect(url_for("auth_login"))

        user = get_user(username)
        if not user:
            return redirect(url_for("auth_login"))

        backup_codes = user.get("backup_codes", [])

        return render_template("auth/backup-codes.html", backup_codes=backup_codes)

    @app.route("/auth/forgot-username", methods=["GET", "POST"])
    def auth_forgot_username():
        """forgot username page and handler - requires 2FA to reveal username"""
        if request.method == "GET":
            return render_template("auth/forgot-username.html", csrf_token=_get_csrf_token())

        # POST: handle username recovery request
        data = request.get_json() if request.is_json else request.form
        token = (data.get("token") or "").strip()
        csrf_token = data.get("csrf_token") or ""

        # verify CSRF
        if not _verify_csrf_token(csrf_token):
            return jsonify({"error": "Invalid CSRF token"}), 400

        if not token:
            return jsonify({"error": "2FA code is required"}), 400

        # find user by 2FA token
        username, error = find_user_by_2fa_token(token)

        if not username:
            return jsonify({"error": error or "Invalid 2FA code"}), 400

        from dashboard.auth import auth_logger

        auth_logger.info(f"Username recovered via 2FA: {username}")
        return jsonify(
            {"success": True, "username": username, "message": f"Your username is: {username}"}
        )

    @app.route("/auth/forgot-password", methods=["GET", "POST"])
    def auth_forgot_password():
        """forgot password page and handler"""
        if request.method == "GET":
            return render_template("auth/forgot-password.html", csrf_token=_get_csrf_token())

        # POST: handle password reset request
        data = request.get_json() if request.is_json else request.form
        username = (data.get("username") or "").strip()
        csrf_token = data.get("csrf_token") or ""

        # verify CSRF
        if not _verify_csrf_token(csrf_token):
            return jsonify({"error": "Invalid CSRF token"}), 400

        if not username:
            return jsonify({"error": "Username required"}), 400

        # normalize username for case-insensitive lookup
        from dashboard.auth import _normalize_username

        username_normalized = _normalize_username(username)
        user = get_user(username_normalized)
        if not user:
            # don not reveal if user exists
            return jsonify(
                {"success": True, "message": "If the user exists, instructions have been sent"}
            )

        # check if 2FA is enabled (required for password reset)
        if not user.get("totp_enabled"):
            return (
                jsonify(
                    {"error": "2FA must be enabled to reset password. Please contact support."}
                ),
                400,
            )

        # return success (we'll verify 2FA on the reset page)
        return jsonify(
            {
                "success": True,
                "username": username_normalized,
                "requires_2fa": True,
                "redirect": url_for("auth_reset_password", username=username_normalized),
            }
        )

    @app.route("/auth/reset-password", methods=["GET", "POST"])
    def auth_reset_password():
        """reset password page and handler"""
        username = request.args.get("username") or ""

        if request.method == "GET":
            if not username:
                return redirect(url_for("auth_forgot_password"))

            # normalize username for case-insensitive lookup
            from dashboard.auth import _normalize_username

            username_normalized = _normalize_username(username)
            user = get_user(username_normalized)
            if not user or not user.get("totp_enabled"):
                return redirect(url_for("auth_forgot_password"))

            return render_template(
                "auth/reset-password.html",
                csrf_token=_get_csrf_token(),
                username=username_normalized,
            )

        # POST: handle password reset
        data = request.get_json() if request.is_json else request.form
        username = (data.get("username") or "").strip()
        new_password = data.get("new_password") or ""
        token = data.get("token") or ""
        csrf_token = data.get("csrf_token") or ""

        # verify CSRF
        if not _verify_csrf_token(csrf_token):
            return jsonify({"error": "Invalid CSRF token"}), 400

        if not username or not new_password or not token:
            return jsonify({"error": "Username, new password, and 2FA token required"}), 400

        # normalize username for case-insensitive lookup
        from dashboard.auth import _normalize_username

        username_normalized = _normalize_username(username)

        # reset password with 2FA verification
        success, message = reset_password_with_2fa(username_normalized, new_password, token)
        if not success:
            return jsonify({"error": message}), 400

        return jsonify({"success": True, "redirect": url_for("auth_login")})

    @app.route("/auth/change-password", methods=["POST"])
    @require_auth
    def auth_change_password():
        """change password handler (requires old password)"""
        username = session.get("username")
        if not username:
            return jsonify({"error": "Not authenticated"}), 401

        data = request.get_json() if request.is_json else request.form
        old_password = data.get("old_password") or ""
        new_password = data.get("new_password") or ""
        csrf_token = data.get("csrf_token") or ""

        # verify CSRF
        if not _verify_csrf_token(csrf_token):
            return jsonify({"error": "Invalid CSRF token"}), 400

        if not old_password or not new_password:
            return jsonify({"error": "Old and new password required"}), 400

        # change password
        success, message = change_password(username, old_password, new_password)
        if not success:
            return jsonify({"error": message}), 400

        return jsonify({"success": True, "message": message})
