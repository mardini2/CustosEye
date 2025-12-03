"""
goal: authentication and authorization module for CustosEye. handles user accounts, password hashing,
      TOTP 2FA, session management, CSRF protection, and brute-force protection. enforces single-admin
      rule (first registered user becomes admin, no second admin allowed).

expects these environment variables:
- CUSTOSEYE_SESSION_SECRET: secret key for Flask sessions (required)
- CUSTOSEYE_PASSWORD_PEPPER: additional secret for password hashing (required)
- CUSTOSEYE_TOTP_ISSUER: issuer name for TOTP QR codes (optional, defaults to "CustosEye")
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    import bcrypt

    HAVE_BCRYPT = True
except ImportError:
    HAVE_BCRYPT = False

try:
    from argon2 import PasswordHasher

    HAVE_ARGON2 = True
except ImportError:
    HAVE_ARGON2 = False

from io import BytesIO

import pyotp
import qrcode

# set up logging for auth events (no sensitive data)
auth_logger = logging.getLogger("custoseye.auth")
auth_logger.setLevel(logging.INFO)


# custom formatter to colorize usernames in purple/magenta
class ColoredUsernameFormatter(logging.Formatter):
    """custom formatter that colors usernames in log messages"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # try to import colorama for Windows ANSI support
        try:
            from colorama import init as _colorama_init

            _colorama_init()
            self.use_color = True
        except Exception:
            self.use_color = False

    def format(self, record):
        # get only the message without levelname or logger name prefix
        msg = record.getMessage()

        if not self.use_color:
            return msg

        # ANSI color codes
        purple = "\x1b[35m"  # magenta/purple
        golden = "\x1b[33m"  # yellow/golden
        green = "\x1b[32m"  # green
        reset = "\x1b[0m"  # reset

        # find usernames, "CustosEye", "2fa", and ✓ symbol in the message and color them
        # pattern: username appears after patterns like "User ", "for user: ", "Account created: "
        import re

        # handle patterns that include ✓ first (before coloring all ✓ symbols)
        # these patterns need special handling to color both ✓ and username
        patterns_with_checkmark = [
            (
                r"(✓ User )([a-zA-Z0-9_]+)",
                green + r"✓ " + reset + r"User " + purple + r"\2" + reset,
            ),  # "✓ User admin"
            (
                r"(✓ 2FA enabled for user: )([a-zA-Z0-9_]+)",
                green + r"✓ " + reset + r"2FA enabled for user: " + purple + r"\2" + reset,
            ),  # "✓ 2FA enabled for user: admin"
            (
                r"(✓ 2FA disabled for user: )([a-zA-Z0-9_]+)",
                green + r"✓ " + reset + r"2FA disabled for user: " + purple + r"\2" + reset,
            ),  # "✓ 2FA disabled for user: admin"
            (
                r"(✓ Account created: )([a-zA-Z0-9_]+)",
                green + r"✓ " + reset + r"Account created: " + purple + r"\2" + reset,
            ),  # "✓ Account created: admin"
        ]

        for pattern, replacement in patterns_with_checkmark:
            msg = re.sub(pattern, replacement, msg)

        # color any remaining ✓ symbols green (those not part of the patterns above)
        msg = re.sub(r"(✓)", green + r"\1" + reset, msg)

        # match usernames that appear after common patterns (without ✓)
        # examples: "User admin logged in" or "for user: admin" or "Account created: admin"
        patterns = [
            (r"(User )([a-zA-Z0-9_]+)", r"\1" + purple + r"\2" + reset),  # "User admin"
            (r"(for user: )([a-zA-Z0-9_]+)", r"\1" + purple + r"\2" + reset),  # "for user: admin"
            (
                r"(Account created: )([a-zA-Z0-9_]+)",
                r"\1" + purple + r"\2" + reset,
            ),  # "Account created: admin"
            (r"(CustosEye)", purple + r"\1" + reset),  # "CustosEye" anywhere in the message
            (r"(2fa)", golden + r"\1" + reset),  # "2fa" anywhere in the message (case-insensitive)
            (r"(2FA)", golden + r"\1" + reset),  # "2FA" anywhere in the message
        ]

        for pattern, replacement in patterns:
            msg = re.sub(pattern, replacement, msg)

        return msg


# set up the custom formatter for auth logger
# format only shows the message without levelname or logger name prefix for better UX
# use SpinnerStatusHandler from console.py if available to coordinate with spinner animation
handler: logging.Handler
try:
    # Lazy import to avoid circular dependency - console.py imports dashboard modules
    # This import only happens when auth.py is loaded, which is after console.py starts
    from app.console import SpinnerStatusHandler

    handler = SpinnerStatusHandler()
except (ImportError, AttributeError):
    # Fall back to StreamHandler if console.py handler is not available
    handler = logging.StreamHandler()

handler.setFormatter(ColoredUsernameFormatter("%(message)s"))
auth_logger.addHandler(handler)
auth_logger.propagate = False  # prevent duplicate messages

# load secrets from environment
SESSION_SECRET = os.getenv("CUSTOSEYE_SESSION_SECRET")
PASSWORD_PEPPER = os.getenv("CUSTOSEYE_PASSWORD_PEPPER")
TOTP_ISSUER = os.getenv("CUSTOSEYE_TOTP_ISSUER", "CustosEye")

if not SESSION_SECRET:
    raise ValueError("CUSTOSEYE_SESSION_SECRET environment variable is required")
if not PASSWORD_PEPPER:
    raise ValueError("CUSTOSEYE_PASSWORD_PEPPER environment variable is required")

# type assertions: after validation, these are guaranteed to be strings
assert SESSION_SECRET is not None
assert PASSWORD_PEPPER is not None

# user database path (stored in data directory)
BASE_DIR = Path(__file__).resolve().parents[1]
USERS_DB_PATH = BASE_DIR / "data" / "users.json"

# brute force protection: track failed login attempts
FAILED_ATTEMPTS: dict[str, list[float]] = defaultdict(list)
LOCKOUT_DURATION = 300  # 5 minutes
MAX_ATTEMPTS = 5
ATTEMPT_WINDOW = 600  # 10 minutes


def _normalize_username(username: str) -> str:
    """normalize username to lowercase for case-insensitive comparison"""
    return username.lower() if username else ""


def _load_users() -> dict[str, dict[str, Any]]:
    """load user database from JSON file"""
    if not USERS_DB_PATH.exists():
        return {}
    try:
        with open(USERS_DB_PATH, encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _save_users(users: dict[str, dict[str, Any]]) -> None:
    """save user database to JSON file"""
    USERS_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(USERS_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def _hash_password(password: str) -> str:
    """hash password with pepper and strong algorithm (Argon2 preferred, bcrypt fallback)"""
    # combine password with pepper (PASSWORD_PEPPER is guaranteed to be str after validation)
    assert PASSWORD_PEPPER is not None
    salted = password + PASSWORD_PEPPER

    if HAVE_ARGON2:
        ph = PasswordHasher()
        return ph.hash(salted)
    elif HAVE_BCRYPT:
        salt_bytes = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(salted.encode("utf-8"), salt_bytes).decode("utf-8")
    else:
        # fallback to SHA-256 with salt (not ideal, but better than nothing)
        salt_str = secrets.token_hex(32)
        return (
            f"sha256:{salt_str}:{hashlib.sha256((salted + salt_str).encode('utf-8')).hexdigest()}"
        )


def _verify_password(password: str, password_hash: str) -> bool:
    """verify password against hash"""
    # PASSWORD_PEPPER is guaranteed to be str after validation
    assert PASSWORD_PEPPER is not None
    salted = password + PASSWORD_PEPPER

    if password_hash.startswith("$argon2"):
        if not HAVE_ARGON2:
            return False
        try:
            ph = PasswordHasher()
            ph.verify(password_hash, salted)
            return True
        except Exception:
            return False
    elif password_hash.startswith("$2b$") or password_hash.startswith("$2a$"):
        if not HAVE_BCRYPT:
            return False
        try:
            return bcrypt.checkpw(salted.encode("utf-8"), password_hash.encode("utf-8"))
        except Exception:
            return False
    elif password_hash.startswith("sha256:"):
        # fallback SHA-256 verification
        parts = password_hash.split(":", 2)
        if len(parts) != 3:
            return False
        _, salt, expected = parts
        actual = hashlib.sha256((salted + salt).encode("utf-8")).hexdigest()
        return secrets.compare_digest(actual, expected)
    return False


def _check_brute_force(username: str) -> tuple[bool, str | None]:
    """check if user is locked out due to brute force attempts"""
    now = time.time()
    username_normalized = _normalize_username(username)
    attempts = FAILED_ATTEMPTS[username_normalized]

    # clean old attempts
    attempts[:] = [t for t in attempts if now - t < ATTEMPT_WINDOW]

    if len(attempts) >= MAX_ATTEMPTS:
        # check if lockout period has passed
        oldest = min(attempts) if attempts else 0
        if now - oldest < LOCKOUT_DURATION:
            remaining = int(LOCKOUT_DURATION - (now - oldest))
            return False, f"Account locked. Try again in {remaining} seconds."
        else:
            # lockout expired, clear attempts
            attempts.clear()

    return True, None


def _record_failed_attempt(username: str) -> None:
    """record a failed login attempt"""
    now = time.time()
    username_normalized = _normalize_username(username)
    FAILED_ATTEMPTS[username_normalized].append(now)
    auth_logger.warning(f"Failed login attempt for user: {username_normalized}")


def _clear_failed_attempts(username: str) -> None:
    """clear failed attempts after successful login"""
    username_normalized = _normalize_username(username)
    FAILED_ATTEMPTS.pop(username_normalized, None)


def create_user(username: str, password: str) -> tuple[bool, str]:
    """create a new user account. only one account is allowed - the first registered user becomes admin."""
    users = _load_users()

    # enforce single account rule - only allow creating the first account
    if len(users) > 0:
        return False, "Only one account is allowed. An account already exists."

    # validate username: 2-25 characters, only letters and numbers, no spaces or special characters
    if not username:
        return False, "Username is required"
    username = username.strip()
    if len(username) < 2:
        return False, "Username must be at least 2 characters"
    if len(username) > 25:
        return False, "Username must be no more than 25 characters"
    if not username.isalnum():
        return (
            False,
            "Username must contain only letters and numbers (no spaces or special characters)",
        )
    if " " in username:
        return False, "Username cannot contain spaces"

    # normalize username to lowercase for case-insensitive storage
    username_lower = _normalize_username(username)
    if username_lower in {_normalize_username(u) for u in users.keys()}:
        return False, "Username already exists"

    # validate password using shared validation function
    valid, error = _validate_password(password)
    if not valid:
        return False, error

    # first (and only) user is always admin
    is_admin = True

    # hash password
    password_hash = _hash_password(password)

    # normalize username to lowercase for case-insensitive storage and lookup
    username_normalized = _normalize_username(username)

    # create user record - store with lowercase username as key for case-insensitive lookup
    users[username_normalized] = {
        "username": username_normalized,
        "password_hash": password_hash,
        "totp_secret": None,
        "totp_enabled": False,
        "backup_codes": [],
        "is_admin": is_admin,
        "created_at": time.time(),
    }

    _save_users(users)
    admin_status = "admin" if is_admin else "user"
    auth_logger.info(f"✓ Account created: {username_normalized} ({admin_status})")

    return True, "User created successfully"


def verify_user(username: str, password: str) -> tuple[bool, str | None]:
    """verify username and password"""
    # normalize username to lowercase for case-insensitive lookup
    username_normalized = _normalize_username(username)

    # check brute force protection
    can_login, error = _check_brute_force(username_normalized)
    if not can_login:
        return False, error

    users = _load_users()
    user = users.get(username_normalized)

    if not user:
        _record_failed_attempt(username_normalized)
        return False, "Invalid username or password"

    if not _verify_password(password, user["password_hash"]):
        _record_failed_attempt(username_normalized)
        return False, "Invalid username or password"

    # successful login (without 2FA verification - that's logged separately in the route)
    _clear_failed_attempts(username_normalized)
    # don't log here - let the route handler log with 2FA context
    return True, None


def get_user(username: str) -> dict[str, Any] | None:
    """get user record by username (case-insensitive)"""
    users = _load_users()
    username_normalized = _normalize_username(username)
    return users.get(username_normalized)


def is_admin(username: str) -> bool:
    """check if user is admin"""
    user = get_user(username)
    if not user:
        return False
    return bool(user.get("is_admin", False))


def generate_totp_secret(username: str) -> str:
    """generate a new TOTP secret for a user"""
    return pyotp.random_base32()


def get_totp_uri(username: str, secret: str) -> str:
    """generate TOTP URI for QR code"""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=TOTP_ISSUER)


def generate_qr_code(uri: str) -> str:
    """generate QR code as base64 data URL"""
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"


def verify_totp(secret: str, token: str) -> bool:
    """verify TOTP token (6-digit code from authenticator app)"""
    if not secret or not token:
        return False
    try:
        # strip whitespace and ensure token is numeric
        token = token.strip().replace(" ", "")
        if not token.isdigit():
            return False
        # TOTP codes are typically 6 digits
        if len(token) != 6:
            return False
        totp = pyotp.TOTP(secret)
        # verify with a small time window (current and previous/next 30-second window)
        # valid_window=1 means we accept current window and 1 window before/after (total 3 windows = 90 seconds)
        return totp.verify(token, valid_window=1)
    except Exception as e:
        auth_logger.warning(f"TOTP verification error: {e}")
        return False


def generate_backup_codes(count: int = 10) -> list[str]:
    """generate backup codes for 2FA"""
    return [secrets.token_hex(4).upper() for _ in range(count)]


def verify_backup_code(user: dict[str, Any], code: str) -> bool:
    """verify a backup code and remove it if valid. backup codes are 8-character hex strings."""
    codes = user.get("backup_codes", [])
    # normalize: strip whitespace, convert to uppercase, remove any dashes/spaces
    code_upper = code.upper().strip().replace("-", "").replace(" ", "")

    # backup codes should be 8 hex characters
    if len(code_upper) != 8:
        return False

    # check if code is in the list (case-insensitive match)
    if code_upper in codes:
        # remove used code
        codes.remove(code_upper)
        users = _load_users()
        users[user["username"]]["backup_codes"] = codes
        _save_users(users)
        auth_logger.info(f"Backup code used for user: {user['username']}")
        return True
    return False


def enable_2fa(username: str, secret: str, token: str) -> tuple[bool, str]:
    """enable 2FA for a user after verifying the token"""
    username_normalized = _normalize_username(username)
    users = _load_users()
    user = users.get(username_normalized)

    if not user:
        return False, "User not found"

    # verify token
    if not verify_totp(secret, token):
        return False, "Invalid verification code"

    # generate backup codes
    backup_codes = generate_backup_codes()

    # update user
    user["totp_secret"] = secret
    user["totp_enabled"] = True
    user["backup_codes"] = backup_codes

    _save_users(users)
    auth_logger.info(f"✓ 2FA enabled for user: {username_normalized}")

    return True, "2FA enabled successfully"


def disable_2fa(username: str, token: str) -> tuple[bool, str]:
    """disable 2FA for a user after verifying the token one last time"""
    username_normalized = _normalize_username(username)
    users = _load_users()
    user = users.get(username_normalized)

    if not user:
        return False, "User not found"

    if not user.get("totp_enabled"):
        return False, "2FA is not enabled for this account"

    # verify token one last time before disabling
    secret = user.get("totp_secret")
    if not secret:
        return False, "2FA secret not found"

    if not verify_totp(secret, token):
        # also try backup code
        if not verify_backup_code(user, token):
            return (
                False,
                "Invalid 2FA code. Please enter the code from your authenticator app or use a backup code.",
            )

    # disable 2FA
    user["totp_enabled"] = False
    user["totp_secret"] = None
    user["backup_codes"] = []  # clear backup codes when disabling
    _save_users(users)
    auth_logger.info(f"✓ 2FA disabled for user: {username_normalized}")

    return True, "2FA disabled successfully"


def find_user_by_2fa_token(token: str) -> tuple[str | None, str | None]:
    """find a user by their 2FA token. returns (username, error) or (None, error) if not found."""
    users = _load_users()
    token_clean = token.strip()

    # check all users with 2FA enabled
    for username, user in users.items():
        if not user.get("totp_enabled"):
            continue

        secret = user.get("totp_secret")
        if not secret:
            continue

        # try TOTP code first
        if verify_totp(secret, token_clean):
            return username, None

        # try backup code
        if verify_backup_code(user, token_clean):
            return username, None

    return (
        None,
        "Invalid 2FA code. Please enter the code from your authenticator app or use a backup code.",
    )


def verify_2fa(username: str, token: str) -> tuple[bool, str | None]:
    """verify 2FA token or backup code. 2FA is always required if enabled."""
    user = get_user(username)

    if not user:
        return False, "User not found"

    # if 2FA is not enabled, return success (skip verification)
    if not user.get("totp_enabled"):
        return True, None

    # 2FA is enabled - token is required
    if not token:
        return False, "2FA code is required"

    secret = user.get("totp_secret")
    if not secret:
        return False, "2FA not properly configured. Please contact support."

    # normalize token (strip whitespace)
    token_clean = token.strip()

    # try backup code first (8-character hex string) - backup codes are longer
    # backup codes are 8 hex characters, so if it's 8 chars, try backup code first
    if len(token_clean.replace("-", "").replace(" ", "")) == 8:
        if verify_backup_code(user, token_clean):
            return True, None
        # if backup code failed, continue to try TOTP (user might have typed wrong)

    # try TOTP (normal 6-digit code from authenticator app)
    if verify_totp(secret, token_clean):
        return True, None

    # if we tried backup code and it failed, mention it in the error
    if len(token_clean.replace("-", "").replace(" ", "")) == 8:
        return (
            False,
            "Invalid backup code. Please check your backup codes or try the 6-digit code from your authenticator app.",
        )

    return (
        False,
        "Invalid 2FA code. Please enter the 6-digit code from your authenticator app, or use an 8-character backup code.",
    )


def reset_password_with_2fa(username: str, new_password: str, token: str) -> tuple[bool, str]:
    """reset password after verifying 2FA"""
    username_normalized = _normalize_username(username)

    # verify 2FA first
    valid, error = verify_2fa(username_normalized, token)
    if not valid:
        return False, error or "2FA verification failed"

    # validate new password using shared validation function
    valid, error = _validate_password(new_password)
    if not valid:
        return False, error

    users = _load_users()
    user = users.get(username_normalized)

    if not user:
        return False, "User not found"

    # check if new password is the same as the old password
    old_password_hash = user.get("password_hash")
    if old_password_hash and _verify_password(new_password, old_password_hash):
        return False, "New password must be different from your current password"

    # update password
    user["password_hash"] = _hash_password(new_password)
    _save_users(users)
    auth_logger.info(f"Password reset for user: {username_normalized}")

    return True, "Password reset successfully"


def _validate_password(password: str) -> tuple[bool, str]:
    """validate password meets requirements: at least 8 chars, capital, number, special char, no spaces"""
    if not password:
        return False, "Password is required"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if " " in password:
        return False, "Password cannot contain spaces"
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/~`" for c in password)

    if not has_upper:
        return False, "Password must include at least one capital letter"
    if not has_digit:
        return False, "Password must include at least one number"
    if not has_special:
        return (
            False,
            "Password must include at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?/~`)",
        )
    return True, ""


def change_password(username: str, old_password: str, new_password: str) -> tuple[bool, str]:
    """change password (requires old password)"""
    username_normalized = _normalize_username(username)

    # verify old password
    valid, error = verify_user(username_normalized, old_password)
    if not valid:
        return False, error or "Invalid current password"

    # validate new password using shared validation function
    valid, error = _validate_password(new_password)
    if not valid:
        return False, error

    # check if new password is the same as the old password
    if old_password == new_password:
        return False, "New password must be different from your current password"

    users = _load_users()
    user = users.get(username_normalized)

    if not user:
        return False, "User not found"

    # double-check by verifying the new password doesn't match the old hash
    old_password_hash = user.get("password_hash")
    if old_password_hash and _verify_password(new_password, old_password_hash):
        return False, "New password must be different from your current password"

    # update password
    user["password_hash"] = _hash_password(new_password)
    _save_users(users)
    auth_logger.info(f"Password changed for user: {username_normalized}")

    return True, "Password changed successfully"
