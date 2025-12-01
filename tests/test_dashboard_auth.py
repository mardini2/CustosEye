"""
Tests for dashboard.auth - Authentication core functionality
Tests user creation, password hashing, 2FA, and authentication logic.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pyotp
import pytest

from dashboard.auth import (
    _check_brute_force,
    _clear_failed_attempts,
    _hash_password,
    _normalize_username,
    _record_failed_attempt,
    _validate_password,
    _verify_password,
    change_password,
    create_user,
    disable_2fa,
    enable_2fa,
    generate_backup_codes,
    generate_qr_code,
    generate_totp_secret,
    get_totp_uri,
    get_user,
    is_admin,
    reset_password_with_2fa,
    verify_2fa,
    verify_backup_code,
    verify_totp,
    verify_user,
)


@pytest.fixture
def tmp_users_db(tmp_path, monkeypatch):
    """Create temporary users database"""
    users_file = tmp_path / "users.json"
    users_file.write_text("{}", encoding="utf-8")

    # Monkeypatch the USERS_DB_PATH
    from dashboard import auth

    monkeypatch.setattr(auth, "USERS_DB_PATH", users_file)

    return users_file


class TestNormalizeUsername:
    """Tests for _normalize_username function"""

    def test_normalize_username_lowercase(self):
        """Test that username is normalized to lowercase"""
        assert _normalize_username("TestUser") == "testuser"
        assert _normalize_username("ADMIN") == "admin"

    def test_normalize_username_handles_none(self):
        """Test that _normalize_username handles None"""
        assert _normalize_username(None) == ""

    def test_normalize_username_handles_empty(self):
        """Test that _normalize_username handles empty string"""
        assert _normalize_username("") == ""


class TestPasswordValidation:
    """Tests for password validation"""

    def test_validate_password_too_short(self):
        """Test that password must be at least 8 characters"""
        valid, error = _validate_password("Short1!")
        assert not valid
        assert "8 characters" in error

    def test_validate_password_missing_uppercase(self):
        """Test that password requires uppercase letter"""
        valid, error = _validate_password("lowercase1!")
        assert not valid
        assert "capital" in error.lower()

    def test_validate_password_missing_digit(self):
        """Test that password requires digit"""
        valid, error = _validate_password("NoDigit!")
        assert not valid
        assert "number" in error.lower()

    def test_validate_password_missing_special(self):
        """Test that password requires special character"""
        valid, error = _validate_password("NoSpecial1")
        assert not valid
        assert "special" in error.lower()

    def test_validate_password_contains_space(self):
        """Test that password cannot contain spaces"""
        valid, error = _validate_password("Has Space1!")
        assert not valid
        assert "space" in error.lower()

    def test_validate_password_valid(self):
        """Test that valid password passes"""
        valid, error = _validate_password("ValidPass1!")
        assert valid
        assert error == ""

    def test_validate_password_empty(self):
        """Test that empty password fails"""
        valid, error = _validate_password("")
        assert not valid
        assert "required" in error.lower()


class TestPasswordHashing:
    """Tests for password hashing"""

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_hash_password_creates_hash(self):
        """Test that _hash_password creates a hash"""
        hash_result = _hash_password("testpassword")
        assert hash_result is not None
        assert len(hash_result) > 0

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_verify_password_matches_hash(self):
        """Test that _verify_password verifies correct password"""
        password = "testpassword"
        hash_result = _hash_password(password)
        assert _verify_password(password, hash_result) is True

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_verify_password_rejects_wrong_password(self):
        """Test that _verify_password rejects wrong password"""
        password = "testpassword"
        hash_result = _hash_password(password)
        assert _verify_password("wrongpassword", hash_result) is False

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_verify_password_handles_invalid_hash(self):
        """Test that _verify_password handles invalid hash format"""
        assert _verify_password("password", "invalid_hash") is False


class TestUserManagement:
    """Tests for user management functions"""

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_create_user_first_user_is_admin(self, tmp_users_db):
        """Test that first user becomes admin"""
        success, message = create_user("admin", "TestPass1!")
        assert success
        assert is_admin("admin") is True

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_create_user_only_one_allowed(self, tmp_users_db):
        """Test that only one user can be created"""
        create_user("user1", "TestPass1!")
        success, message = create_user("user2", "TestPass2!")
        assert not success
        assert "one account" in message.lower()

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_create_user_validates_username(self, tmp_users_db):
        """Test that create_user validates username"""
        # Too short
        success, _ = create_user("a", "TestPass1!")
        assert not success

        # Too long
        success, _ = create_user("a" * 26, "TestPass1!")
        assert not success

        # Contains space
        success, _ = create_user("user name", "TestPass1!")
        assert not success

        # Contains special chars
        success, _ = create_user("user@name", "TestPass1!")
        assert not success

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_create_user_validates_password(self, tmp_users_db):
        """Test that create_user validates password"""
        success, message = create_user("admin", "weak")
        assert not success
        assert "password" in message.lower()

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_verify_user_correct_credentials(self, tmp_users_db):
        """Test that verify_user accepts correct credentials"""
        create_user("admin", "TestPass1!")
        valid, error = verify_user("admin", "TestPass1!")
        assert valid
        assert error is None

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_verify_user_wrong_password(self, tmp_users_db):
        """Test that verify_user rejects wrong password"""
        create_user("admin", "TestPass1!")
        valid, error = verify_user("admin", "WrongPass1!")
        assert not valid
        assert error is not None

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_verify_user_nonexistent_user(self, tmp_users_db):
        """Test that verify_user rejects nonexistent user"""
        valid, error = verify_user("nonexistent", "TestPass1!")
        assert not valid
        assert error is not None

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_get_user_retrieves_user(self, tmp_users_db):
        """Test that get_user retrieves user"""
        create_user("admin", "TestPass1!")
        user = get_user("admin")
        assert user is not None
        assert user["username"] == "admin"

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_get_user_case_insensitive(self, tmp_users_db):
        """Test that get_user is case-insensitive"""
        create_user("Admin", "TestPass1!")
        user = get_user("admin")
        assert user is not None
        assert user["username"] == "admin"  # Normalized to lowercase


class TestBruteForceProtection:
    """Tests for brute force protection"""

    def test_check_brute_force_allows_normal_login(self):
        """Test that _check_brute_force allows normal login"""
        can_login, error = _check_brute_force("testuser")
        assert can_login
        assert error is None

    def test_record_failed_attempt_tracks_attempts(self):
        """Test that _record_failed_attempt records attempts"""
        from dashboard.auth import FAILED_ATTEMPTS

        FAILED_ATTEMPTS.clear()
        _record_failed_attempt("testuser")
        assert len(FAILED_ATTEMPTS["testuser"]) > 0

    def test_check_brute_force_locks_after_max_attempts(self):
        """Test that _check_brute_force locks after max attempts"""
        from dashboard.auth import FAILED_ATTEMPTS, MAX_ATTEMPTS

        FAILED_ATTEMPTS.clear()
        username = "testuser"

        # Record max attempts
        for _ in range(MAX_ATTEMPTS):
            _record_failed_attempt(username)

        can_login, error = _check_brute_force(username)
        assert not can_login
        assert "locked" in error.lower()

    def test_clear_failed_attempts_clears_attempts(self):
        """Test that _clear_failed_attempts clears attempts"""
        from dashboard.auth import FAILED_ATTEMPTS

        FAILED_ATTEMPTS.clear()
        username = "testuser"
        _record_failed_attempt(username)
        _clear_failed_attempts(username)
        assert username not in FAILED_ATTEMPTS


class Test2FA:
    """Tests for 2FA functionality"""

    def test_generate_totp_secret_creates_secret(self):
        """Test that generate_totp_secret creates a secret"""
        secret = generate_totp_secret("testuser")
        assert secret is not None
        assert len(secret) > 0

    def test_get_totp_uri_creates_uri(self):
        """Test that get_totp_uri creates a valid URI"""
        secret = generate_totp_secret("testuser")
        uri = get_totp_uri("testuser", secret)
        assert uri.startswith("otpauth://")
        assert "testuser" in uri

    def test_generate_qr_code_creates_image(self):
        """Test that generate_qr_code creates base64 image"""
        secret = generate_totp_secret("testuser")
        uri = get_totp_uri("testuser", secret)
        qr_code = generate_qr_code(uri)
        assert qr_code.startswith("data:image/png;base64,")

    def test_verify_totp_valid_code(self):
        """Test that verify_totp verifies valid code"""
        secret = generate_totp_secret("testuser")
        totp = pyotp.TOTP(secret)
        code = totp.now()
        assert verify_totp(secret, code) is True

    def test_verify_totp_invalid_code(self):
        """Test that verify_totp rejects invalid code"""
        secret = generate_totp_secret("testuser")
        assert verify_totp(secret, "000000") is False

    def test_verify_totp_handles_none(self):
        """Test that verify_totp handles None values"""
        assert verify_totp(None, "123456") is False
        assert verify_totp("secret", None) is False

    def test_generate_backup_codes_creates_codes(self):
        """Test that generate_backup_codes creates codes"""
        codes = generate_backup_codes()
        assert len(codes) == 10
        assert all(len(code) == 8 for code in codes)

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_enable_2fa_enables_2fa(self, tmp_users_db):
        """Test that enable_2fa enables 2FA for user"""
        create_user("admin", "TestPass1!")
        secret = generate_totp_secret("admin")
        totp = pyotp.TOTP(secret)
        code = totp.now()

        success, message = enable_2fa("admin", secret, code)
        assert success

        user = get_user("admin")
        assert user["totp_enabled"] is True
        assert user["totp_secret"] == secret
        assert len(user["backup_codes"]) == 10

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_enable_2fa_requires_valid_code(self, tmp_users_db):
        """Test that enable_2fa requires valid code"""
        create_user("admin", "TestPass1!")
        secret = generate_totp_secret("admin")

        success, message = enable_2fa("admin", secret, "000000")
        assert not success
        assert "invalid" in message.lower()

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_verify_2fa_skips_when_disabled(self, tmp_users_db):
        """Test that verify_2fa skips when 2FA is disabled"""
        create_user("admin", "TestPass1!")
        valid, error = verify_2fa("admin", None)
        assert valid
        assert error is None

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_verify_2fa_requires_code_when_enabled(self, tmp_users_db):
        """Test that verify_2fa requires code when 2FA is enabled"""
        create_user("admin", "TestPass1!")
        secret = generate_totp_secret("admin")
        totp = pyotp.TOTP(secret)
        enable_2fa("admin", secret, totp.now())

        valid, error = verify_2fa("admin", None)
        assert not valid
        assert "required" in error.lower()

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_verify_backup_code_valid(self, tmp_users_db):
        """Test that verify_backup_code verifies valid backup code"""
        create_user("admin", "TestPass1!")
        secret = generate_totp_secret("admin")
        totp = pyotp.TOTP(secret)
        enable_2fa("admin", secret, totp.now())

        user = get_user("admin")
        backup_code = user["backup_codes"][0]

        assert verify_backup_code(user, backup_code) is True

        # Code should be removed after use
        user = get_user("admin")
        assert backup_code not in user["backup_codes"]

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_disable_2fa_disables_2fa(self, tmp_users_db):
        """Test that disable_2fa disables 2FA"""
        create_user("admin", "TestPass1!")
        secret = generate_totp_secret("admin")
        totp = pyotp.TOTP(secret)
        enable_2fa("admin", secret, totp.now())

        success, message = disable_2fa("admin", totp.now())
        assert success

        user = get_user("admin")
        assert user["totp_enabled"] is False
        assert user["totp_secret"] is None
        assert len(user["backup_codes"]) == 0


class TestPasswordReset:
    """Tests for password reset functionality"""

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_reset_password_with_2fa_resets_password(self, tmp_users_db):
        """Test that reset_password_with_2fa resets password"""
        create_user("admin", "OldPass1!")
        secret = generate_totp_secret("admin")
        totp = pyotp.TOTP(secret)
        enable_2fa("admin", secret, totp.now())

        success, message = reset_password_with_2fa("admin", "NewPass1!", totp.now())
        assert success

        # Should be able to login with new password
        valid, _ = verify_user("admin", "NewPass1!")
        assert valid

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_reset_password_requires_2fa(self, tmp_users_db):
        """Test that reset_password_with_2fa requires 2FA"""
        create_user("admin", "OldPass1!")
        secret = generate_totp_secret("admin")
        totp = pyotp.TOTP(secret)
        enable_2fa("admin", secret, totp.now())

        success, message = reset_password_with_2fa("admin", "NewPass1!", "000000")
        assert not success

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_change_password_changes_password(self, tmp_users_db):
        """Test that change_password changes password"""
        create_user("admin", "OldPass1!")

        success, message = change_password("admin", "OldPass1!", "NewPass1!")
        assert success

        # Should be able to login with new password
        valid, _ = verify_user("admin", "NewPass1!")
        assert valid

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_change_password_requires_old_password(self, tmp_users_db):
        """Test that change_password requires old password"""
        create_user("admin", "OldPass1!")

        success, message = change_password("admin", "WrongPass1!", "NewPass1!")
        assert not success

    @patch.dict(os.environ, {"CUSTOSEYE_PASSWORD_PEPPER": "test_pepper"})
    def test_change_password_rejects_same_password(self, tmp_users_db):
        """Test that change_password rejects same password"""
        create_user("admin", "TestPass1!")

        success, message = change_password("admin", "TestPass1!", "TestPass1!")
        assert not success
        assert "different" in message.lower()
