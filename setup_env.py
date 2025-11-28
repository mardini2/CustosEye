# SPDX-License-Identifier: GPL-3.0-or-later
#!/usr/bin/env python3
"""
goal: environment setup script for CustosEye. auto-generates .env file with secure secrets if it doesn't exist.
      makes it easy for new devs to get started without manually creating env files.
"""

import secrets
from pathlib import Path


def generate_secret(length: int = 32) -> str:
    """
    generate a random hex secret string. uses Python's secrets module which is cryptographically secure.
    length is in bytes, so length=32 gives a 64-character hex string.
    """
    return secrets.token_hex(length)


def setup_env() -> None:
    """
    main setup function. checks if .env exists, and if not, creates it with auto-generated secrets.
    this makes sure every dev gets unique secrets without manual work.
    """
    env_file = Path(".env")
    
    # if .env already exists, don't overwrite it - dev might have custom values
    if env_file.exists():
        print("[OK] .env file already exists")
        print("  Skipping setup. Delete .env if you want to regenerate.")
        return
    
    # generate secure random secrets for session and password hashing
    # these need to be random and unique for each installation
    session_secret = generate_secret(32)  # 64-char hex string for Flask sessions
    password_pepper = generate_secret(32)  # 64-char hex string for password hashing
    
    # build the .env file content with all required variables
    # keeping it simple with just the essentials
    env_content = f"""# =========================================
# CustosEye Environment Variables
# =========================================
# auto-generated secrets - keep this file secure and never commit it!
# see .env.example for documentation of what each variable does

# required: secret key for Flask sessions (auto-generated)
CUSTOSEYE_SESSION_SECRET={session_secret}

# required: additional secret for password hashing (auto-generated)
CUSTOSEYE_PASSWORD_PEPPER={password_pepper}

# optional: issuer name for TOTP QR codes (defaults to "CustosEye" if not set)
CUSTOSEYE_TOTP_ISSUER=CustosEye

# optional: enable HTTPS for secure cookies (set to "true" if using HTTPS)
# CUSTOSEYE_HTTPS=false
"""
    
    # write the .env file
    env_file.write_text(env_content, encoding="utf-8")
    
    print("[OK] Created .env file with auto-generated secrets")
    print("[OK] All required values have been filled in automatically")
    print("  Keep .env secure - it contains secrets and should never be committed!")


if __name__ == "__main__":
    # run the setup when script is executed directly
    setup_env()