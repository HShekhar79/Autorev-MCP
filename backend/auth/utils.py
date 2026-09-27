# backend/auth/utils.py

"""
AutoRev Authentication Security Utilities

Responsibilities:
- Argon2id password hashing
- Password verification
- JWT access-token creation
- JWT access-token validation

This module contains security primitives only.

HTTP routes belong in auth/routes.py.
FastAPI authentication dependencies belong in auth/dependencies.py.
"""

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from dotenv import load_dotenv
from pwdlib import PasswordHash


# =============================================================================
# Environment
# =============================================================================

# Load backend/.env when this module is imported.
load_dotenv()


# =============================================================================
# Password hashing
# =============================================================================

# pwdlib's recommended hasher uses Argon2id.
#
# We intentionally do NOT use:
# - passlib
# - bcrypt
#
password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """
    Hash a plaintext password using Argon2id.

    The plaintext password must never be stored or logged.
    """

    if not password:
        raise ValueError("Password cannot be empty.")

    return password_hash.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    """
    Verify a plaintext password against an Argon2id hash.

    Returns False rather than raising for invalid credentials.
    """

    if not plain_password or not hashed_password:
        return False

    return password_hash.verify(
        plain_password,
        hashed_password,
    )


# =============================================================================
# JWT configuration
# =============================================================================

JWT_ALGORITHM = "HS256"

JWT_ISSUER = "autorev"

JWT_AUDIENCE = "autorev-api"

JWT_TYPE = "access"

ACCESS_TOKEN_EXPIRE_MINUTES = 30


def get_jwt_secret() -> str:
    """
    Load the JWT signing secret.

    There is deliberately NO fallback/default secret.

    Authentication must fail safely if the secret is not configured.
    """

    secret = os.getenv("ARISE_SECRET_KEY")

    if not secret:
        raise RuntimeError(
            "ARISE_SECRET_KEY is not configured."
        )

    # HS256 requires a sufficiently strong secret.
    # Our generated secret is substantially longer than this minimum.
    if len(secret) < 32:
        raise RuntimeError(
            "ARISE_SECRET_KEY must be at least 32 characters long."
        )

    return secret


# =============================================================================
# JWT creation
# =============================================================================

def create_access_token(
    user_id: int,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a signed AutoRev access token.

    JWT claims:
    - sub: authenticated user ID
    - jti: unique token identifier
    - type: application-level token type
    - iss: token issuer
    - aud: intended API audience
    - iat: issued-at timestamp
    - exp: expiration timestamp

    The JWT header also contains:
    - typ: JWT
    """

    now = datetime.now(timezone.utc)

    if expires_delta is None:
        expires_delta = timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )

    expires_at = now + expires_delta

    payload = {
        "sub": str(user_id),
        "jti": str(uuid.uuid4()),
        "type": JWT_TYPE,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": expires_at,
    }

    return jwt.encode(
        payload,
        get_jwt_secret(),
        algorithm=JWT_ALGORITHM,
        headers={
            "typ": "JWT",
        },
    )


# =============================================================================
# JWT validation
# =============================================================================

def decode_access_token(token: str) -> dict[str, Any]:
    """
    Validate and decode an AutoRev access token.

    Validation includes:
    - signature
    - allowed algorithm
    - issuer
    - audience
    - required claims
    - expiration
    - token type
    - subject format
    - JWT header type
    """

    if not token:
        raise ValueError("Authentication token is required.")

    try:
        # Decode header first so the token type can be explicitly checked.
        header = jwt.get_unverified_header(token)

        if header.get("typ") != "JWT":
            raise ValueError("Invalid JWT type.")

        payload = jwt.decode(
            token,
            get_jwt_secret(),
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={
                "require": [
                    "sub",
                    "jti",
                    "type",
                    "iss",
                    "aud",
                    "iat",
                    "exp",
                ],
            },
        )

    except jwt.ExpiredSignatureError as exc:
        raise ValueError("Authentication token has expired.") from exc

    except jwt.InvalidTokenError as exc:
        raise ValueError("Invalid authentication token.") from exc

    if payload.get("type") != JWT_TYPE:
        raise ValueError("Invalid authentication token type.")

    subject = payload.get("sub")

    if not subject:
        raise ValueError("Authentication token has no subject.")

    try:
        user_id = int(subject)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid authentication subject.") from exc

    if user_id <= 0:
        raise ValueError("Invalid authentication subject.")

    jti = payload.get("jti")

    if not jti:
        raise ValueError("Authentication token has no token ID.")

    return payload