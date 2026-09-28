# backend/auth/schemas.py

"""
AutoRev Authentication API Schemas

These schemas define the public authentication API.

Important:
- Client registration does NOT accept subscription tier.
- Subscription entitlement is controlled server-side.
- Passwords are accepted only for authentication operations.
- Passwords and password hashes are never returned in responses.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# =============================================================================
# Registration
# =============================================================================

class UserCreate(BaseModel):
    """
    Public registration request.

    Subscription tier is intentionally NOT included.

    Every newly registered account is created as FREE by the backend.
    """

    email: EmailStr = Field(
        ...,
        max_length=255,
    )

    username: str = Field(
        ...,
        min_length=3,
        max_length=100,
    )

    password: str = Field(
        ...,
        min_length=12,
        max_length=128,
    )

    full_name: str | None = Field(
        default=None,
        max_length=200,
    )


# =============================================================================
# Login
# =============================================================================

class UserLogin(BaseModel):
    """Login credentials."""

    email: EmailStr = Field(
        ...,
        max_length=255,
    )

    password: str = Field(
        ...,
        min_length=1,
        max_length=128,
    )


# =============================================================================
# User response
# =============================================================================

class UserOut(BaseModel):
    """
    Safe public representation of an authenticated user.

    Sensitive fields such as hashed_password are intentionally excluded.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int

    email: EmailStr

    username: str

    full_name: str | None

    is_active: bool

    is_verified: bool

    created_at: datetime

    last_login: datetime | None

    tier: str

    tier_expires_at: datetime | None

    uploads_this_month: int

    uploads_remaining: int | None


# =============================================================================
# Authentication token response
# =============================================================================

class Token(BaseModel):
    """
    Successful authentication response.
    """

    access_token: str

    token_type: str = "bearer"

    user: UserOut