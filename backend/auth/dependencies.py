# backend/auth/dependencies.py

"""
AutoRev Authentication Dependencies

Responsibilities:
- Extract Bearer access tokens
- Validate JWT access tokens
- Resolve the authenticated User
- Provide optional authentication
- Provide reusable ownership checks

This module does NOT:
- create users
- authenticate passwords
- create tokens
- enforce subscription quotas

Those responsibilities belong elsewhere.
"""

from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from database import get_db
from models import User

from auth.utils import decode_access_token


# =============================================================================
# Bearer authentication
# =============================================================================

bearer_scheme = HTTPBearer(
    auto_error=False,
)


# =============================================================================
# Authentication errors
# =============================================================================

def authentication_required() -> HTTPException:
    """
    Standard authentication failure response.

    We intentionally avoid revealing whether:
    - the token was malformed
    - the user exists
    - the user was deleted
    """

    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required.",
        headers={
            "WWW-Authenticate": "Bearer",
        },
    )


# =============================================================================
# Current authenticated user
# =============================================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
    db: Session = Depends(get_db),
) -> User:
    """
    Resolve the currently authenticated AutoRev user.

    Flow:

        Authorization: Bearer <JWT>
                    ↓
             decode JWT
                    ↓
             extract user ID
                    ↓
             database lookup
                    ↓
             active User
    """

    if credentials is None:
        raise authentication_required()

    # HTTPBearer normally gives us "Bearer", but explicitly verify it.
    if credentials.scheme.lower() != "bearer":
        raise authentication_required()

    token = credentials.credentials

    try:
        payload = decode_access_token(token)
    except ValueError:
        raise authentication_required()

    subject = payload.get("sub")

    if not subject:
        raise authentication_required()

    try:
        user_id = int(subject)
    except (TypeError, ValueError):
        raise authentication_required()

    if user_id <= 0:
        raise authentication_required()

    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if user is None:
        raise authentication_required()

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive.",
        )

    return user


# =============================================================================
# Optional authentication
# =============================================================================

def get_current_user_optional(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """
    Return the authenticated user when a valid Bearer token is supplied.

    Return None when no credentials are provided.

    An invalid token is still rejected.

    This distinction is important:

        No authentication
            → None

        Invalid authentication
            → 401
    """

    if credentials is None:
        return None

    return get_current_user(
        credentials=credentials,
        db=db,
    )


# =============================================================================
# Resource ownership
# =============================================================================

def require_user_ownership(
    resource_user_id: int,
    current_user: User,
) -> None:
    """
    Ensure the authenticated user owns a resource.

    This helper should be used by analysis/report endpoints.

    Example:

        require_user_ownership(
            analysis.user_id,
            current_user,
        )

    A user must never be able to access another user's:
    - analysis
    - report
    - uploaded sample metadata
    - comparison
    """

    if resource_user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resource not found.",
        )