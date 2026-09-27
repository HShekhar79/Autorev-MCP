# backend/auth/routes.py

"""
AutoRev Authentication Routes

Endpoints:
    POST /auth/register
    POST /auth/login
    GET  /auth/me
    POST /auth/logout

Security principles:
- New accounts always start as FREE.
- Client cannot choose subscription tier.
- Passwords are hashed with Argon2id.
- JWTs are issued only after successful authentication.
- Authentication errors do not reveal unnecessary account information.
- User responses never expose password hashes.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user
from auth.schemas import Token, UserCreate, UserLogin, UserOut
from auth.utils import (
    create_access_token,
    hash_password,
    verify_password,
)
from database import get_db
from models import SubscriptionTier, User


# =============================================================================
# Router
# =============================================================================

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


# =============================================================================
# Helpers
# =============================================================================

def user_to_response(user: User) -> UserOut:
    """
    Convert a database User into the safe public authentication response.
    """

    return UserOut(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        is_active=user.is_active,
        is_verified=user.is_verified,
        created_at=user.created_at,
        last_login=user.last_login,
        tier=user.tier.value,
        tier_expires_at=user.tier_expires_at,
        uploads_this_month=user.uploads_this_month,
        uploads_remaining=user.uploads_remaining(),
    )


# =============================================================================
# Registration
# =============================================================================

@router.post(
    "/register",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
)
def register(
    payload: UserCreate,
    db: Session = Depends(get_db),
):
    """
    Create a new AutoRev account.

    IMPORTANT:
    The client cannot choose the subscription tier.

    Every new account starts as FREE.
    """

    normalized_email = payload.email.strip().lower()
    normalized_username = payload.username.strip()

    # -------------------------------------------------------------------------
    # Duplicate checks
    # -------------------------------------------------------------------------

    existing_email = (
        db.query(User)
        .filter(User.email == normalized_email)
        .first()
    )

    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Unable to create account with the provided information.",
        )

    existing_username = (
        db.query(User)
        .filter(User.username == normalized_username)
        .first()
    )

    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Unable to create account with the provided information.",
        )

    # -------------------------------------------------------------------------
    # Create user
    # -------------------------------------------------------------------------

    user = User(
        email=normalized_email,
        username=normalized_username,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        is_active=True,
        is_verified=False,

        # SECURITY:
        # Never accept subscription tier from the client.
        tier=SubscriptionTier.FREE,

        tier_expires_at=None,
        uploads_this_month=0,
        upload_reset_date=datetime.now(timezone.utc),
    )

    db.add(user)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()

        # Handles race conditions where two requests attempt to create
        # the same unique email/username simultaneously.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Unable to create account with the provided information.",
        )

    db.refresh(user)

    return user_to_response(user)


# =============================================================================
# Login
# =============================================================================

@router.post(
    "/login",
    response_model=Token,
)
def login(
    payload: UserLogin,
    db: Session = Depends(get_db),
):
    """
    Authenticate an existing user and issue an access token.
    """

    normalized_email = payload.email.strip().lower()

    user = (
        db.query(User)
        .filter(User.email == normalized_email)
        .first()
    )

    # Deliberately use the same public error for:
    # - unknown email
    # - incorrect password
    #
    # This reduces account enumeration.
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    if not verify_password(
        payload.password,
        user.hashed_password,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    # -------------------------------------------------------------------------
    # Account state
    # -------------------------------------------------------------------------

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive.",
        )

    # -------------------------------------------------------------------------
    # Update last login
    # -------------------------------------------------------------------------

    user.last_login = datetime.now(timezone.utc)

    db.commit()
    db.refresh(user)

    # -------------------------------------------------------------------------
    # Issue access token
    # -------------------------------------------------------------------------

    access_token = create_access_token(
        user_id=user.id,
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        user=user_to_response(user),
    )


# =============================================================================
# Current user
# =============================================================================

@router.get(
    "/me",
    response_model=UserOut,
)
def get_me(
    current_user: User = Depends(get_current_user),
):
    """
    Return the currently authenticated user's safe profile.
    """

    return user_to_response(current_user)


# =============================================================================
# Logout
# =============================================================================

@router.post(
    "/logout",
)
def logout(
    current_user: User = Depends(get_current_user),
):
    """
    Logout endpoint.

    Current JWT access tokens are short-lived.

    A full server-side revocation/session system will be added as part
    of the authentication hardening phase rather than pretending that
    deleting a client-side token is server-side revocation.

    The endpoint still requires authentication so clients can reliably
    treat logout as an authenticated lifecycle operation.
    """

    return {
        "message": "Logged out successfully.",
    }