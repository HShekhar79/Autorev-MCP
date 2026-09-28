# backend/models.py

from datetime import datetime, timezone
import enum

from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    Float,
    Text,
    ForeignKey,
    Enum as SAEnum,
    Index,
)
from sqlalchemy.orm import relationship

from database import Base


# =============================================================================
# Time
# =============================================================================

def utcnow():
    return datetime.now(timezone.utc)


# =============================================================================
# Subscription Tiers
# =============================================================================

class SubscriptionTier(str, enum.Enum):
    FREE = "free"
    STARTER = "starter"
    PRO = "pro"
    ENTERPRISE = "enterprise"


# Monthly upload limits.
#
# None means genuinely unlimited.
# We do NOT use an artificial number such as 999999.
#
TIER_LIMITS = {
    SubscriptionTier.FREE: 5,
    SubscriptionTier.STARTER: 50,
    SubscriptionTier.PRO: 500,
    SubscriptionTier.ENTERPRISE: None,
}


# Monthly pricing in INR.
#
# These are initial product-planning values.
# Payment integration and final commercial pricing will be handled separately.
#
TIER_PRICING = {
    SubscriptionTier.FREE: 0,
    SubscriptionTier.STARTER: 2999,
    SubscriptionTier.PRO: 9999,
    SubscriptionTier.ENTERPRISE: 49999,
}


# =============================================================================
# User
# =============================================================================

class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    email = Column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )

    username = Column(
        String(100),
        unique=True,
        index=True,
        nullable=False,
    )

    hashed_password = Column(
        String(255),
        nullable=False,
    )

    full_name = Column(
        String(200),
        nullable=True,
    )

    is_active = Column(
        Boolean,
        default=True,
        nullable=False,
    )

    is_verified = Column(
        Boolean,
        default=False,
        nullable=False,
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )

    last_login = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    # -------------------------------------------------------------------------
    # Subscription
    # -------------------------------------------------------------------------

    tier = Column(
        SAEnum(SubscriptionTier),
        default=SubscriptionTier.FREE,
        nullable=False,
    )

    tier_expires_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    # -------------------------------------------------------------------------
    # Upload accounting
    # -------------------------------------------------------------------------

    uploads_this_month = Column(
        Integer,
        default=0,
        nullable=False,
    )

    upload_reset_date = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )

    # -------------------------------------------------------------------------
    # Relationships
    # -------------------------------------------------------------------------

    jobs = relationship(
        "AnalysisJob",
        back_populates="owner",
        cascade="all, delete-orphan",
    )

    # -------------------------------------------------------------------------
    # Upload helpers
    # -------------------------------------------------------------------------

    def uploads_remaining(self):
        limit = TIER_LIMITS[self.tier]

        # Enterprise = unlimited.
        if limit is None:
            return None

        return max(
            0,
            limit - self.uploads_this_month,
        )

    def can_upload(self):
        limit = TIER_LIMITS[self.tier]

        # Enterprise = unlimited.
        if limit is None:
            return True

        return self.uploads_this_month < limit

    def reset_monthly_if_needed(self):
        now = utcnow()
        reset = self.upload_reset_date or now

        if (
            now.month != reset.month
            or now.year != reset.year
        ):
            self.uploads_this_month = 0
            self.upload_reset_date = now


# =============================================================================
# Analysis Job
# =============================================================================

class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    task_id = Column(
        String(100),
        unique=True,
        index=True,
        nullable=False,
    )

    user_id = Column(
        Integer,
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    # -------------------------------------------------------------------------
    # File metadata
    # -------------------------------------------------------------------------

    original_filename = Column(
        String(500),
        nullable=True,
    )

    file_hash_sha256 = Column(
        String(64),
        nullable=True,
        index=True,
    )

    file_size_bytes = Column(
        Integer,
        nullable=True,
    )

    file_type = Column(
        String(50),
        nullable=True,
    )

    # -------------------------------------------------------------------------
    # Task status
    # -------------------------------------------------------------------------

    status = Column(
        String(30),
        default="pending",
        nullable=False,
        index=True,
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )

    started_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    completed_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    # -------------------------------------------------------------------------
    # Analysis result summary
    # -------------------------------------------------------------------------

    verdict = Column(
        String(50),
        nullable=True,
    )

    risk_score = Column(
        Float,
        nullable=True,
    )

    cvss_score = Column(
        Float,
        nullable=True,
    )

    confidence = Column(
        Float,
        nullable=True,
    )

    mitre_count = Column(
        Integer,
        nullable=True,
    )

    capabilities = Column(
        Text,
        nullable=True,
    )

    mitre_ids = Column(
        Text,
        nullable=True,
    )

    error_message = Column(
        Text,
        nullable=True,
    )

    # -------------------------------------------------------------------------
    # Relationship
    # -------------------------------------------------------------------------

    owner = relationship(
        "User",
        back_populates="jobs",
    )


# =============================================================================
# Composite indexes
# =============================================================================

Index(
    "ix_analysis_jobs_user_created",
    AnalysisJob.user_id,
    AnalysisJob.created_at,
)

Index(
    "ix_analysis_jobs_user_status",
    AnalysisJob.user_id,
    AnalysisJob.status,
)


# =============================================================================
# Persistent Job Record
# =============================================================================

class JobRecord(Base):
    """
    Authoritative persistent backing for core/job_manager.py.

    Deliberately separate from AnalysisJob: AnalysisJob has no file_path
    column and a different status/result shape.
    """
    __tablename__ = "job_records"

    job_id = Column(
        String(36),
        primary_key=True,
    )

    user_id = Column(
        Integer,
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    filename = Column(
        String(500),
        nullable=False,
    )

    file_path = Column(
        Text,
        nullable=False,
    )

    status = Column(
        String(30),
        nullable=False,
        default="uploaded",
        index=True,
    )

    result = Column(
        Text,
        nullable=True,
    )

    error_message = Column(
        Text,
        nullable=True,
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )

    updated_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )

    owner = relationship(
        "User",
    )


Index(
    "ix_job_records_user_status",
    JobRecord.user_id,
    JobRecord.status,
)