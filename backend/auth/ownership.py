# backend/auth/ownership.py

"""
Ownership check for job-bound resources.

A job_id is also the Celery task id of the analysis it started
(see /upload-analyze), so the JobRecord's user_id is the single authoritative
owner for BOTH the job_id and task_id access paths.

Built only from the existing primitives:
    core.job_manager.get_job
    auth.dependencies.require_user_ownership

A missing id and an id owned by someone else raise the SAME 404, so ids
cannot be probed for existence. Callers run this BEFORE any filesystem,
Celery or pipeline access.
"""

from fastapi import HTTPException, status

from auth.dependencies import require_user_ownership
from core.job_manager import get_job
from models import User


def require_owned_job(job_id: str, current_user: User) -> dict:
    job = get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resource not found.",
        )
    require_user_ownership(job.get("user_id"), current_user)
    return job
