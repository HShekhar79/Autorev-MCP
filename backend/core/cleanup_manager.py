"""
backend/core/cleanup_manager.py

Task 6B.1 — Cleanup service boundary.
Task 6C  — Pure, reusable eligibility primitive (is_cleanup_eligible).

Provides safe, reusable primitives for cleaning up physical uploaded
malware sample files. This module does NOT perform any automatic
cleanup on its own — see the bottom of this docstring for why.

Reused interfaces (no duplication of existing logic):
  - core.job_manager.get_job() / VALID_STATUSES — the authoritative,
    persistent job lifecycle state (Task 8: SQLAlchemyJobRepository /
    models.JobRecord in production, InMemoryJobRepository in tests).
  - The UUID-based storage naming convention and upload-root resolution
    already established in api/routes/upload.py (`{job_id}.bin` under
    UPLOAD_DIR). This module deliberately does NOT import
    api.routes.upload — it re-derives the same UPLOAD_DIR path
    independently, using the identical relative-path logic
    (backend/core/cleanup_manager.py -> parent.parent == backend/,
    matching backend/api/routes/upload.py -> parent.parent.parent ==
    backend/), so that core/ never depends on api/ and no circular
    import is introduced.

LIFECYCLE SAFETY:
  - uploaded    -> NOT eligible (job hasn't been analyzed yet)
  - processing  -> NEVER eligible (an active analysis may still be
                   reading this exact file — see Task 7's per-job lock
                   and Task 9's audit of _run_full_pipeline)
  - completed   -> POTENTIALLY eligible (a later task decides timing)
  - failed      -> POTENTIALLY eligible (same)
  - anything else (unknown/missing job, invalid status) -> NOT eligible,
    fail closed.

  Task 6C: this rule now has a SINGLE source of truth —
  is_cleanup_eligible(status), a pure function taking just a status
  string. is_job_cleanup_eligible(job_id) is a thin wrapper around it
  for callers who only have a job_id. Any future caller that already
  has a status in hand (e.g. a Task 12 scheduler iterating
  job_manager.list_jobs()) should call is_cleanup_eligible(status)
  directly rather than re-deriving this classification.

PATH SAFETY:
  - The only file this module will ever delete is one whose path:
      1. resolves (after following any symlink) to a location strictly
         inside the configured upload root, AND
      2. matches the exact expected naming convention
         "<uuid4>.bin".
  - If the path currently exists, it must be a regular file (never a
    directory).
  - A path that is safe but does NOT currently exist is still a VALID
    target — non-existence is handled as an idempotent "already_absent"
    success by safe_delete_sample(), not as a validation failure. This
    is deliberate: repeatedly asking to delete an already-gone sample
    must never be treated as an error.
  - The upload root itself can never be deleted.
  - No recursive deletion of any kind is performed.
  - A path that fails any safety check is rejected (fail closed) —
    never "best effort" deleted.

WHY THIS MODULE DOES NOT YET PERFORM AUTOMATIC CLEANUP:
  Per Task 6B.1's explicit scope, this is only the primitives layer.
  Retention/TTL policy (Task 12), a scheduler, startup orphan sweeps,
  and automatic post-analysis deletion are all deliberately NOT wired
  up here — those require a product decision on WHEN a "potentially
  eligible" completed/failed job should actually be cleaned, which is
  out of scope for this task and must not be invented. Task 6C adds
  only a reusable eligibility PRIMITIVE (is_cleanup_eligible) — it does
  not call it from anywhere new, and does not trigger any deletion.
"""

import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.job_manager import get_job, list_jobs, VALID_STATUSES

log = logging.getLogger("arise.cleanup_manager")


# =============================================================================
# Upload root — independently derived, matching api/routes/upload.py's
# UPLOAD_DIR exactly, without importing that route module.
# =============================================================================

_BACKEND_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = (_BACKEND_DIR / "storage" / "uploads").resolve()

# Matches api/routes/upload.py's store_name = f"{job_id}.bin" convention.
_UUID_BIN_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.bin$",
    re.IGNORECASE,
)

# Statuses for which physical cleanup could ever be considered.
# Deliberately does NOT mean "should be cleaned now" — only "not
# categorically forbidden". Timing policy belongs to a later task.
_POTENTIALLY_ELIGIBLE_STATUSES = {"completed", "failed"}

# Statuses for which cleanup must NEVER be considered, regardless of
# any future retention policy.
_NEVER_ELIGIBLE_STATUSES = {"uploaded", "processing"}


class CleanupResult:
    """
    Structured outcome of a cleanup primitive call. Deliberately a plain
    class (not a dict) so callers get attribute access and IDE support,
    while still being trivially convertible to a dict via vars() if a
    future caller (e.g. a Task 12 scheduler) wants to log/serialize it.
    """

    def __init__(self, success: bool, reason: str, detail: str = ""):
        self.success = success
        self.reason = reason
        self.detail = detail

    def __repr__(self) -> str:
        return f"CleanupResult(success={self.success}, reason={self.reason!r}, detail={self.detail!r})"

    def __eq__(self, other) -> bool:
        if not isinstance(other, CleanupResult):
            return NotImplemented
        return (
            self.success == other.success
            and self.reason == other.reason
        )


# =============================================================================
# 1. Lifecycle eligibility
# =============================================================================

def is_cleanup_eligible(status: str) -> bool:
    """
    Task 6C — pure, status-only cleanup eligibility predicate. This is
    the SINGLE source of truth for the lifecycle safety model described
    at the top of this module.

    Takes just a status string — no job_id, no get_job() lookup, no
    filesystem access. Any caller that already has a status value in
    hand (e.g. a future scheduler iterating job_manager.list_jobs())
    should call this directly rather than re-deriving the rule or
    paying for a redundant job lookup.

    Returns True only for "completed" or "failed". Returns False for
    "uploaded", "processing", or any string not in VALID_STATUSES
    (fail closed on unrecognized/invalid input).

    Does NOT consider retention/TTL timing — it only answers "is this
    status categorically off-limits, or not".
    """
    if status not in VALID_STATUSES:
        return False
    if status in _NEVER_ELIGIBLE_STATUSES:
        return False
    return status in _POTENTIALLY_ELIGIBLE_STATUSES


def is_job_cleanup_eligible(job_id: str) -> bool:
    """
    Determine whether a job's physical sample is even potentially
    eligible for cleanup, based SOLELY on its current authoritative
    lifecycle state (via core.job_manager.get_job()).

    Thin wrapper around is_cleanup_eligible(status) — fetches the job,
    fails closed if it's missing, then delegates the actual
    classification to the pure predicate so the rule lives in exactly
    one place.

    This function does NOT delete anything and does NOT consider
    retention/TTL timing — it only answers "is this categorically
    off-limits, or not".
    """
    if not job_id:
        return False

    job = get_job(job_id)
    if job is None:
        log.info("[cleanup] job %s not found — not eligible (fail closed)", job_id)
        return False

    status = job.get("status")

    if status not in VALID_STATUSES:
        log.warning(
            "[cleanup] job %s has unrecognized status %r — not eligible (fail closed)",
            job_id, status,
        )
        return False

    return is_cleanup_eligible(status)


# =============================================================================
# 2. Path safety validation
# =============================================================================

def validate_upload_path(candidate_path: str) -> Optional[Path]:
    """
    Validate that `candidate_path` is SAFE to treat as an AutoRev upload
    sample target for safe_delete_sample() — this checks safety, not
    existence.

    Returns the resolved Path if, and only if, ALL of the following
    hold:
      - the path is non-empty and resolves without error
      - the resolved path is strictly INSIDE UPLOAD_DIR (never equal
        to UPLOAD_DIR itself, and never outside it — rejects path
        traversal via ../, and rejects any symlink/reparse point whose
        resolved target escapes UPLOAD_DIR, since Path.resolve()
        follows symlinks and we check the FINAL resolved location, not
        the pre-resolution string)
      - the resolved filename matches the exact "<uuid4>.bin" naming
        convention this codebase uses for stored samples
      - IF the resolved path currently exists, it must be a regular
        file (never a directory or other special file). A path that
        does NOT exist is NOT rejected here — non-existence is not a
        safety problem, it's an existence fact that safe_delete_sample()
        handles as an idempotent success.

    Returns None on ANY safety failure — fail closed. Never raises for
    ordinary invalid input (traversal attempt, wrong naming, etc.);
    only a genuinely unexpected OS-level error is logged and also
    results in None rather than propagating.
    """
    if not candidate_path:
        log.warning("[cleanup] validate_upload_path: empty path rejected")
        return None

    try:
        resolved = Path(candidate_path).resolve()
    except (OSError, RuntimeError) as exc:
        log.warning("[cleanup] validate_upload_path: could not resolve %r: %s", candidate_path, exc)
        return None

    if resolved.parent != UPLOAD_DIR:
        log.warning(
            "[cleanup] validate_upload_path: %r resolves outside upload root (%s)",
            candidate_path, UPLOAD_DIR,
        )
        return None

    if resolved == UPLOAD_DIR:
        log.warning("[cleanup] validate_upload_path: refusing to treat upload root itself as a target")
        return None

    if not _UUID_BIN_PATTERN.match(resolved.name):
        log.warning(
            "[cleanup] validate_upload_path: %r does not match expected <uuid4>.bin naming",
            resolved.name,
        )
        return None

    try:
        if resolved.exists() and not resolved.is_file():
            log.warning(
                "[cleanup] validate_upload_path: %s exists but is not a regular file",
                resolved,
            )
            return None
    except OSError as exc:
        log.warning("[cleanup] validate_upload_path: stat failed for %s: %s", resolved, exc)
        return None

    return resolved


# =============================================================================
# 3/4. Safe deletion primitive
# =============================================================================

def safe_delete_sample(file_path: str) -> CleanupResult:
    """
    Safely delete a single uploaded sample file.

    This is a PATH-LEVEL primitive only — it does NOT consult job
    lifecycle state. Callers that need lifecycle-aware deletion must
    first call is_job_cleanup_eligible() themselves (see
    delete_job_sample_if_eligible() below for the combined helper).

    Never recursive. Never deletes a directory — validate_upload_path()
    already refuses a path that exists as a directory, and this is
    re-checked here as a second, independent guard rather than relying
    solely on the validator not being bypassed.

    Idempotent: deleting an already-missing file is reported as a
    successful no-op ("already_absent"), not an error, so repeated
    calls are always safe.
    """
    validated = validate_upload_path(file_path)

    if validated is None:
        return CleanupResult(
            success=False,
            reason="invalid_path",
            detail=f"path failed validation: {file_path!r}",
        )

    try:
        if not validated.exists():
            return CleanupResult(success=True, reason="already_absent")

        if validated.is_dir():
            return CleanupResult(
                success=False,
                reason="refused_directory",
                detail=f"{validated} is a directory, not deleted",
            )

        validated.unlink()
        log.info("[cleanup] deleted sample: %s", validated)
        return CleanupResult(success=True, reason="deleted")

    except FileNotFoundError:
        return CleanupResult(success=True, reason="already_absent")
    except OSError as exc:
        log.warning("[cleanup] could not delete %s: %s", validated, exc)
        return CleanupResult(success=False, reason="os_error", detail=str(exc))


# =============================================================================
# 5. Combined, lifecycle-aware primitive — the one future callers
#    (Task 12's scheduler) are expected to actually use.
# =============================================================================

def delete_job_sample_if_eligible(job_id: str) -> CleanupResult:
    """
    Combined primitive: checks lifecycle eligibility via
    is_job_cleanup_eligible(), and only if eligible, resolves the job's
    recorded file_path and attempts safe_delete_sample() on it.

    This is the single function a future scheduler/retention mechanism
    (Task 12) is expected to call — it does not itself decide WHEN to
    run, only WHETHER a given job_id may currently have its sample
    removed.

    Fails closed at every stage: missing job, wrong status, missing
    file_path, or a file_path that fails path validation all result in
    success=False with a specific `reason`, never a deletion.
    """
    if not is_job_cleanup_eligible(job_id):
        return CleanupResult(success=False, reason="not_eligible")

    job = get_job(job_id)
    if job is None:
        return CleanupResult(success=False, reason="job_vanished")

    file_path = job.get("file_path")
    if not file_path:
        return CleanupResult(success=False, reason="missing_file_path")

    return safe_delete_sample(file_path)


# =============================================================================
# 6. Retention policy (Task 12)
# =============================================================================
#
# PRODUCT POLICY (explicit, supplied — NOT inferred from code):
#   - completed sample retention: 7 days
#   - failed sample retention:    7 days
#   - age is measured from JobRecord.updated_at while the job is in a
#     terminal state (no dedicated completed_at/failed_at column exists;
#     see the Task 12 audit — nothing in this codebase writes to a
#     terminal JobRecord row again after it becomes terminal, so
#     updated_at is a reliable, if reused, proxy for "time since this
#     job finished").
#   - boundary is INCLUSIVE: age >= max_age means expired.
#   - uploaded/processing are NEVER retention-eligible, regardless of age
#     — enforced by delegating to is_cleanup_eligible() FIRST, so the
#     Task 6C lifecycle-safety rule cannot be bypassed by any future
#     retention duration, including a duration of zero.
#
# This section adds three NEW functions only. Nothing above this point in
# the file is modified. No scheduler, no startup wiring, no JobRecord
# deletion — this is the manual/admin-triggered execution mechanism only,
# per the current Task 12 scope.
#
# REPORT-GENERATION PRECONDITION (documented per audit finding — NOT fixed
# here; report.py is explicitly out of scope for Task 12):
#   report.py's job_id-resolution path (_resolve_result) re-derives a file
#   path from job["filename"] (display name) rather than job["file_path"]
#   (the actual UUID-based stored path), and falls back to re-running the
#   pipeline against that (likely already-wrong) path on any cache miss,
#   rather than reliably preferring the persisted job["result"] dict.
#   Concretely: even BEFORE Task 12 exists, report generation for a
#   completed job is not guaranteed to use the durable, already-computed
#   result over a fresh file read. Once run_retention_sweep() below is
#   ever actually invoked against production data, this pre-existing gap
#   becomes an active risk — a report request for a job whose sample was
#   just cleaned up could fail outright instead of falling back to the
#   persisted result it should already trust. This must be resolved (in
#   report.py, in whatever task owns that file) BEFORE run_retention_sweep
#   is wired into any automatic trigger. It is not blocking for the
#   current manual-only scope, since a human operator invoking the sweep
#   can coordinate timing themselves, but it is blocking for any future
#   scheduler.
# =============================================================================

def _to_aware_utc(dt: datetime) -> datetime:
    """
    Normalize a datetime to timezone-aware UTC.

    JobRecord's timestamp columns are declared DateTime(timezone=True) in
    models.py, but this project's default database is SQLite
    (database.py's DATABASE_URL default), and SQLite does not actually
    persist tzinfo — a value written as UTC can round-trip back out as a
    naive datetime. Every writer of these timestamps (job_manager.py's
    InMemoryJobRepository._now() and SQLAlchemyJobRepository, both using
    datetime.now(timezone.utc)) always writes UTC wall-clock values, so a
    naive datetime here is explicitly treated as "already UTC, tzinfo
    just got lost in the round trip" rather than rejected as unsafe —
    failing closed on every naive value would make retention silently
    never fire under this project's actual default database, which is a
    worse outcome than assuming a documented, verified writer convention.
    An already-aware datetime in a non-UTC zone is converted correctly
    rather than assumed.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def is_retention_expired(
    status: str,
    updated_at: datetime,
    now: datetime,
    max_age,
) -> bool:
    """
    Task 12 — pure, side-effect-free retention predicate.

    No filesystem access, no DB access, no job_id, no get_job() lookup —
    a plain status string, two datetimes, and a duration in, a bool out.
    This is the SINGLE source of truth for "is this job's sample old
    enough to be retention-eligible", exactly as is_cleanup_eligible() is
    the single source of truth for "is this status categorically
    off-limits" (Task 6C) — this function composes that rule rather than
    re-deriving it.

    Requirements enforced, in order:
      1. Task 6C eligibility is checked FIRST and is absolute: uploaded
         and processing return False unconditionally, and an unknown/
         invalid status also returns False, regardless of `max_age` —
         including a max_age of zero. A retention duration can only ever
         narrow eligibility further, never bypass the lifecycle-safety
         rule.
      2. Missing/invalid inputs fail closed (return False) rather than
         raising, matching this module's existing fail-closed convention
         throughout (validate_upload_path, is_job_cleanup_eligible).
      3. Both datetimes are normalized to timezone-aware UTC via
         _to_aware_utc() before comparison — see that function's
         docstring for why a naive datetime is treated as "already UTC"
         rather than rejected.
      4. age = now - updated_at; expired iff age >= max_age (inclusive
         boundary, per explicit product decision). A `updated_at` in the
         future relative to `now` yields a negative age, which is always
         less than any non-negative max_age, so it is correctly treated
         as NOT expired without any special-case branch.
    """
    if not is_cleanup_eligible(status):
        return False

    if updated_at is None or now is None or max_age is None:
        return False

    try:
        updated_at_utc = _to_aware_utc(updated_at)
        now_utc = _to_aware_utc(now)
    except (AttributeError, TypeError) as exc:
        log.warning(
            "[cleanup] is_retention_expired: invalid datetime input(s): %s",
            exc,
        )
        return False

    age = now_utc - updated_at_utc
    return age >= max_age


def is_job_retention_expired(
    job_id: str,
    max_age,
    now: Optional[datetime] = None,
) -> bool:
    """
    Task 12 — job-level retention wrapper.

    Retrieves the job's AUTHORITATIVE current state via get_job() (never
    a caller-supplied/cached snapshot) and delegates the actual
    expiry classification entirely to is_retention_expired() — the same
    delegate-to-pure-function pattern is_job_cleanup_eligible() already
    established for Task 6C, so the retention rule also lives in exactly
    one place.

    `now` defaults to the real current UTC time; a fixed value can be
    passed for deterministic testing (see test_retention_policy.py).

    Fails closed: a missing job, or a job with no updated_at, returns
    False without raising.
    """
    if not job_id:
        return False

    job = get_job(job_id)
    if job is None:
        log.info("[cleanup] job %s not found — not retention-expired (fail closed)", job_id)
        return False

    status = job.get("status")
    updated_at_raw = job.get("updated_at")

    if updated_at_raw is None:
        return False

    if isinstance(updated_at_raw, datetime):
        updated_at = updated_at_raw
    elif isinstance(updated_at_raw, str):
        try:
            updated_at = datetime.fromisoformat(updated_at_raw)
        except ValueError as exc:
            log.warning(
                "[cleanup] job %s has unparseable updated_at %r: %s",
                job_id, updated_at_raw, exc,
            )
            return False
    else:
        log.warning(
            "[cleanup] job %s has unexpected updated_at type %r",
            job_id, type(updated_at_raw),
        )
        return False

    effective_now = now if now is not None else datetime.now(timezone.utc)

    return is_retention_expired(status, updated_at, effective_now, max_age)


def run_retention_sweep(
    max_age,
    now: Optional[datetime] = None,
) -> list[tuple[str, "CleanupResult"]]:
    """
    Task 12 — manual/admin-triggered retention sweep.

    NOT wired into any scheduler, background worker, or application
    startup/lifespan path — per the current Task 12 scope, this function
    must be invoked explicitly (e.g. from an admin script or a future,
    separately-scoped trigger). Calling it does nothing on its own.

    For every job returned by job_manager.list_jobs() (the authoritative
    repository, whichever implementation is currently active):
      1. Re-fetches that job's CURRENT state via is_job_retention_expired()
         (which itself calls get_job() fresh) — the job dict returned by
         list_jobs() is used ONLY to obtain job_id; expiry is never
         decided from that potentially-stale bulk snapshot. This closes
         the read-then-act race identified in the Task 12 audit: a job
         that transitions between the list_jobs() call and the per-job
         check is evaluated on its state AT CHECK TIME, not at list time.
      2. If, and only if, expired, delegates deletion entirely to the
         existing, unmodified delete_job_sample_if_eligible(job_id) —
         this function NEVER calls safe_delete_sample() or Path.unlink()
         directly, and NEVER deletes a JobRecord. All existing path
         validation, UUID matching, and fail-closed behaviour in
         cleanup_manager's deletion primitives applies unchanged.

    Idempotent: a job whose file was already removed by a previous sweep
    is still "expired" on a second run, and delete_job_sample_if_eligible
    -> safe_delete_sample already reports "already_absent" as success
    for a missing file, so re-running this sweep is always safe and
    produces no different observable outcome for already-cleaned jobs.

    A cleanup failure for one job (e.g. an OS-level delete error) does
    NOT modify that job's JobRecord in any way — this function performs
    no writes to job state at all, in success or failure; it only reads
    (via is_job_retention_expired/get_job) and calls the existing
    deletion primitive, which itself never touches JobRecord.

    Returns a list of (job_id, CleanupResult) pairs — one entry per job
    that was found to be retention-expired and had deletion attempted
    (successfully or not). Jobs that are not expired are not included at
    all, so an empty return value means "nothing was eligible this run",
    not "everything failed".
    """
    effective_now = now if now is not None else datetime.now(timezone.utc)
    results: list[tuple[str, CleanupResult]] = []

    for job in list_jobs():
        job_id = job.get("job_id")
        if not job_id:
            continue

        if not is_job_retention_expired(job_id, max_age, now=effective_now):
            continue

        result = delete_job_sample_if_eligible(job_id)
        results.append((job_id, result))

    return results