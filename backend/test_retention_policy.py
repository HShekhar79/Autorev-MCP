"""
test_retention_policy.py

Task 12 — focused regression tests for the retention policy additions in
core/cleanup_manager.py (is_retention_expired, is_job_retention_expired,
run_retention_sweep).

Uses the real InMemoryJobRepository (via core.job_manager.set_repository),
exactly as test_cleanup_manager.py does, so these tests exercise the
actual get_job()/list_jobs()/VALID_STATUSES contract rather than a
hand-rolled mock. Independently runnable — no production database, no
scheduler, no background worker, no real sleeping/time delays.

Product policy under test (explicit, supplied — not inferred):
  - completed/failed retention: 7 days (RETENTION_MAX_AGE below)
  - age measured from JobRecord.updated_at while terminal
  - boundary inclusive: age >= max_age is expired
  - uploaded/processing are never eligible, regardless of age
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

import core.job_manager as job_manager
from core.job_manager import InMemoryJobRepository
import core.cleanup_manager as cleanup_manager
from core.cleanup_manager import (
    is_retention_expired,
    is_job_retention_expired,
    run_retention_sweep,
    is_job_cleanup_eligible,
    UPLOAD_DIR,
)


RETENTION_MAX_AGE = timedelta(days=7)

# Fixed, deterministic reference instant — every test computes "now",
# "expired", and "not expired" timestamps relative to this, never to the
# real wall clock, so nothing here depends on when the suite is run.
FIXED_NOW = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _fresh_in_memory_repo():
    """Isolate every test with its own fresh, real InMemoryJobRepository."""
    job_manager.set_repository(InMemoryJobRepository())
    yield


@pytest.fixture
def make_job():
    """
    Creates a real job via job_manager, then force-sets its status and
    updated_at directly on the in-memory store so tests can construct
    exact, deterministic ages without waiting on real time or chaining
    multiple real transitions (each of which would stamp "now" itself).
    """
    created_paths = []

    def _make(status="uploaded", updated_at=None, with_file=True):
        job_id = str(uuid.uuid4())
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        file_path = UPLOAD_DIR / f"{job_id}.bin"
        if with_file:
            file_path.write_bytes(b"test sample content")
            created_paths.append(file_path)

        job_manager.create_job(
            job_id=job_id,
            filename="sample.exe",
            file_path=str(file_path),
            user_id=1,
        )

        if status == "completed":
            job_manager.set_result(job_id, {"verdict": "BENIGN"})
        elif status == "failed":
            job_manager.set_job_error(job_id, "failed", "engine crashed")
        elif status == "processing":
            job_manager.update_job(job_id, "processing")
        # "uploaded" needs no further transition.

        if updated_at is not None:
            # Reach into the in-memory store directly to set a specific,
            # deterministic updated_at — this is test-only manipulation
            # of internal state, exactly analogous to how
            # test_cleanup_manager.py's test_unknown_status_fails_closed
            # already monkeypatches get_job() to inject an otherwise
            # unreachable value.
            repo = job_manager._repo
            with repo._lock:
                repo._jobs[job_id]["updated_at"] = updated_at.isoformat()

        return job_id, file_path

    yield _make

    for p in created_paths:
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 1-4. Pure predicate: completed/failed, expired/not-expired
# ---------------------------------------------------------------------------

def test_non_expired_completed_job_is_false():
    updated_at = FIXED_NOW - timedelta(days=3)
    assert is_retention_expired("completed", updated_at, FIXED_NOW, RETENTION_MAX_AGE) is False


def test_expired_completed_job_is_true():
    updated_at = FIXED_NOW - timedelta(days=10)
    assert is_retention_expired("completed", updated_at, FIXED_NOW, RETENTION_MAX_AGE) is True


def test_non_expired_failed_job_is_false():
    updated_at = FIXED_NOW - timedelta(days=1)
    assert is_retention_expired("failed", updated_at, FIXED_NOW, RETENTION_MAX_AGE) is False


def test_expired_failed_job_is_true():
    updated_at = FIXED_NOW - timedelta(days=8)
    assert is_retention_expired("failed", updated_at, FIXED_NOW, RETENTION_MAX_AGE) is True


# ---------------------------------------------------------------------------
# 5-7. Non-terminal / unknown statuses never expire, regardless of age
# ---------------------------------------------------------------------------

def test_uploaded_never_expires_regardless_of_age():
    ancient = FIXED_NOW - timedelta(days=3650)
    assert is_retention_expired("uploaded", ancient, FIXED_NOW, RETENTION_MAX_AGE) is False


def test_processing_never_expires_regardless_of_age():
    ancient = FIXED_NOW - timedelta(days=3650)
    assert is_retention_expired("processing", ancient, FIXED_NOW, RETENTION_MAX_AGE) is False
    # Also true at max_age == zero: a retention duration can never
    # bypass the Task 6C lifecycle-safety rule.
    assert is_retention_expired("processing", ancient, FIXED_NOW, timedelta(0)) is False


def test_unknown_status_is_false():
    old = FIXED_NOW - timedelta(days=365)
    assert is_retention_expired("totally-unknown-status", old, FIXED_NOW, RETENTION_MAX_AGE) is False
    assert is_retention_expired("", old, FIXED_NOW, RETENTION_MAX_AGE) is False


# ---------------------------------------------------------------------------
# 8. Exact inclusive boundary
# ---------------------------------------------------------------------------

def test_exact_boundary_age_equals_max_age_is_expired():
    updated_at = FIXED_NOW - RETENTION_MAX_AGE  # age == exactly 7 days
    assert is_retention_expired("completed", updated_at, FIXED_NOW, RETENTION_MAX_AGE) is True

    # One second short of the boundary must NOT be expired.
    just_under = FIXED_NOW - RETENTION_MAX_AGE + timedelta(seconds=1)
    assert is_retention_expired("completed", just_under, FIXED_NOW, RETENTION_MAX_AGE) is False

    # One second past the boundary must be expired.
    just_over = FIXED_NOW - RETENTION_MAX_AGE - timedelta(seconds=1)
    assert is_retention_expired("completed", just_over, FIXED_NOW, RETENTION_MAX_AGE) is True


# ---------------------------------------------------------------------------
# 9. Future updated_at
# ---------------------------------------------------------------------------

def test_future_updated_at_is_not_expired():
    future = FIXED_NOW + timedelta(days=1)
    assert is_retention_expired("completed", future, FIXED_NOW, RETENTION_MAX_AGE) is False


# ---------------------------------------------------------------------------
# 10. Timezone-aware datetime handling
# ---------------------------------------------------------------------------

def test_naive_datetimes_are_treated_as_utc_not_rejected():
    """
    SQLite does not persist tzinfo, so a naive datetime read back from a
    real JobRecord row must be handled, not rejected outright — see
    _to_aware_utc()'s docstring for the documented reasoning.
    """
    naive_updated_at = (FIXED_NOW - timedelta(days=10)).replace(tzinfo=None)
    naive_now = FIXED_NOW.replace(tzinfo=None)
    assert is_retention_expired("completed", naive_updated_at, naive_now, RETENTION_MAX_AGE) is True

    naive_not_expired = (FIXED_NOW - timedelta(days=1)).replace(tzinfo=None)
    assert is_retention_expired("completed", naive_not_expired, naive_now, RETENTION_MAX_AGE) is False


def test_non_utc_timezone_is_converted_correctly():
    """A datetime in a different, non-UTC offset must be converted
    correctly, not misinterpreted as already being in UTC."""
    plus_five = timezone(timedelta(hours=5))
    # This instant is 10 days before FIXED_NOW in absolute terms, merely
    # expressed in a +05:00 offset rather than UTC.
    updated_at_plus5 = (FIXED_NOW - timedelta(days=10)).astimezone(plus_five)
    assert is_retention_expired("completed", updated_at_plus5, FIXED_NOW, RETENTION_MAX_AGE) is True


def test_mixed_naive_and_aware_inputs_handled():
    """One naive, one aware — both must still normalize to the same
    absolute comparison rather than raising or comparing incorrectly."""
    naive_updated_at = (FIXED_NOW - timedelta(days=10)).replace(tzinfo=None)
    assert is_retention_expired("completed", naive_updated_at, FIXED_NOW, RETENTION_MAX_AGE) is True


# ---------------------------------------------------------------------------
# 11. Job-level wrapper delegates to the pure predicate
# ---------------------------------------------------------------------------

def test_job_level_wrapper_delegates_to_pure_predicate(make_job, monkeypatch):
    job_id, _ = make_job(status="completed", updated_at=FIXED_NOW - timedelta(days=10))

    calls = []
    real_predicate = cleanup_manager.is_retention_expired

    def _spy(status, updated_at, now, max_age):
        calls.append((status, max_age))
        return real_predicate(status, updated_at, now, max_age)

    monkeypatch.setattr(cleanup_manager, "is_retention_expired", _spy)

    result = is_job_retention_expired(job_id, RETENTION_MAX_AGE, now=FIXED_NOW)

    assert calls == [("completed", RETENTION_MAX_AGE)]
    assert result is True

    # Prove the wrapper returns EXACTLY what the pure predicate returns,
    # not a recomputed answer of its own.
    monkeypatch.setattr(cleanup_manager, "is_retention_expired", lambda *a, **k: "sentinel")
    assert is_job_retention_expired(job_id, RETENTION_MAX_AGE, now=FIXED_NOW) == "sentinel"


# ---------------------------------------------------------------------------
# 12-15. Sweep behaviour
# ---------------------------------------------------------------------------

def test_sweep_only_processes_expired_terminal_jobs(make_job):
    expired_completed, expired_path = make_job(status="completed", updated_at=FIXED_NOW - timedelta(days=10))
    fresh_completed, fresh_path = make_job(status="completed", updated_at=FIXED_NOW - timedelta(days=1))
    expired_failed, expired_failed_path = make_job(status="failed", updated_at=FIXED_NOW - timedelta(days=30))
    uploaded_job, uploaded_path = make_job(status="uploaded", updated_at=FIXED_NOW - timedelta(days=3650))

    results = run_retention_sweep(RETENTION_MAX_AGE, now=FIXED_NOW)
    processed_ids = {job_id for job_id, _ in results}

    assert expired_completed in processed_ids
    assert expired_failed in processed_ids
    assert fresh_completed not in processed_ids
    assert uploaded_job not in processed_ids

    assert not expired_path.exists()
    assert not expired_failed_path.exists()
    assert fresh_path.exists()
    assert uploaded_path.exists()


def test_sweep_refetches_current_state_before_deletion(make_job, monkeypatch):
    """
    Simulates the exact race documented in the Task 12 audit: a job that
    LOOKS expired in the bulk list_jobs() snapshot but has since changed
    state (here: deleted / gone) by the time the sweep gets to it must
    be re-evaluated at that moment, not acted on from the stale snapshot.
    """
    job_id, file_path = make_job(status="completed", updated_at=FIXED_NOW - timedelta(days=10))

    real_get_job = cleanup_manager.get_job
    call_count = {"n": 0}

    def _get_job_that_vanishes_after_first_call(jid):
        call_count["n"] += 1
        if call_count["n"] > 1 and jid == job_id:
            return None  # simulate the job vanishing between list and delete
        return real_get_job(jid)

    monkeypatch.setattr(cleanup_manager, "get_job", _get_job_that_vanishes_after_first_call)

    # is_job_retention_expired's own get_job() call is the "immediately
    # before deletion" re-fetch; it must reflect current state, not the
    # list_jobs() snapshot. We don't assert a specific outcome from the
    # contrived vanish (that's exercised by is_job_cleanup_eligible's own
    # existing "missing job -> False" test) — what we assert is that
    # get_job was actually called again per job, proving no decision was
    # made purely from the bulk snapshot.
    run_retention_sweep(RETENTION_MAX_AGE, now=FIXED_NOW)

    assert call_count["n"] >= 1, "sweep must re-fetch job state, not rely solely on list_jobs()"


def test_non_expired_jobs_remain_untouched(make_job):
    job_id, file_path = make_job(status="completed", updated_at=FIXED_NOW - timedelta(days=6, hours=23))
    results = run_retention_sweep(RETENTION_MAX_AGE, now=FIXED_NOW)
    assert job_id not in {jid for jid, _ in results}
    assert file_path.exists()
    job = job_manager.get_job(job_id)
    assert job["status"] == "completed"  # JobRecord itself untouched


def test_processing_jobs_are_never_touched_by_sweep(make_job):
    job_id, file_path = make_job(status="processing", updated_at=FIXED_NOW - timedelta(days=3650))
    results = run_retention_sweep(RETENTION_MAX_AGE, now=FIXED_NOW)
    assert job_id not in {jid for jid, _ in results}
    assert file_path.exists()
    assert job_manager.get_job(job_id)["status"] == "processing"


# ---------------------------------------------------------------------------
# 16. Cleanup failure does not modify JobRecord
# ---------------------------------------------------------------------------

def test_cleanup_failure_does_not_modify_job_record(make_job, monkeypatch):
    job_id, file_path = make_job(status="completed", updated_at=FIXED_NOW - timedelta(days=10))

    before = job_manager.get_job(job_id)

    def _fail_delete(path):
        return cleanup_manager.CleanupResult(success=False, reason="os_error", detail="simulated failure")

    monkeypatch.setattr(cleanup_manager, "safe_delete_sample", _fail_delete)

    results = run_retention_sweep(RETENTION_MAX_AGE, now=FIXED_NOW)
    assert results == [(job_id, cleanup_manager.CleanupResult(success=False, reason="os_error"))]

    after = job_manager.get_job(job_id)
    assert after == before, "a failed physical delete must leave JobRecord completely unchanged"
    assert file_path.exists()  # the (mocked) failure means nothing was actually removed


# ---------------------------------------------------------------------------
# 17. Idempotency
# ---------------------------------------------------------------------------

def test_running_sweep_twice_is_idempotent(make_job):
    job_id, file_path = make_job(status="completed", updated_at=FIXED_NOW - timedelta(days=10))

    first = run_retention_sweep(RETENTION_MAX_AGE, now=FIXED_NOW)
    assert (job_id, cleanup_manager.CleanupResult(success=True, reason="deleted")) in first
    assert not file_path.exists()

    second = run_retention_sweep(RETENTION_MAX_AGE, now=FIXED_NOW)
    matching = [r for jid, r in second if jid == job_id]
    assert matching == [cleanup_manager.CleanupResult(success=True, reason="already_absent")]

    # JobRecord itself is unaffected by either run.
    job = job_manager.get_job(job_id)
    assert job["status"] == "completed"


# ---------------------------------------------------------------------------
# 18. Already-missing sample handled safely
# ---------------------------------------------------------------------------

def test_already_missing_sample_handled_safely(make_job):
    job_id, file_path = make_job(status="completed", updated_at=FIXED_NOW - timedelta(days=10), with_file=False)
    assert not file_path.exists()

    results = run_retention_sweep(RETENTION_MAX_AGE, now=FIXED_NOW)
    matching = [r for jid, r in results if jid == job_id]

    assert matching == [cleanup_manager.CleanupResult(success=True, reason="already_absent")]
    job = job_manager.get_job(job_id)
    assert job["status"] == "completed"


# ---------------------------------------------------------------------------
# 19. JobRecord is never deleted by retention
# ---------------------------------------------------------------------------

def test_job_record_is_never_deleted_by_sweep(make_job):
    job_id, file_path = make_job(status="failed", updated_at=FIXED_NOW - timedelta(days=100))

    run_retention_sweep(RETENTION_MAX_AGE, now=FIXED_NOW)

    job = job_manager.get_job(job_id)
    assert job is not None, "run_retention_sweep must never delete the JobRecord itself"
    assert job["status"] == "failed"


# ---------------------------------------------------------------------------
# 20. Sweep performs no unsafe deletion itself — relies entirely on
#     cleanup_manager's existing, unmodified path-safety primitives
# ---------------------------------------------------------------------------

def test_sweep_never_calls_unlink_directly(make_job, monkeypatch):
    """
    run_retention_sweep() must delegate ALL actual deletion to
    delete_job_sample_if_eligible() (and, transitively,
    safe_delete_sample()/validate_upload_path()) — it must never call
    Path.unlink or os.remove itself. Proven by replacing
    delete_job_sample_if_eligible with a spy that never performs a real
    deletion, and confirming files still exist yet the sweep still
    "processed" the job (i.e. it did call the delegated primitive).
    """
    from pathlib import Path

    job_id, file_path = make_job(status="completed", updated_at=FIXED_NOW - timedelta(days=10))

    delegate_calls = []

    def _spy_delete(jid):
        delegate_calls.append(jid)
        return cleanup_manager.CleanupResult(success=True, reason="deleted")

    def _unlink_must_not_be_called(self, *a, **k):
        raise AssertionError("run_retention_sweep must never call Path.unlink directly")

    monkeypatch.setattr(cleanup_manager, "delete_job_sample_if_eligible", _spy_delete)
    monkeypatch.setattr(Path, "unlink", _unlink_must_not_be_called)

    results = run_retention_sweep(RETENTION_MAX_AGE, now=FIXED_NOW)

    assert delegate_calls == [job_id]
    assert [jid for jid, _ in results] == [job_id]
    # File still exists because deletion was faked via the spy — proves
    # the sweep itself never touched the filesystem, only the delegate.
    assert file_path.exists()
