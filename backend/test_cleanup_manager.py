"""
test_cleanup_manager.py

Focused regression tests for core/cleanup_manager.py (Task 6B.1).

Uses the real InMemoryJobRepository (via core.job_manager.set_repository)
so eligibility checks exercise the actual get_job()/VALID_STATUSES
contract rather than a hand-rolled mock — consistent with how
test_job_ownership.py / test_upload_security.py already validate against
real repository behavior elsewhere in this project.

Does NOT touch main.py's database wiring or ARISE_SKIP_DB_INIT — this
test file explicitly injects an InMemoryJobRepository itself, so it is
independently runnable without a real database.
"""

import os
import uuid

import pytest

import core.job_manager as job_manager
from core.job_manager import InMemoryJobRepository
import core.cleanup_manager as cleanup_manager
from core.cleanup_manager import (
    is_cleanup_eligible,
    is_job_cleanup_eligible,
    validate_upload_path,
    safe_delete_sample,
    delete_job_sample_if_eligible,
    UPLOAD_DIR,
)


@pytest.fixture(autouse=True)
def _fresh_in_memory_repo():
    """Isolate every test with its own fresh, real InMemoryJobRepository."""
    job_manager.set_repository(InMemoryJobRepository())
    yield


@pytest.fixture
def make_job():
    created_paths = []

    def _make(status="uploaded", with_file=True):
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
        if status != "uploaded":
            job_manager.update_job(job_id, status)
        return job_id, file_path

    yield _make

    for p in created_paths:
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 1-5. Lifecycle eligibility
# ---------------------------------------------------------------------------

def test_uploaded_job_not_eligible(make_job):
    job_id, _ = make_job(status="uploaded")
    assert is_job_cleanup_eligible(job_id) is False


def test_processing_job_never_eligible(make_job):
    job_id, _ = make_job(status="processing")
    assert is_job_cleanup_eligible(job_id) is False


def test_completed_job_potentially_eligible(make_job):
    job_id, _ = make_job(status="uploaded")
    job_manager.set_result(job_id, {"verdict": "MALICIOUS"})
    assert is_job_cleanup_eligible(job_id) is True


def test_failed_job_potentially_eligible(make_job):
    job_id, _ = make_job(status="uploaded")
    job_manager.set_job_error(job_id, "failed", "engine crashed")
    assert is_job_cleanup_eligible(job_id) is True


def test_missing_job_fails_closed():
    assert is_job_cleanup_eligible("nonexistent-job-id") is False


def test_unknown_status_fails_closed(make_job, monkeypatch):
    job_id, _ = make_job(status="uploaded")
    # Directly corrupt the stored status to something outside
    # VALID_STATUSES to prove the eligibility check fails closed on it,
    # not just on the four known statuses.
    real_get = job_manager.get_job
    def _bad_get(jid):
        job = real_get(jid)
        if job:
            job = dict(job)
            job["status"] = "totally-unknown-status"
        return job
    monkeypatch.setattr(cleanup_manager, "get_job", _bad_get)
    assert is_job_cleanup_eligible(job_id) is False


# ---------------------------------------------------------------------------
# Task 6C — pure, status-only eligibility primitive: is_cleanup_eligible()
#
# These test the PURE FUNCTION directly — a plain status string in, a bool
# out. No job_id, no get_job() lookup, no filesystem access, no fixture.
# This is deliberately separate from the test_*_job_*_eligible tests above,
# which exercise the SAME rule indirectly through real job objects via
# is_job_cleanup_eligible(). Together they prove both layers agree.
# ---------------------------------------------------------------------------

def test_is_cleanup_eligible_uploaded_is_false():
    assert is_cleanup_eligible("uploaded") is False


def test_is_cleanup_eligible_processing_is_false():
    assert is_cleanup_eligible("processing") is False


def test_is_cleanup_eligible_completed_is_true():
    assert is_cleanup_eligible("completed") is True


def test_is_cleanup_eligible_failed_is_true():
    assert is_cleanup_eligible("failed") is True


def test_is_cleanup_eligible_unknown_status_is_false():
    """
    Fail-closed on any string outside VALID_STATUSES — not just the four
    known statuses. Distinct from test_unknown_status_fails_closed above,
    which tests this through is_job_cleanup_eligible(job_id) with a
    monkeypatched get_job(); this calls the pure function directly with
    no job involved at all.
    """
    assert is_cleanup_eligible("totally-unknown-status") is False
    assert is_cleanup_eligible("") is False
    assert is_cleanup_eligible("PENDING") is False  # AnalysisJob's default
                                                      # status string must
                                                      # not be conflated
                                                      # with job_manager's
                                                      # vocabulary


# ---------------------------------------------------------------------------
# Task 6C — job-ID wrapper delegates to the pure function
# ---------------------------------------------------------------------------

def test_is_job_cleanup_eligible_delegates_to_pure_function(make_job, monkeypatch):
    """
    Proves DELEGATION, not just matching output: is_job_cleanup_eligible()
    must call is_cleanup_eligible(status) rather than re-implementing the
    same rule a second time. Spies on the pure function (still calling
    through to the real implementation) and asserts it was invoked with
    the job's actual status, and that its return value is what the
    wrapper returns.
    """
    job_id, _ = make_job(status="uploaded")
    job_manager.set_result(job_id, {"verdict": "BENIGN"})  # -> "completed"

    calls = []
    real_is_cleanup_eligible = cleanup_manager.is_cleanup_eligible

    def _spy(status):
        calls.append(status)
        return real_is_cleanup_eligible(status)

    monkeypatch.setattr(cleanup_manager, "is_cleanup_eligible", _spy)

    result = is_job_cleanup_eligible(job_id)

    assert calls == ["completed"], (
        "is_job_cleanup_eligible must delegate classification to "
        "is_cleanup_eligible(status) — single source of truth"
    )
    assert result is True

    # Also prove the wrapper's return value IS the pure function's return
    # value, not merely correlated with it — force a mismatched answer
    # from the (now fully-replaced) pure function and confirm the wrapper
    # faithfully returns exactly that, rather than recomputing anything
    # itself.
    monkeypatch.setattr(cleanup_manager, "is_cleanup_eligible", lambda status: "sentinel")
    assert is_job_cleanup_eligible(job_id) == "sentinel"


# ---------------------------------------------------------------------------
# Task 6C — eligibility checks never delete physical files
# ---------------------------------------------------------------------------

def test_eligibility_checks_never_delete_physical_files(make_job, monkeypatch):
    """
    is_cleanup_eligible() and is_job_cleanup_eligible() are classification
    ONLY — Task 6C explicitly adds no deletion trigger anywhere. Guard
    against a future regression (e.g. someone "helpfully" wiring deletion
    into the eligibility check itself) by making Path.unlink a hard
    failure for the duration of this test, then calling both eligibility
    functions — across every status, including the "potentially eligible"
    ones — and confirming no exception is raised and the file is
    untouched.
    """
    from pathlib import Path

    def _unlink_must_not_be_called(self, *a, **k):
        raise AssertionError(
            f"unlink() was called on {self} — an eligibility check must "
            f"never delete a file"
        )

    monkeypatch.setattr(Path, "unlink", _unlink_must_not_be_called)

    for status in ("uploaded", "processing"):
        job_id, file_path = make_job(status=status)
        assert is_job_cleanup_eligible(job_id) is False
        assert file_path.exists()

    for status in ("completed", "failed"):
        job_id, file_path = make_job(status="uploaded")
        if status == "completed":
            job_manager.set_result(job_id, {"verdict": "BENIGN"})
        else:
            job_manager.set_job_error(job_id, "failed", "engine crashed")
        assert is_job_cleanup_eligible(job_id) is True
        assert file_path.exists(), (
            "a TRUE eligibility answer must not itself cause deletion — "
            "only a separate, explicit call to safe_delete_sample()/"
            "delete_job_sample_if_eligible() may delete anything"
        )

    # And the pure function, called with every valid + an invalid status,
    # touches no path at all (it doesn't even accept one).
    for status in ("uploaded", "processing", "completed", "failed", "bogus"):
        is_cleanup_eligible(status)  # must not raise, must not touch Path.unlink

def test_valid_upload_path_accepted(make_job):
    _, file_path = make_job(status="uploaded")
    result = validate_upload_path(str(file_path))
    assert result is not None
    assert result == file_path.resolve()


def test_path_traversal_rejected():
    traversal = str(UPLOAD_DIR / ".." / ".." / "etc" / "passwd")
    assert validate_upload_path(traversal) is None


def test_path_outside_upload_root_rejected(tmp_path):
    outside_uuid = f"{uuid.uuid4()}.bin"
    outside = tmp_path / outside_uuid
    outside.write_bytes(b"not in upload dir")
    assert validate_upload_path(str(outside)) is None


def test_upload_root_itself_cannot_be_deleted():
    assert validate_upload_path(str(UPLOAD_DIR)) is None
    result = safe_delete_sample(str(UPLOAD_DIR))
    assert result.success is False


def test_directory_deletion_rejected():
    subdir = UPLOAD_DIR / f"{uuid.uuid4()}.bin"
    subdir.mkdir(parents=True, exist_ok=True)
    try:
        assert validate_upload_path(str(subdir)) is None
        result = safe_delete_sample(str(subdir))
        assert result.success is False
        assert subdir.exists()
    finally:
        subdir.rmdir()


# ---------------------------------------------------------------------------
# 11-13. Missing/repeated deletion, UUID validation
# ---------------------------------------------------------------------------

def test_missing_file_handled_safely():
    fake = UPLOAD_DIR / f"{uuid.uuid4()}.bin"
    assert not fake.exists()
    result = safe_delete_sample(str(fake))
    assert result.success is True
    assert result.reason == "already_absent"


def test_repeated_deletion_is_idempotent(make_job):
    _, file_path = make_job(status="uploaded")
    first = safe_delete_sample(str(file_path))
    assert first.success is True
    assert first.reason == "deleted"

    second = safe_delete_sample(str(file_path))
    assert second.success is True
    assert second.reason == "already_absent"


def test_non_uuid_filename_rejected():
    bad_name = UPLOAD_DIR / "not-a-uuid.bin"
    bad_name.write_bytes(b"x")
    try:
        assert validate_upload_path(str(bad_name)) is None
    finally:
        bad_name.unlink()


# ---------------------------------------------------------------------------
# 14. Symlink escape (POSIX-practical)
# ---------------------------------------------------------------------------

def test_symlink_escape_rejected(tmp_path):
    if not hasattr(os, "symlink"):
        pytest.skip("symlink not supported on this platform")

    outside_target = tmp_path / "secret.bin"
    outside_target.write_bytes(b"should not be reachable")

    link_name = f"{uuid.uuid4()}.bin"
    link_path = UPLOAD_DIR / link_name
    try:
        os.symlink(str(outside_target), str(link_path))
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted in this environment")

    try:
        # resolve() follows the symlink; the resolved target lives
        # outside UPLOAD_DIR, so this must be rejected.
        assert validate_upload_path(str(link_path)) is None
        result = safe_delete_sample(str(link_path))
        assert result.success is False
        assert outside_target.exists()
    finally:
        if link_path.exists() or link_path.is_symlink():
            link_path.unlink()


# ---------------------------------------------------------------------------
# Combined lifecycle-aware primitive
# ---------------------------------------------------------------------------

def test_delete_job_sample_if_eligible_blocks_processing(make_job):
    job_id, file_path = make_job(status="processing")
    result = delete_job_sample_if_eligible(job_id)
    assert result.success is False
    assert result.reason == "not_eligible"
    assert file_path.exists()


def test_delete_job_sample_if_eligible_allows_completed(make_job):
    job_id, file_path = make_job(status="uploaded")
    job_manager.set_result(job_id, {"verdict": "BENIGN"})
    result = delete_job_sample_if_eligible(job_id)
    assert result.success is True
    assert not file_path.exists()