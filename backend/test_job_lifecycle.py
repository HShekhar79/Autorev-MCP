"""
test_job_lifecycle.py

Task 8 — authoritative job lifecycle regression tests.

Uses an isolated, on-disk SQLite database created fresh per test session
(never the developer's real arise.db), and constructs SQLAlchemyJobRepository
instances directly rather than relying on main.py's lifespan wiring — so
these tests exercise core/job_manager.py's persistence contract in
isolation from the FastAPI app, auth flow, and analysis pipeline.

Run with:
    pytest -q test_job_lifecycle.py
"""

import os
import tempfile
import threading
import time
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from core import job_manager
from core.job_manager import (
    SQLAlchemyJobRepository,
    InMemoryJobRepository,
    RESTART_INTERRUPTED_MESSAGE,
    VALID_STATUSES,
)


# ---------------------------------------------------------------------------
# Isolated database fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def isolated_db(tmp_path, monkeypatch):
    """
    A throwaway SQLite file per test, with its own Base/engine/session
    factory and its own User + JobRecord tables — completely independent
    of the real backend/arise.db and of models.Base's global registry
    state where possible.

    We reuse the REAL `models.JobRecord`/`models.User` classes (so the
    repository under test is exercised against the actual production
    schema, not a hand-rolled stand-in), but bind them to a fresh,
    isolated engine/session factory for this test only.
    """
    db_path = tmp_path / f"test_lifecycle_{uuid.uuid4().hex}.db"
    db_url = f"sqlite:///{db_path}"

    engine = create_engine(db_url, connect_args={"check_same_thread": False})

    import models  # the real production models module
    models.Base.metadata.create_all(bind=engine)

    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # A real user row is required because JobRecord.user_id is a real FK.
    session = SessionLocal()
    user = models.User(
        email=f"lifecycle_{uuid.uuid4().hex[:8]}@example.com",
        username=f"lifecycle_{uuid.uuid4().hex[:8]}",
        hashed_password="not-a-real-hash",
    )
    session.add(user)
    session.commit()
    user_id = user.id
    session.close()

    yield SessionLocal, user_id

    engine.dispose()


@pytest.fixture()
def repo(isolated_db):
    SessionLocal, _user_id = isolated_db
    return SQLAlchemyJobRepository(SessionLocal)


@pytest.fixture(autouse=True)
def _isolate_active_repository():
    """
    Every test in this file swaps job_manager's module-level active
    repository for the duration of the test, then restores whatever was
    active before — so these tests never leak state into, or depend on
    state from, any other test file that uses job_manager's public
    wrappers (create_job/get_job/etc.) against the default repository.
    """
    original = job_manager._repo
    yield
    job_manager._repo = original


# ---------------------------------------------------------------------------
# 1. create -> uploaded
# ---------------------------------------------------------------------------

def test_create_produces_uploaded_status(repo, isolated_db):
    _, user_id = isolated_db
    job_id = str(uuid.uuid4())

    created = repo.create(job_id, "sample.exe", "/tmp/storage/x.bin", user_id)
    assert created is True

    job = repo.get(job_id)
    assert job is not None
    assert job["status"] == "uploaded"
    assert job["job_id"] == job_id
    assert job["user_id"] == user_id
    assert job["filename"] == "sample.exe"
    assert job["file_path"] == "/tmp/storage/x.bin"
    assert job["result"] is None
    assert job["error_message"] is None
    assert job["created_at"] is not None
    assert job["updated_at"] is not None


def test_duplicate_job_id_rejected(repo, isolated_db):
    _, user_id = isolated_db
    job_id = str(uuid.uuid4())
    assert repo.create(job_id, "a.exe", "/tmp/a.bin", user_id) is True
    assert repo.create(job_id, "b.exe", "/tmp/b.bin", user_id) is False


# ---------------------------------------------------------------------------
# 2. uploaded -> processing
# ---------------------------------------------------------------------------

def test_uploaded_transitions_to_processing(repo, isolated_db):
    _, user_id = isolated_db
    job_id = str(uuid.uuid4())
    repo.create(job_id, "a.exe", "/tmp/a.bin", user_id)

    assert repo.update_status(job_id, "processing") is True
    job = repo.get(job_id)
    assert job["status"] == "processing"


# ---------------------------------------------------------------------------
# 3 & 4. processing -> completed, result round-trip
# ---------------------------------------------------------------------------

def test_processing_to_completed_with_result_round_trip(repo, isolated_db):
    _, user_id = isolated_db
    job_id = str(uuid.uuid4())
    repo.create(job_id, "a.exe", "/tmp/a.bin", user_id)
    repo.update_status(job_id, "processing")

    original_result = {
        "verdict": "MALICIOUS",
        "risk": {"combined_score": 82},
        "cvss_results": {"cvss_score": 9.1},
        "nested": {"list": [1, 2, {"three": 3}]},
    }

    assert repo.set_result(job_id, original_result) is True

    job = repo.get(job_id)
    assert job["status"] == "completed"
    assert job["result"] == original_result  # exact structural round trip
    assert job["error_message"] is None


# ---------------------------------------------------------------------------
# 5. failed state + error_message
# ---------------------------------------------------------------------------

def test_failed_state_persists_error_message(repo, isolated_db):
    _, user_id = isolated_db
    job_id = str(uuid.uuid4())
    repo.create(job_id, "a.exe", "/tmp/a.bin", user_id)
    repo.update_status(job_id, "processing")

    assert repo.set_error(job_id, "failed", "simulated pipeline exception") is True

    job = repo.get(job_id)
    assert job["status"] == "failed"
    assert job["error_message"] == "simulated pipeline exception"
    assert job["result"] is None


def test_set_error_rejects_invalid_status(repo, isolated_db):
    _, user_id = isolated_db
    job_id = str(uuid.uuid4())
    repo.create(job_id, "a.exe", "/tmp/a.bin", user_id)

    assert repo.set_error(job_id, "not_a_real_status", "whatever") is False
    job = repo.get(job_id)
    assert job["status"] == "uploaded"  # unchanged


# ---------------------------------------------------------------------------
# 6. persistence across a FRESH repository instance
# ---------------------------------------------------------------------------

def test_persists_across_fresh_repository_instance(isolated_db):
    SessionLocal, user_id = isolated_db
    job_id = str(uuid.uuid4())

    repo_a = SQLAlchemyJobRepository(SessionLocal)
    repo_a.create(job_id, "a.exe", "/tmp/a.bin", user_id)
    repo_a.update_status(job_id, "processing")
    repo_a.set_result(job_id, {"verdict": "BENIGN"})

    # A brand new repository object, same underlying DB — simulates a
    # fresh process attaching to the same database file.
    repo_b = SQLAlchemyJobRepository(SessionLocal)
    job = repo_b.get(job_id)

    assert job is not None
    assert job["status"] == "completed"
    assert job["result"] == {"verdict": "BENIGN"}
    assert job["file_path"] == "/tmp/a.bin"


# ---------------------------------------------------------------------------
# 7. processing -> failed after simulated restart/reconciliation
# ---------------------------------------------------------------------------

def test_reconcile_interrupted_marks_processing_jobs_failed(repo, isolated_db):
    _, user_id = isolated_db

    stuck_job = str(uuid.uuid4())
    done_job = str(uuid.uuid4())
    fresh_job = str(uuid.uuid4())

    repo.create(stuck_job, "stuck.exe", "/tmp/stuck.bin", user_id)
    repo.update_status(stuck_job, "processing")  # simulates a crash mid-analysis

    repo.create(done_job, "done.exe", "/tmp/done.bin", user_id)
    repo.set_result(done_job, {"verdict": "BENIGN"})  # already completed

    repo.create(fresh_job, "fresh.exe", "/tmp/fresh.bin", user_id)  # still "uploaded"

    reconciled_count = repo.reconcile_interrupted()
    assert reconciled_count == 1

    stuck = repo.get(stuck_job)
    assert stuck["status"] == "failed"
    assert stuck["error_message"] == RESTART_INTERRUPTED_MESSAGE

    done = repo.get(done_job)
    assert done["status"] == "completed"  # untouched
    assert done["error_message"] is None

    fresh = repo.get(fresh_job)
    assert fresh["status"] == "uploaded"  # untouched


def test_reconcile_interrupted_is_idempotent(repo, isolated_db):
    _, user_id = isolated_db
    job_id = str(uuid.uuid4())
    repo.create(job_id, "a.exe", "/tmp/a.bin", user_id)
    repo.update_status(job_id, "processing")

    first = repo.reconcile_interrupted()
    second = repo.reconcile_interrupted()

    assert first == 1
    assert second == 0  # already "failed" — not re-counted

    job = repo.get(job_id)
    assert job["status"] == "failed"
    assert job["error_message"] == RESTART_INTERRUPTED_MESSAGE


def test_reconcile_startup_state_uses_active_repository(repo, isolated_db):
    _, user_id = isolated_db
    job_id = str(uuid.uuid4())
    repo.create(job_id, "a.exe", "/tmp/a.bin", user_id)
    repo.update_status(job_id, "processing")

    job_manager.set_repository(repo)
    count = job_manager.reconcile_startup_state()

    assert count == 1
    job = job_manager.get_job(job_id)
    assert job["status"] == "failed"
    assert job["error_message"] == RESTART_INTERRUPTED_MESSAGE


# ---------------------------------------------------------------------------
# 8 & 9. completed job returns persisted result / does not re-run pipeline
# ---------------------------------------------------------------------------

def test_completed_job_short_circuit_contract(repo, isolated_db):
    """
    This test validates the REPOSITORY-level contract that
    api/routes/analysis.py's _run_full_pipeline() is patched to rely on
    (see analysis_py_patch_instructions.md, section F): once a job is
    "completed" with a non-empty result, that result is retrievable
    without needing anything from _pipeline_cache.

    It does not exercise the real pipeline function (out of scope for
    this file / not available in isolation), but proves the persistence
    guarantee that change depends on.
    """
    _, user_id = isolated_db
    job_id = str(uuid.uuid4())
    repo.create(job_id, "a.exe", "/tmp/a.bin", user_id)
    repo.update_status(job_id, "processing")
    repo.set_result(job_id, {"verdict": "MALICIOUS", "risk": {"combined_score": 90}})

    # Simulate "process restarted, _pipeline_cache is empty" by simply
    # not touching any in-memory cache at all — the repository is the
    # only thing consulted here, on purpose.
    job = repo.get(job_id)
    assert job["status"] == "completed"
    assert job["result"] is not None
    assert job["result"]["verdict"] == "MALICIOUS"


# ---------------------------------------------------------------------------
# 10. ownership remains correct
# ---------------------------------------------------------------------------

def test_ownership_preserved_through_persistence(repo, isolated_db):
    SessionLocal, user_id = isolated_db
    job_id = str(uuid.uuid4())
    repo.create(job_id, "a.exe", "/tmp/a.bin", user_id)

    job = repo.get(job_id)
    assert job["user_id"] == user_id

    # A different user_id must not collide with or be able to overwrite it.
    import models
    session = SessionLocal()
    other_user = models.User(
        email=f"other_{uuid.uuid4().hex[:8]}@example.com",
        username=f"other_{uuid.uuid4().hex[:8]}",
        hashed_password="x",
    )
    session.add(other_user)
    session.commit()
    other_user_id = other_user.id
    session.close()

    other_job_id = str(uuid.uuid4())
    repo.create(other_job_id, "b.exe", "/tmp/b.bin", other_user_id)

    job_a = repo.get(job_id)
    job_b = repo.get(other_job_id)
    assert job_a["user_id"] == user_id
    assert job_b["user_id"] == other_user_id
    assert job_a["user_id"] != job_b["user_id"]


# ---------------------------------------------------------------------------
# 11. expire_job hard-deletes
# ---------------------------------------------------------------------------

def test_delete_hard_removes_job(repo, isolated_db):
    _, user_id = isolated_db
    job_id = str(uuid.uuid4())
    repo.create(job_id, "a.exe", "/tmp/a.bin", user_id)
    assert repo.get(job_id) is not None

    assert repo.delete(job_id) is True
    assert repo.get(job_id) is None

    # Deleting again returns False rather than raising.
    assert repo.delete(job_id) is False


def test_expire_job_wrapper_still_hard_deletes(repo, isolated_db):
    _, user_id = isolated_db
    job_id = str(uuid.uuid4())
    repo.create(job_id, "a.exe", "/tmp/a.bin", user_id)

    job_manager.set_repository(repo)
    assert job_manager.expire_job(job_id) is True
    assert job_manager.get_job(job_id) is None
    # No "expired" status was introduced anywhere.
    assert "expired" not in VALID_STATUSES


# ---------------------------------------------------------------------------
# 12 & 13. concurrency: same job once, different jobs independent
# ---------------------------------------------------------------------------

def test_concurrent_status_updates_to_same_job_are_serialized_safely(repo, isolated_db):
    """
    Not a re-test of the per-job application-level lock in
    api/routes/analysis.py (that is covered by the existing, untouched
    test_job_pipeline_concurrency.py). This proves the REPOSITORY layer
    itself doesn't corrupt state or raise under concurrent writers to
    the same row — a prerequisite for that higher-level lock to be
    meaningful at all.
    """
    _, user_id = isolated_db
    job_id = str(uuid.uuid4())
    repo.create(job_id, "a.exe", "/tmp/a.bin", user_id)

    errors = []

    def worker():
        try:
            repo.update_status(job_id, "processing")
            time.sleep(0.01)
            repo.set_result(job_id, {"worker": True})
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not errors
    job = repo.get(job_id)
    assert job["status"] == "completed"
    assert job["result"] == {"worker": True}


def test_different_jobs_independent_under_concurrency(repo, isolated_db):
    _, user_id = isolated_db
    job_ids = [str(uuid.uuid4()) for _ in range(10)]
    for jid in job_ids:
        repo.create(jid, f"{jid}.exe", f"/tmp/{jid}.bin", user_id)

    def worker(jid):
        repo.update_status(jid, "processing")
        repo.set_result(jid, {"job": jid})

    threads = [threading.Thread(target=worker, args=(jid,)) for jid in job_ids]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    for jid in job_ids:
        job = repo.get(jid)
        assert job["status"] == "completed"
        assert job["result"] == {"job": jid}


# ---------------------------------------------------------------------------
# 14. existing upload contract still holds against the in-memory repo
#     (sanity check that InMemoryJobRepository's added `error_message`
#      key doesn't disturb the pre-existing dict contract)
# ---------------------------------------------------------------------------

def test_in_memory_repository_contract_unchanged_by_task8_additions():
    mem_repo = InMemoryJobRepository()
    job_id = str(uuid.uuid4())

    assert mem_repo.create(job_id, "a.exe", "/tmp/a.bin", 1) is True
    job = mem_repo.get(job_id)

    for key in ("job_id", "user_id", "filename", "file_path", "status",
                "result", "created_at", "updated_at"):
        assert key in job

    assert job["status"] == "uploaded"

    assert mem_repo.update_status(job_id, "processing") is True
    assert mem_repo.get(job_id)["status"] == "processing"

    assert mem_repo.set_result(job_id, {"ok": True}) is True
    job = mem_repo.get(job_id)
    assert job["status"] == "completed"
    assert job["result"] == {"ok": True}

    assert mem_repo.delete(job_id) is True
    assert mem_repo.get(job_id) is None
