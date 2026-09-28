"""
core/job_manager.py

Authoritative persistent job lifecycle, backed by models.JobRecord.

Two repository implementations share one contract:
    create(job_id, filename, file_path, user_id) -> bool
    get(job_id) -> dict | None
    update_status(job_id, status) -> bool
    set_result(job_id, result) -> bool
    set_error(job_id, status, error_message) -> bool
    delete(job_id) -> bool
    list_jobs() -> list[dict]
    reconcile_interrupted() -> int

get() always returns a plain dict with exactly:
    job_id, user_id, filename, file_path, status, result,
    error_message, created_at, updated_at

Valid statuses are exactly: uploaded, processing, completed, failed.
There is no "expired" status — expire_job() hard-deletes the JobRecord;
it does not set a status.
"""

import copy
import json
import threading
import uuid
from datetime import datetime, timezone

VALID_STATUSES = {"uploaded", "processing", "completed", "failed"}
RESTART_INTERRUPTED_MESSAGE = "Job was interrupted by a server restart"


def _now():
    return datetime.now(timezone.utc)


def generate_job_id() -> str:
    return str(uuid.uuid4())


# =============================================================================
# In-memory repository (tests / no-DB environments)
# =============================================================================

class InMemoryJobRepository:
    def __init__(self):
        self._jobs: dict = {}
        self._lock = threading.Lock()

    def create(self, job_id, filename, file_path, user_id) -> bool:
        if not job_id or not filename or not file_path or user_id is None:
            return False
        now = _now().isoformat()
        with self._lock:
            if job_id in self._jobs:
                return False
            self._jobs[job_id] = {
                "job_id": job_id,
                "user_id": user_id,
                "filename": filename,
                "file_path": file_path,
                "status": "uploaded",
                "result": None,
                "error_message": None,
                "created_at": now,
                "updated_at": now,
            }
        return True

    def get(self, job_id):
        with self._lock:
            job = self._jobs.get(job_id)
            return copy.deepcopy(job) if job is not None else None

    def update_status(self, job_id, status) -> bool:
        if status not in VALID_STATUSES:
            return False
        with self._lock:
            if job_id not in self._jobs:
                return False
            self._jobs[job_id]["status"] = status
            self._jobs[job_id]["updated_at"] = _now().isoformat()
            return True

    def set_result(self, job_id, result) -> bool:
        with self._lock:
            if job_id not in self._jobs:
                return False
            self._jobs[job_id]["status"] = "completed"
            self._jobs[job_id]["result"] = copy.deepcopy(result)
            self._jobs[job_id]["error_message"] = None
            self._jobs[job_id]["updated_at"] = _now().isoformat()
            return True

    def set_error(self, job_id, status, error_message) -> bool:
        if status not in VALID_STATUSES:
            return False
        with self._lock:
            if job_id not in self._jobs:
                return False
            self._jobs[job_id]["status"] = status
            self._jobs[job_id]["error_message"] = error_message
            # Bug fix: a job transitioning to failed/error must not keep a
            # stale result from a prior completed run (e.g. a retry after
            # set_result() was already called once for this job_id).
            self._jobs[job_id]["result"] = None
            self._jobs[job_id]["updated_at"] = _now().isoformat()
            return True

    def delete(self, job_id) -> bool:
        with self._lock:
            if job_id not in self._jobs:
                return False
            del self._jobs[job_id]
            return True

    def list_jobs(self):
        with self._lock:
            return [copy.deepcopy(j) for j in self._jobs.values()]

    def reconcile_interrupted(self) -> int:
        count = 0
        with self._lock:
            for job in self._jobs.values():
                if job["status"] == "processing":
                    job["status"] = "failed"
                    job["error_message"] = RESTART_INTERRUPTED_MESSAGE
                    job["updated_at"] = _now().isoformat()
                    count += 1
        return count


# =============================================================================
# SQLAlchemy repository (production) — backed by models.JobRecord
# =============================================================================

class SQLAlchemyJobRepository:
    """
    `session_factory` is a sessionmaker (e.g. database.SessionLocal, or a
    test's own isolated one) — a fresh Session is opened and closed per
    call, so a new SQLAlchemyJobRepository instance sharing the same
    underlying database can immediately see committed state (no per-call
    caching), which is what `test_persists_across_fresh_repository_instance`
    depends on.

    All write operations are serialized through one process-local lock in
    addition to normal DB transactions, avoiding "database is locked"
    contention under SQLite's single-writer model when multiple threads
    hit the same job concurrently — this is a minimum-change concurrency
    safeguard, not a replacement for real DB-level locking semantics.
    """

    def __init__(self, session_factory):
        self._session_factory = session_factory
        self._lock = threading.Lock()

    @staticmethod
    def _to_dict(record) -> dict:
        result = None
        if record.result:
            try:
                result = json.loads(record.result)
            except (TypeError, ValueError):
                result = None
        return {
            "job_id": record.job_id,
            "user_id": record.user_id,
            "filename": record.filename,
            "file_path": record.file_path,
            "status": record.status,
            "result": result,
            "error_message": record.error_message,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }

    def create(self, job_id, filename, file_path, user_id) -> bool:
        from models import JobRecord

        if not job_id or not filename or not file_path or user_id is None:
            return False

        with self._lock:
            session = self._session_factory()
            try:
                if session.get(JobRecord, job_id) is not None:
                    return False
                record = JobRecord(
                    job_id=job_id,
                    user_id=user_id,
                    filename=filename,
                    file_path=file_path,
                    status="uploaded",
                    result=None,
                    error_message=None,
                )
                session.add(record)
                session.commit()
                return True
            except Exception:
                session.rollback()
                return False
            finally:
                session.close()

    def get(self, job_id):
        from models import JobRecord

        session = self._session_factory()
        try:
            record = session.get(JobRecord, job_id)
            return self._to_dict(record) if record is not None else None
        finally:
            session.close()

    def update_status(self, job_id, status) -> bool:
        if status not in VALID_STATUSES:
            return False
        from models import JobRecord

        with self._lock:
            session = self._session_factory()
            try:
                record = session.get(JobRecord, job_id)
                if record is None:
                    return False
                record.status = status
                record.updated_at = _now()
                session.commit()
                return True
            finally:
                session.close()

    def set_result(self, job_id, result) -> bool:
        from models import JobRecord

        with self._lock:
            session = self._session_factory()
            try:
                record = session.get(JobRecord, job_id)
                if record is None:
                    return False
                record.status = "completed"
                record.result = json.dumps(result)
                record.error_message = None
                record.updated_at = _now()
                session.commit()
                return True
            finally:
                session.close()

    def set_error(self, job_id, status, error_message) -> bool:
        if status not in VALID_STATUSES:
            return False
        from models import JobRecord

        with self._lock:
            session = self._session_factory()
            try:
                record = session.get(JobRecord, job_id)
                if record is None:
                    return False
                record.status = status
                record.error_message = error_message
                # Bug fix: same stale-result issue as InMemoryJobRepository
                # above — clear any previously persisted completed result.
                record.result = None
                record.updated_at = _now()
                session.commit()
                return True
            finally:
                session.close()

    def delete(self, job_id) -> bool:
        from models import JobRecord

        with self._lock:
            session = self._session_factory()
            try:
                record = session.get(JobRecord, job_id)
                if record is None:
                    return False
                session.delete(record)
                session.commit()
                return True
            finally:
                session.close()

    def list_jobs(self):
        from models import JobRecord

        session = self._session_factory()
        try:
            return [self._to_dict(r) for r in session.query(JobRecord).all()]
        finally:
            session.close()

    def reconcile_interrupted(self) -> int:
        from models import JobRecord

        with self._lock:
            session = self._session_factory()
            try:
                stuck = (
                    session.query(JobRecord)
                    .filter(JobRecord.status == "processing")
                    .all()
                )
                count = 0
                for record in stuck:
                    record.status = "failed"
                    record.error_message = RESTART_INTERRUPTED_MESSAGE
                    record.updated_at = _now()
                    count += 1
                session.commit()
                return count
            finally:
                session.close()


# =============================================================================
# Active repository + public module-level API
#
# Production callers (api/routes/upload.py, api/routes/analysis.py,
# core/cleanup_manager.py, main.py's lifespan) go through these
# functions rather than touching a repository instance directly, so the
# active repository can be swapped (see set_repository) without touching
# callers — exactly the pattern test_job_lifecycle.py's
# _isolate_active_repository fixture and test_cleanup_manager.py /
# test_retention_policy.py's _fresh_in_memory_repo fixture rely on.
# =============================================================================

_repo = InMemoryJobRepository()


def set_repository(repo) -> None:
    global _repo
    _repo = repo


def create_job(job_id: str, filename: str, file_path: str, user_id: int) -> bool:
    return _repo.create(job_id, filename, file_path, user_id)


def update_job(job_id: str, status: str) -> bool:
    return _repo.update_status(job_id, status)


def get_job(job_id: str):
    return _repo.get(job_id)


def list_jobs():
    return _repo.list_jobs()


def set_result(job_id: str, result) -> bool:
    return _repo.set_result(job_id, result)


def set_job_error(job_id: str, status: str, error_message: str) -> bool:
    return _repo.set_error(job_id, status, error_message)


def expire_job(job_id: str) -> bool:
    """Hard-deletes the JobRecord. There is no 'expired' status."""
    return _repo.delete(job_id)


def reconcile_startup_state() -> int:
    return _repo.reconcile_interrupted()
