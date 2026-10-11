"""
backend/tests/test_queue_submission_rollback.py

Targeted tests for Fix 2: Rollback when queue submission fails in upload_analyze.
Verifies:
1. Successful submission creates job record and persists upload.
2. Queue failure triggers best-effort rollback:
   - Newly created file on disk is removed.
   - Newly created JobRecord is deleted from repository.
   - Controlled 503 response returned without exposing credentials or internal trace.
   - Server-side logging captures the original enqueue exception.
3. Rollback failure resilience:
   - If deletion of job record or file raises an error during rollback,
     the original 503 error is not masked and the rollback failure is logged.
4. Existing files belonging to other jobs/users are never touched.
"""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient

import auth.dependencies as auth_deps
from core import job_manager
import upload_api

USER_A = SimpleNamespace(id=101, username="alice", is_active=True)


@pytest.fixture
def client(tmp_path, monkeypatch):
    upload_dir = tmp_path / "arise_uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(upload_api, "UPLOAD_DIR", upload_dir)

    # Use in-memory repo for job_manager to isolate test
    repo = job_manager.InMemoryJobRepository()
    job_manager.set_repository(repo)

    # Override current user dependency
    upload_api.app.dependency_overrides[auth_deps.get_current_user] = lambda: USER_A

    yield TestClient(upload_api.app), upload_dir, repo

    upload_api.app.dependency_overrides.clear()


def test_successful_queue_submission(client):
    test_client, upload_dir, repo = client

    with patch.object(upload_api.run_analysis_task, "apply_async") as mock_apply:
        mock_apply.side_effect = lambda *args, **kwargs: MagicMock(id=kwargs.get("task_id", "default-id"))

        res = test_client.post(
            "/upload-analyze",
            files={"file": ("sample.exe", b"MZdummyexecutablecontent", "application/octet-stream")},
        )
        assert res.status_code == 202
        data = res.json()
        assert data["status"] == "pending"
        assert data["stage"] == "queued"
        task_id = data["task_id"]

        # Job record should exist
        job = repo.get(task_id)
        assert job is not None
        assert job["user_id"] == 101
        assert job["filename"] == "sample.exe"

        # File on disk should exist
        file_path = upload_dir / f"{task_id}.bin"
        assert file_path.is_file()


def test_queue_failure_triggers_cleanup(client):
    test_client, upload_dir, repo = client

    # Simulate Celery/Redis enqueue failure
    with patch.object(upload_api.run_analysis_task, "apply_async", side_effect=RuntimeError("Redis connection refused")), \
         patch.object(upload_api.log, "error") as mock_log_err:

        res = test_client.post(
            "/upload-analyze",
            files={"file": ("malware.exe", b"MZmaliciouscode", "application/octet-stream")},
        )

        assert res.status_code == 503
        data = res.json()
        assert "Queue submission failed" in data["detail"]
        # Must not expose raw internal trace to client
        assert "Redis connection refused" not in data["detail"]

        # Server-side log should preserve the original exception
        assert any("Failed to enqueue analysis task" in str(call) for call in mock_log_err.call_args_list)

        # Verify no orphaned job records remain
        all_jobs = repo.list_jobs()
        assert len(all_jobs) == 0

        # Verify no orphaned files remain in upload directory
        files_remaining = list(upload_dir.glob("*.bin"))
        assert len(files_remaining) == 0


def test_queue_failure_does_not_remove_other_files(client):
    test_client, upload_dir, repo = client

    # Pre-create an unrelated file and job
    existing_job_id = "preexisting-job-id"
    existing_file = upload_dir / f"{existing_job_id}.bin"
    existing_file.write_bytes(b"MZlegitbinary")
    repo.create(existing_job_id, "legit.exe", str(existing_file), 999)

    with patch.object(upload_api.run_analysis_task, "apply_async", side_effect=RuntimeError("Broker down")):
        res = test_client.post(
            "/upload-analyze",
            files={"file": ("new_sample.exe", b"MZnewpayload", "application/octet-stream")},
        )
        assert res.status_code == 503

    # The preexisting file and job must remain untouched
    assert existing_file.is_file()
    assert repo.get(existing_job_id) is not None
    assert len(repo.list_jobs()) == 1


def test_queue_failure_when_rollback_itself_fails(client):
    test_client, upload_dir, repo = client

    # Simulate delete_job failing during rollback
    with patch.object(upload_api.run_analysis_task, "apply_async", side_effect=RuntimeError("Celery timeout")), \
         patch("upload_api.delete_job", side_effect=RuntimeError("DB delete failed")), \
         patch.object(upload_api.log, "error") as mock_log_err:

        res = test_client.post(
            "/upload-analyze",
            files={"file": ("sample.exe", b"MZdummycontent", "application/octet-stream")},
        )

        # Must still return 503 to client without crashing
        assert res.status_code == 503
        # Original enqueue failure and rollback failure must both be logged
        assert any("Failed to enqueue analysis task" in str(call) for call in mock_log_err.call_args_list)
        assert any("Rollback failed for job record" in str(call) for call in mock_log_err.call_args_list)
