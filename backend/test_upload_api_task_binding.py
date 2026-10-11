"""
test_upload_api_task_binding.py

Task ownership for the legacy /upload-analyze flow (upload_api.py):
the Celery task id is bound to the authenticated uploader's JobRecord, and
/task-status, DELETE /task and /report/* all enforce that binding before
touching Celery. Celery, Redis and the DB are faked; auth, job_manager and
the route code are real. Run with:

    python -m pytest -q test_upload_api_task_binding.py
"""
import importlib
import os
import sys
import types
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import auth.dependencies as deps
from core import job_manager
from database import get_db

USER_A = SimpleNamespace(id=1, is_active=True)
USER_B = SimpleNamespace(id=2, is_active=True)
TOKENS = {"token-a": USER_A, "token-b": USER_B}
AUTH_A = {"Authorization": "Bearer token-a"}
AUTH_B = {"Authorization": "Bearer token-b"}
NOT_FOUND = {"detail": "Resource not found."}
RESULT = {"analysis_meta": {"filename": "s.exe"}, "capabilities": ["c"],
          "verdict": {"verdict": "MALICIOUS"}, "risk_score": 50}


class _FakeDB:
    current = None

    def query(self, *a):
        return self

    def filter(self, *a):
        return self

    def first(self):
        return type(self).current


def _fake_decode(token):
    user = TOKENS.get(token)
    if user is None:
        raise ValueError("bad token")
    _FakeDB.current = user
    return {"sub": str(user.id)}


@pytest.fixture
def api(tmp_path):
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    spy = SimpleNamespace(dispatched=[], async_results=[], revoked=[])

    # upload_api runs database.init_db() and mkdirs at import time: neutralise both.
    import database
    with patch.object(database, "init_db", lambda: None), \
         patch.dict(os.environ, {"ARISE_UPLOAD_DIR": str(uploads)}):
        upload_api = importlib.import_module("upload_api")

    class FakeTask:
        def apply_async(self, args=None, task_id=None, **kw):
            spy.dispatched.append({"args": args, "task_id": task_id})
            return SimpleNamespace(id=task_id or "random-celery-id")

    class FakeAsyncResult:
        def __init__(self, task_id, app=None):
            spy.async_results.append(task_id)
            self.state = "SUCCESS"
            self.result = RESULT
            self.info = None

    class FakeControl:
        def revoke(self, task_id, terminate=False):
            spy.revoked.append(task_id)

    fake_worker = types.ModuleType("celery_worker")
    fake_worker.celery_app = SimpleNamespace(control=FakeControl())

    previous = job_manager._repo
    job_manager.set_repository(job_manager.InMemoryJobRepository())
    upload_api.app.dependency_overrides[get_db] = lambda: _FakeDB()

    import celery.result
    with patch.object(deps, "decode_access_token", _fake_decode), \
         patch.object(upload_api, "UPLOAD_DIR", uploads), \
         patch.object(upload_api, "run_analysis_task", FakeTask()), \
         patch.object(upload_api, "AsyncResult", FakeAsyncResult), \
         patch.object(upload_api, "celery_app", fake_worker.celery_app), \
         patch.object(celery.result, "AsyncResult", FakeAsyncResult), \
         patch.dict(sys.modules, {"celery_worker": fake_worker}):
        yield SimpleNamespace(client=TestClient(upload_api.app), spy=spy,
                              uploads=uploads)

    upload_api.app.dependency_overrides.clear()
    job_manager.set_repository(previous)


def _upload(api, headers, name="sample.exe"):
    return api.client.post("/upload-analyze", headers=headers,
                           files={"file": (name, b"MZ" + b"\x00" * 32)})


# --- binding at creation ------------------------------------------------------

def test_upload_analyze_requires_authentication(api):
    assert _upload(api, {}).status_code == 401
    assert api.spy.dispatched == []
    assert job_manager.list_jobs() == []
    assert list(api.uploads.iterdir()) == []


def test_upload_binds_task_id_to_owner_job(api):
    r = _upload(api, AUTH_A, name="../../evil.exe")
    assert r.status_code == 202
    task_id = r.json()["task_id"]

    job = job_manager.get_job(task_id)
    assert job is not None and job["user_id"] == USER_A.id
    assert api.spy.dispatched[0]["task_id"] == task_id          # task id == job id

    # storage path is UUID-based; the client filename never reaches the filesystem
    assert job["file_path"] == str(api.uploads / f"{task_id}.bin")
    assert os.path.isfile(job["file_path"])
    assert api.spy.dispatched[0]["args"] == [job["file_path"], job["filename"]]
    assert "evil" not in os.path.basename(job["file_path"])


# --- /task-status -------------------------------------------------------------

def test_task_status_owner_foreign_anon_missing(api):
    tid = _upload(api, AUTH_A).json()["task_id"]

    ok = api.client.get(f"/task-status/{tid}", headers=AUTH_A)
    assert ok.status_code == 200 and ok.json()["status"] == "completed"
    assert api.spy.async_results == [tid]
    api.spy.async_results.clear()

    foreign = api.client.get(f"/task-status/{tid}", headers=AUTH_B)
    missing = api.client.get("/task-status/no-such-task", headers=AUTH_B)
    anon = api.client.get(f"/task-status/{tid}")
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json() == NOT_FOUND
    assert anon.status_code == 401
    assert api.spy.async_results == []                           # Celery never queried


# --- DELETE /task -------------------------------------------------------------

def test_revoke_owner_only(api):
    tid = _upload(api, AUTH_A).json()["task_id"]

    assert api.client.delete(f"/task/{tid}", headers=AUTH_B).status_code == 404
    assert api.client.delete(f"/task/{tid}").status_code == 401
    assert api.client.delete("/task/no-such-task", headers=AUTH_A).status_code == 404
    assert api.spy.revoked == []

    assert api.client.delete(f"/task/{tid}", headers=AUTH_A).status_code == 200
    assert api.spy.revoked == [tid]


# --- end to end: upload -> report ---------------------------------------------

def test_report_task_access_follows_upload_ownership(api):
    tid = _upload(api, AUTH_A).json()["task_id"]
    body = {"task_id": tid}

    assert api.client.post("/report/preview", json=body, headers=AUTH_A).status_code == 200
    api.spy.async_results.clear()

    foreign = api.client.post("/report/preview", json=body, headers=AUTH_B)
    anon = api.client.post("/report/preview", json=body)
    assert foreign.status_code == 404 and foreign.json() == NOT_FOUND
    assert anon.status_code == 401
    assert api.spy.async_results == []
