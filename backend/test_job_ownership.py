"""
Job-ownership regression tests (in-process, fast, self-contained).

Replaces the old live-server urllib script.  Everything on the ownership path is
REAL:

    * api.routes.analysis router + _resolve_owned_path
    * auth.dependencies.get_current_user / require_user_ownership
    * core.job_manager job lookup (real InMemoryJobRepository)
    * auth.routes /auth/register + /auth/login (real password hashing + JWT)
    * models.User on an isolated in-memory SQLite database

The ONLY thing replaced is the expensive analysis boundary,
api.routes.analysis.run_analysis_pipeline, which is reached strictly AFTER the
ownership check has passed.  The stub records its calls, so the tests also prove
the pipeline never starts for unauthenticated or foreign requests.

Run:
    python -m pytest -q test_job_ownership.py
"""

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.routes import analysis as analysis_route
from auth.routes import router as auth_router
from core import job_manager
from database import Base, get_db
from models import User

STUB_RESULT = {"stub": "analysis pipeline not executed"}
NOT_FOUND = {"detail": "Resource not found."}

USERS = {
    "a": {
        "email": "autorev.owner.a@example.com",
        "username": "autorev_owner_a",
        "password": "AutoRev-Owner-A-123!",
        "full_name": "AutoRev Owner A",
    },
    "b": {
        "email": "autorev.owner.b@example.com",
        "username": "autorev_owner_b",
        "password": "AutoRev-Owner-B-123!",
        "full_name": "AutoRev Owner B",
    },
}


# ---------------------------------------------------------------------------
# App / database / users (module scope: password hashing is the slow part)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield sessionmaker(bind=engine, autoflush=False, autocommit=False)
    engine.dispose()


@pytest.fixture(scope="module")
def client(session_factory):
    app = FastAPI()
    app.include_router(auth_router)
    app.include_router(analysis_route.router)

    def _override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture(scope="module")
def users(client, session_factory):
    """Register + log in User A and User B through the real auth routes."""
    out = {}
    for key, payload in USERS.items():
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code in (200, 201), resp.text

        resp = client.post(
            "/auth/login",
            json={"email": payload["email"], "password": payload["password"]},
        )
        assert resp.status_code == 200, resp.text
        token = resp.json()["access_token"]

        db = session_factory()
        try:
            user_id = db.query(User).filter(User.email == payload["email"]).one().id
        finally:
            db.close()

        out[key] = {"id": user_id, "headers": {"Authorization": f"Bearer {token}"}}

    assert out["a"]["id"] != out["b"]["id"]
    return out


# ---------------------------------------------------------------------------
# Per-test isolation: job repository + analysis-pipeline boundary
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def pipeline_stub(monkeypatch):
    """Stub ONLY the expensive pipeline; record every call it receives."""
    calls = []

    def _stub(path):
        calls.append(path)
        return dict(STUB_RESULT)

    monkeypatch.setattr(analysis_route, "run_analysis_pipeline", _stub)
    return calls


@pytest.fixture
def owned_job(users, tmp_path, monkeypatch):
    """A job owned by User A, created through the real job_manager API."""
    monkeypatch.setattr(job_manager, "_repo", job_manager.InMemoryJobRepository())

    sample = tmp_path / "ownership_test.bin"
    sample.write_bytes(b"AutoRev ownership security test")

    job_id = job_manager.generate_job_id()
    assert job_manager.create_job(
        job_id, "ownership_test.txt", str(sample), users["a"]["id"]
    )
    return {"job_id": job_id, "file_path": str(sample)}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_owner_access_passes_ownership_layer(client, users, owned_job, pipeline_stub):
    resp = client.get(f"/analysis/{owned_job['job_id']}", headers=users["a"]["headers"])

    assert resp.status_code == 200
    assert resp.json() == STUB_RESULT
    # the real resolver handed the job's stored file_path to the pipeline boundary
    assert pipeline_stub == [owned_job["file_path"]]


def test_cross_user_access_is_404_and_never_runs_pipeline(client, users, owned_job, pipeline_stub):
    resp = client.get(f"/analysis/{owned_job['job_id']}", headers=users["b"]["headers"])

    assert resp.status_code == 404
    assert resp.json() == NOT_FOUND
    assert STUB_RESULT["stub"] not in resp.text
    assert pipeline_stub == []


def test_foreign_and_missing_jobs_return_identical_404(client, users, owned_job, pipeline_stub):
    foreign = client.get(f"/analysis/{owned_job['job_id']}", headers=users["b"]["headers"])
    missing_for_b = client.get(f"/analysis/{uuid.uuid4()}", headers=users["b"]["headers"])
    missing_for_a = client.get(f"/analysis/{uuid.uuid4()}", headers=users["a"]["headers"])

    for resp in (foreign, missing_for_b, missing_for_a):
        assert resp.status_code == 404
        assert resp.json() == NOT_FOUND
    # no existence oracle: a foreign job is indistinguishable from a missing one
    assert foreign.status_code == missing_for_b.status_code == missing_for_a.status_code
    assert foreign.json() == missing_for_b.json() == missing_for_a.json()
    assert pipeline_stub == []


def test_unauthenticated_access_is_401_and_never_runs_pipeline(client, owned_job, pipeline_stub):
    resp = client.get(f"/analysis/{owned_job['job_id']}")

    assert resp.status_code == 401
    assert resp.json() == {"detail": "Authentication required."}
    assert resp.headers.get("www-authenticate") == "Bearer"
    assert pipeline_stub == []


def test_invalid_token_is_401_and_never_runs_pipeline(client, owned_job, pipeline_stub):
    resp = client.get(
        f"/analysis/{owned_job['job_id']}",
        headers={"Authorization": "Bearer not-a-valid-token"},
    )

    assert resp.status_code == 401
    assert pipeline_stub == []
