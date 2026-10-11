"""
test_analysis_route_ownership.py

Regression tests for job ownership on the analysis-resource endpoints
(api/routes/analysis.py) and the job_id path of api/routes/report.py.

The real get_current_user / require_user_ownership / job_manager code runs;
only token decoding, the DB user lookup, and the (expensive) analysis
pipeline / report / PDF engines are faked. Run with:

    python -m pytest -q test_analysis_route_ownership.py
"""
import sys
import types
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import auth.dependencies as deps
from core import job_manager
from database import get_db
from api.routes import analysis as route
from api.routes import report as report_route

USER_A = SimpleNamespace(id=1, is_active=True)
USER_B = SimpleNamespace(id=2, is_active=True)
TOKENS = {"token-a": USER_A, "token-b": USER_B}
AUTH_A = {"Authorization": "Bearer token-a"}
AUTH_B = {"Authorization": "Bearer token-b"}

RESULT = {
    "analysis": {"results": [{"function_name": "f"}]},
    "imports": ["kernel32.dll"], "strings": ["s"],
    "behaviors": {"behaviors": ["process_injection"], "_detail": []},
    "capabilities": ["inject"], "capability_scores": {"inject": 1.0},
    "mitre_results": {"mitre_techniques": ["T1055"]},
    "capability_mitre_results": {"mitre_techniques": ["T1055"]},
    "final_mitre": {"mitre_techniques": ["T1055"]},
    "ranked_functions": [{"name": "f"}],
    "risk": {"combined_score": 60},
    "cvss_results": {"cvss_score": 7.5, "risk_level": "HIGH"},
    "arise_verdict": {"verdict": "MALICIOUS"},
    "capa_results": {}, "analysis_meta": {"filename": "sample.exe"},
}

# endpoint -> expected body for the owner (response shape must be unchanged)
EXPECTED = {
    "analysis": RESULT,
    "behaviours": RESULT["behaviors"],
    "mitre": {"mitre_results": RESULT["mitre_results"],
              "capability_mitre_results": RESULT["capability_mitre_results"],
              "final_mitre": RESULT["final_mitre"]},
    "capabilities": {"capabilities": ["inject"], "scores": {"inject": 1.0}},
    "cvss": RESULT["cvss_results"],
    "report": {"fake": "report"},
    "ranking": {"ranked_functions": RESULT["ranked_functions"], "total": 1},
    "risk": {"risk": RESULT["risk"], "threat_level": "HIGH",
             "cvss_score": 7.5, "cvss_risk_level": "HIGH"},
}
ENDPOINTS = list(EXPECTED)
NOT_FOUND = {"detail": "Resource not found."}


class _FakeDB:
    """Stands in for the SQLAlchemy session used by get_current_user."""
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
def env(tmp_path):
    calls = []

    def fake_pipeline(path, progress_cb=None):
        calls.append(path)
        return RESULT

    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    repo = job_manager.InMemoryJobRepository()
    previous = job_manager._repo
    job_manager.set_repository(repo)
    assert job_manager.create_job("job-a", "sample.exe", str(sample), user_id=1)

    app = FastAPI()
    app.include_router(route.router)
    app.include_router(report_route.router)
    app.dependency_overrides[get_db] = lambda: _FakeDB()

    with patch.object(deps, "decode_access_token", _fake_decode), \
         patch.object(route, "run_analysis_pipeline", fake_pipeline), \
         patch.object(route, "generate_final_report", lambda **k: {"fake": "report"}), \
         patch.object(route, "UPLOAD_DIR", str(tmp_path)):
        yield SimpleNamespace(client=TestClient(app), calls=calls, sample=sample)

    job_manager.set_repository(previous)


def _url(endpoint, job_id="job-a"):
    return f"/{endpoint}/{job_id}"


# --- A / B / F: owner access + unchanged response shape ----------------------

def test_a_owner_can_access_analysis(env):
    r = env.client.get("/analysis/job-a", headers=AUTH_A)
    assert r.status_code == 200
    assert r.json() == RESULT


@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_b_f_owner_can_access_every_endpoint_with_same_shape(env, endpoint):
    r = env.client.get(_url(endpoint), headers=AUTH_A)
    assert r.status_code == 200
    assert r.json() == EXPECTED[endpoint]


def test_f_resolve_path_still_returns_authoritative_file_path(env):
    job, path = route.resolve_path("job-a")
    assert path == str(env.sample) and job["user_id"] == 1


# --- C: another user's job ---------------------------------------------------

@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_c_other_user_gets_404_and_pipeline_never_runs(env, endpoint):
    r = env.client.get(_url(endpoint), headers=AUTH_B)
    assert r.status_code == 404
    assert r.json() == NOT_FOUND
    assert env.calls == []


# --- D: unauthenticated / invalid token -------------------------------------

@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_d_unauthenticated_gets_401_and_pipeline_never_runs(env, endpoint):
    r = env.client.get(_url(endpoint))
    assert r.status_code == 401
    assert env.calls == []


@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_d_invalid_token_gets_401(env, endpoint):
    r = env.client.get(_url(endpoint), headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401
    assert env.calls == []


# --- E: missing job is safe and indistinguishable from "not yours" ----------

@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_e_missing_job_is_indistinguishable_from_foreign_job(env, endpoint):
    missing = env.client.get(_url(endpoint, "no-such-job"), headers=AUTH_B)
    foreign = env.client.get(_url(endpoint), headers=AUTH_B)
    assert missing.status_code == foreign.status_code == 404
    assert missing.json() == foreign.json() == NOT_FOUND
    assert env.calls == []


def test_e_missing_job_unauthenticated_is_401_not_404(env):
    assert env.client.get("/analysis/no-such-job").status_code == 401


def test_legacy_job_without_user_id_is_not_exposed(env):
    # defensive: a record whose user_id cannot match anyone must not leak
    job_manager._repo._jobs["job-a"]["user_id"] = None
    assert env.client.get("/analysis/job-a", headers=AUTH_A).status_code == 404


# --- report.py job_id path -------------------------------------------------

def test_report_preview_owner_ok(env):
    r = env.client.post("/report/preview", json={"job_id": "job-a"}, headers=AUTH_A)
    assert r.status_code == 200
    assert "sections" in r.json()


def test_report_preview_other_user_404_same_as_missing(env):
    foreign = env.client.post("/report/preview", json={"job_id": "job-a"}, headers=AUTH_B)
    missing = env.client.post("/report/preview", json={"job_id": "nope"}, headers=AUTH_B)
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json() == NOT_FOUND
    assert env.calls == []


def test_report_preview_unauthenticated_401(env):
    r = env.client.post("/report/preview", json={"job_id": "job-a"})
    assert r.status_code == 401
    assert env.calls == []


@pytest.fixture
def pdf_stub():
    pkg = types.ModuleType("engines.pdf_engine")
    mod = types.ModuleType("engines.pdf_engine.pdf_engine")
    mod.generate_pdf_report = lambda **k: b"%PDF-fake"
    with patch.dict(sys.modules, {"engines.pdf_engine": pkg,
                                  "engines.pdf_engine.pdf_engine": mod}):
        yield


def test_report_generate_owner_ok_other_and_anon_blocked(env, pdf_stub):
    body = {"job_id": "job-a"}
    ok = env.client.post("/report/generate", json=body, headers=AUTH_A)
    assert ok.status_code == 200 and ok.content == b"%PDF-fake"
    n = len(env.calls)
    other = env.client.post("/report/generate", json=body, headers=AUTH_B)
    anon = env.client.post("/report/generate", json=body)
    assert other.status_code == 404 and other.json() == NOT_FOUND
    assert anon.status_code == 401
    assert len(env.calls) == n          # no pipeline run for blocked requests


def test_report_resolve_requires_an_identifier(env):
    with pytest.raises(Exception) as exc:
        report_route._resolve_result(None, None, USER_A)
    assert getattr(exc.value, "status_code", None) == 400


# ===========================================================================
# report.py: authoritative file_path (I) and task_id ownership (J-N)
# ===========================================================================

import os
import uuid


class _Spy:
    """Records filesystem probes / pipeline / PDF / Celery activity."""
    def __init__(self):
        self.isfile = []
        self.pdf = []
        self.async_results = []


@pytest.fixture
def rpt(env, tmp_path):
    """Extends `env` with: a UUID-named .bin job, a filename-derived decoy,
    a task-bound job ("task-a", owner A), spies and a fake Celery."""
    spy = _Spy()
    store = tmp_path / "store"
    store.mkdir()
    uploads = tmp_path / "uploads"           # route.UPLOAD_DIR
    uploads.mkdir()

    job_id = str(uuid.uuid4())
    real = store / f"{job_id}.bin"
    real.write_bytes(b"MZreal")
    decoy = uploads / "evil_name.exe"        # what filename-joining would hit
    decoy.write_bytes(b"MZdecoy")
    assert job_manager.create_job(job_id, "evil_name.exe", str(real), user_id=1)
    assert job_manager.create_job("task-a", "t.exe", str(real), user_id=1)

    real_isfile = os.path.isfile

    def spy_isfile(p):
        spy.isfile.append(str(p))
        return real_isfile(p)

    class FakeAsyncResult:
        def __init__(self, task_id, app=None):
            spy.async_results.append(task_id)
            self.state = "SUCCESS"
            self.result = {"analysis_meta": {"filename": "t.exe"}, "capabilities": ["c"],
                           "verdict": {"verdict": "MALICIOUS"}, "risk_score": 50}

    fake_worker = types.ModuleType("celery_worker")
    fake_worker.celery_app = object()

    pdf_pkg = types.ModuleType("engines.pdf_engine")
    pdf_mod = types.ModuleType("engines.pdf_engine.pdf_engine")

    def fake_pdf(**kwargs):
        spy.pdf.append(kwargs)
        return b"%PDF-fake"
    pdf_mod.generate_pdf_report = fake_pdf

    import celery.result
    with patch.object(route, "UPLOAD_DIR", str(uploads)), \
         patch.object(os.path, "isfile", spy_isfile), \
         patch.object(celery.result, "AsyncResult", FakeAsyncResult), \
         patch.dict(sys.modules, {"celery_worker": fake_worker,
                                  "engines.pdf_engine": pdf_pkg,
                                  "engines.pdf_engine.pdf_engine": pdf_mod}):
        yield SimpleNamespace(env=env, spy=spy, job_id=job_id, real=str(real),
                              decoy=str(decoy), client=env.client)


# --- F/G/H: report job_id owner / foreign / anonymous -----------------------

def test_f_report_job_owner_works(rpt):
    r = rpt.client.post("/report/generate", json={"job_id": rpt.job_id}, headers=AUTH_A)
    assert r.status_code == 200 and r.content == b"%PDF-fake"


def test_g_report_job_foreign_blocked(rpt):
    r = rpt.client.post("/report/generate", json={"job_id": rpt.job_id}, headers=AUTH_B)
    assert r.status_code == 404 and r.json() == NOT_FOUND


def test_h_report_job_anonymous_blocked(rpt):
    r = rpt.client.post("/report/generate", json={"job_id": rpt.job_id})
    assert r.status_code == 401


# --- I: authoritative job["file_path"], never the display filename ----------

def test_i_report_uses_authoritative_file_path_not_filename(rpt):
    rpt.client.post("/report/generate", json={"job_id": rpt.job_id}, headers=AUTH_A)
    assert rpt.env.calls == [rpt.real]            # pipeline ran on <job_id>.bin
    assert rpt.decoy not in rpt.env.calls         # not on UPLOAD_DIR/<filename>
    assert rpt.spy.pdf[0]["file_path"] == rpt.real


def test_i_report_never_probes_filename_derived_path(rpt):
    rpt.client.post("/report/generate", json={"job_id": rpt.job_id}, headers=AUTH_A)
    assert rpt.decoy not in rpt.spy.isfile


def test_i_missing_stored_file_does_not_fall_back_to_filename_path(rpt):
    os.remove(rpt.real)                           # stored sample gone, decoy still exists
    r = rpt.client.post("/report/preview", json={"job_id": rpt.job_id}, headers=AUTH_A)
    assert r.status_code == 404                   # no cached result -> unavailable
    assert rpt.env.calls == []                    # decoy was NOT analysed


def test_i_cached_result_fallback_still_works(rpt):
    os.remove(rpt.real)
    cached = {"analysis_meta": {"filename": "x"}, "capabilities": ["c"], "risk_score": 1}
    job_manager._repo._jobs[rpt.job_id]["result"] = cached
    r = rpt.client.post("/report/preview", json={"job_id": rpt.job_id}, headers=AUTH_A)
    assert r.status_code == 200 and rpt.env.calls == []


def test_i_client_supplied_file_path_is_ignored(rpt):
    body = {"job_id": rpt.job_id, "file_path": "C:/Windows/System32/config/SAM"}
    r = rpt.client.post("/report/generate", json=body, headers=AUTH_A)
    assert r.status_code == 200
    assert rpt.spy.pdf[0]["file_path"] == rpt.real


def test_blocked_job_requests_touch_no_filesystem_pipeline_or_pdf(rpt):
    for headers in (AUTH_B, {}):
        for path in ("/report/generate", "/report/preview"):
            rpt.client.post(path, json={"job_id": rpt.job_id}, headers=headers)
    assert rpt.env.calls == [] and rpt.spy.pdf == []
    assert rpt.real not in rpt.spy.isfile and rpt.decoy not in rpt.spy.isfile


# --- J-N: task_id ownership ---------------------------------------------------

@pytest.mark.parametrize("path", ["/report/preview", "/report/generate"])
def test_j_task_owner_works(rpt, path):
    r = rpt.client.post(path, json={"task_id": "task-a"}, headers=AUTH_A)
    assert r.status_code == 200
    assert rpt.spy.async_results == ["task-a"]


@pytest.mark.parametrize("path", ["/report/preview", "/report/generate"])
def test_k_task_foreign_user_blocked(rpt, path):
    r = rpt.client.post(path, json={"task_id": "task-a"}, headers=AUTH_B)
    assert r.status_code == 404 and r.json() == NOT_FOUND


@pytest.mark.parametrize("path", ["/report/preview", "/report/generate"])
def test_l_task_anonymous_blocked(rpt, path):
    r = rpt.client.post(path, json={"task_id": "task-a"})
    assert r.status_code == 401


@pytest.mark.parametrize("path", ["/report/preview", "/report/generate"])
def test_m_missing_task_is_indistinguishable_from_foreign(rpt, path):
    missing = rpt.client.post(path, json={"task_id": "no-such-task"}, headers=AUTH_B)
    foreign = rpt.client.post(path, json={"task_id": "task-a"}, headers=AUTH_B)
    assert missing.status_code == foreign.status_code == 404
    assert missing.json() == foreign.json() == NOT_FOUND
    assert rpt.client.post(path, json={"task_id": "no-such-task"}).status_code == 401


def test_n_blocked_task_requests_touch_nothing(rpt):
    for headers in (AUTH_B, {}):
        for tid in ("task-a", "no-such-task"):
            for path in ("/report/generate", "/report/preview"):
                rpt.client.post(path, json={"task_id": tid}, headers=headers)
    assert rpt.spy.async_results == []            # Celery never queried
    assert rpt.spy.pdf == []                      # no report generated
    assert rpt.env.calls == []                    # no pipeline
    assert rpt.real not in rpt.spy.isfile         # no filesystem access
