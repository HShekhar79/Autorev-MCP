"""
test_job_pipeline_concurrency.py

Regression coverage for the per-job locking fix in
api/routes/analysis.py's _run_full_pipeline(), added for Task 7
(concurrent-analysis resource limits — same-job race).

Mocks _run_full_pipeline_locked (the actual expensive Radare2/Ghidra/CAPA
work) rather than exercising real engines — deterministic, no external
tool dependencies, uses threading.Event/Barrier instead of sleep() for
synchronization.
"""

import threading
import pytest

import api.routes.analysis as analysis_route


@pytest.fixture(autouse=True)
def _cleanup_test_job_state():
    yield
    for job_id in list(analysis_route._pipeline_cache.keys()):
        if job_id.startswith("job-"):
            analysis_route._pipeline_cache.pop(job_id, None)
    for job_id in list(analysis_route._job_locks.keys()):
        if job_id.startswith("job-"):
            analysis_route._job_locks.pop(job_id, None)


def test_same_job_pipeline_runs_once_under_concurrent_requests(monkeypatch):
    """A. Two near-simultaneous requests for the SAME job_id must invoke
    the underlying pipeline exactly once."""
    job_id = "job-same-1"
    call_count = {"n": 0}
    entered_event = threading.Event()
    proceed_event = threading.Event()

    def fake_inner(job_id_arg, path_arg):
        call_count["n"] += 1
        entered_event.set()
        assert proceed_event.wait(timeout=5), "proceed_event never set"
        result = {"job_id": job_id_arg, "value": "computed"}
        analysis_route._pipeline_cache[job_id_arg] = result
        return result

    monkeypatch.setattr(analysis_route, "_run_full_pipeline_locked", fake_inner)

    results = {}

    def call_a():
        results["a"] = analysis_route._run_full_pipeline(job_id, "fake_path_a")

    def call_b():
        assert entered_event.wait(timeout=5), "A never entered the pipeline"
        results["b"] = analysis_route._run_full_pipeline(job_id, "fake_path_b")

    t_a = threading.Thread(target=call_a)
    t_b = threading.Thread(target=call_b)
    t_a.start()
    t_b.start()
    # Give B time to block on the lock/cache-check before releasing A.
    entered_event.wait(timeout=5)
    proceed_event.set()
    t_a.join(timeout=5)
    t_b.join(timeout=5)

    assert call_count["n"] == 1, "pipeline must run exactly once for the same job_id"
    assert results["a"] == results["b"], "waiting request must receive the cached result"  # also covers C


def test_different_jobs_run_concurrently_not_serialized(monkeypatch):
    """B. Two DIFFERENT job_ids must not be serialized by the same lock."""
    barrier = threading.Barrier(2, timeout=5)

    def fake_inner(job_id_arg, path_arg):
        barrier.wait()  # both threads must arrive here close together
        result = {"job_id": job_id_arg}
        analysis_route._pipeline_cache[job_id_arg] = result
        return result

    monkeypatch.setattr(analysis_route, "_run_full_pipeline_locked", fake_inner)

    results = {}
    errors = []

    def call_x():
        try:
            results["x"] = analysis_route._run_full_pipeline("job-diff-x", "path_x")
        except Exception as exc:
            errors.append(exc)

    def call_y():
        try:
            results["y"] = analysis_route._run_full_pipeline("job-diff-y", "path_y")
        except Exception as exc:
            errors.append(exc)

    t_x = threading.Thread(target=call_x)
    t_y = threading.Thread(target=call_y)
    t_x.start()
    t_y.start()
    t_x.join(timeout=5)
    t_y.join(timeout=5)

    assert not errors, f"unexpected errors (likely a BrokenBarrierError from serialization): {errors}"
    assert results.get("x") == {"job_id": "job-diff-x"}
    assert results.get("y") == {"job_id": "job-diff-y"}


def test_lock_released_after_pipeline_exception(monkeypatch):
    """D. The per-job lock must be released even if the pipeline raises,
    so a subsequent request for the same job_id does not deadlock."""
    job_id = "job-exc-1"

    def fake_inner_raises(job_id_arg, path_arg):
        raise RuntimeError("simulated pipeline failure")

    monkeypatch.setattr(analysis_route, "_run_full_pipeline_locked", fake_inner_raises)

    with pytest.raises(RuntimeError):
        analysis_route._run_full_pipeline(job_id, "path")

    lock = analysis_route._get_job_lock(job_id)
    assert not lock.locked(), "lock must be released after an exception"

    # A subsequent, successful call for the same job_id must not hang.
    def fake_inner_ok(job_id_arg, path_arg):
        result = {"ok": True}
        analysis_route._pipeline_cache[job_id_arg] = result
        return result

    monkeypatch.setattr(analysis_route, "_run_full_pipeline_locked", fake_inner_ok)
    result = analysis_route._run_full_pipeline(job_id, "path")
    assert result == {"ok": True}


def test_executor_max_workers_unchanged():
    """E. Existing ThreadPoolExecutor sizing must remain untouched by
    this change."""
    assert analysis_route._executor._max_workers == 4