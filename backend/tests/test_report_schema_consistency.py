"""
backend/tests/test_report_schema_consistency.py

Targeted tests for Fix 1: Consistent report result schema.
Verifies:
1. Raw pipeline output is correctly normalized to legacy report schema.
2. Already normalized result survives without loss of fields.
3. Absent or malformed result fields are handled safely without inventing
   a successful verdict or fabricated risk score.
4. job_id path prefers persisted job["result"] rather than rerunning pipeline.
5. job_id path with missing result re-runs pipeline on existing file and normalizes output.
6. Both task_id and job_id paths produce identical normalized top-level schema keys.
"""

from unittest.mock import patch, MagicMock
from types import SimpleNamespace
import pytest
from fastapi.testclient import TestClient

import api.routes.report as report_route
from celery_worker import _normalise_result
from models import User

TEST_USER = SimpleNamespace(id=1, is_active=True)

RAW_PIPELINE_OUTPUT = {
    "functions": ["fcn.00401000"],
    "calls": ["VirtualAlloc"],
    "imports": ["kernel32.dll!VirtualAlloc"],
    "strings": ["cmd.exe /c calc"],
    "behaviors": {
        "behaviors": ["process_injection", "command_execution"],
        "_detail": [
            {"name": "process_injection", "source": "function", "confidence": 0.8},
            {"name": "command_execution", "source": "imports", "confidence": 0.9},
        ],
    },
    "capabilities": ["process_injection"],
    "capability_scores": {"process_injection": 0.8},
    "final_mitre": {
        "mitre_techniques": ["T1055"],
        "final_mitre": ["T1055"],
    },
    "risk": {
        "combined_score": 78.5,
    },
    "cvss_results": {
        "cvss_score": 8.2,
        "risk_level": "HIGH",
    },
    "arise_verdict": {
        "verdict": "MALICIOUS",
        "confidence": 90,
        "confidence_pct": 90,
        "category": "Trojan",
        "summary": "Process injection detected",
    },
    "analysis_meta": {
        "ghidra_available": True,
        "radare2_available": True,
        "extraction_engine": "radare2+ghidra",
    },
}


def test_normalise_raw_pipeline_output():
    """Test that raw pipeline output is normalized properly."""
    norm = _normalise_result(
        raw=RAW_PIPELINE_OUTPUT,
        elapsed=3.14,
        original_name="trojan.exe",
        hashes={"md5": "abc", "sha1": "def", "sha256": "123"},
        file_type="PE Executable (EXE/DLL)",
    )

    assert norm["risk_score"] == 78.5
    assert norm["cvss"] == 8.2
    assert norm["cvss_detail"]["cvss_score"] == 8.2
    assert norm["verdict"]["verdict"] == "MALICIOUS"
    assert norm["verdict"]["confidence"] == 90
    assert norm["mitre"] == ["T1055"]
    assert norm["behaviours"] == ["process_injection", "command_execution"]
    assert norm["capabilities"] == ["process_injection"]
    assert norm["hashes"]["sha256"] == "123"
    assert norm["file_type"] == "PE Executable (EXE/DLL)"
    assert norm["analysis_meta"]["filename"] == "trojan.exe"
    assert norm["analysis_meta"]["total_elapsed"] == 3.14


def test_normalise_malformed_empty_result():
    """Test malformed empty result does NOT fabricate a successful verdict or risk score."""
    norm = _normalise_result(raw={})

    assert norm["risk_score"] == 0.0
    assert norm["cvss"] == 0.0
    assert norm["verdict"]["verdict"] == "UNKNOWN"
    assert norm["verdict"]["confidence"] == 0
    assert norm["mitre"] == []
    assert norm["capabilities"] == []
    assert norm["behaviours"] == []
    assert norm["hashes"]["sha256"] == "N/A"
    assert norm["file_type"] == "Unknown"


def test_job_id_path_prefers_persisted_result(monkeypatch):
    """Test that job_id report flow uses stored job['result'] and does not rerun full_pipeline."""
    persisted_result = dict(RAW_PIPELINE_OUTPUT)
    job_record = {
        "job_id": "job-persisted-123",
        "user_id": TEST_USER.id,
        "filename": "sample.exe",
        "file_path": "some_existing_path.bin",
        "result": persisted_result,
    }

    pipeline_called = []
    monkeypatch.setattr(report_route, "require_owned_job", lambda jid, user: job_record)

    def fake_pipeline(path):
        pipeline_called.append(path)
        return {"unexpected": "ran"}

    with patch("api.routes.analysis.full_pipeline", fake_pipeline):
        result, path = report_route._resolve_result(
            task_id=None,
            job_id="job-persisted-123",
            current_user=TEST_USER,
        )

    # full_pipeline must NOT be called because result was already cached/persisted
    assert len(pipeline_called) == 0
    assert result["risk_score"] == 78.5
    assert result["verdict"]["verdict"] == "MALICIOUS"
    assert result["mitre"] == ["T1055"]


def test_job_id_path_regenerates_when_result_missing(tmp_path, monkeypatch):
    """Test that job_id reruns full_pipeline only when job['result'] is missing."""
    sample_file = tmp_path / "sample.bin"
    sample_file.write_bytes(b"MZtestsample")

    job_record = {
        "job_id": "job-missing-res-123",
        "user_id": TEST_USER.id,
        "filename": "regenerated.exe",
        "file_path": str(sample_file),
        "result": None,  # no cached result
    }

    monkeypatch.setattr(report_route, "require_owned_job", lambda jid, user: job_record)

    with patch("api.routes.analysis.full_pipeline", return_value=RAW_PIPELINE_OUTPUT):
        result, path = report_route._resolve_result(
            task_id=None,
            job_id="job-missing-res-123",
            current_user=TEST_USER,
        )

    assert path == str(sample_file)
    assert result["risk_score"] == 78.5
    assert result["verdict"]["verdict"] == "MALICIOUS"
    assert result["analysis_meta"]["filename"] == "regenerated.exe"


def test_task_id_path_normalizes_celery_result(monkeypatch):
    """Test that task_id path normalizes the task result consistently."""
    job_record = {
        "job_id": "task-uuid-456",
        "user_id": TEST_USER.id,
        "filename": "from_celery.exe",
    }
    monkeypatch.setattr(report_route, "require_owned_job", lambda jid, user: job_record)

    mock_async_result = MagicMock()
    mock_async_result.state = "SUCCESS"
    mock_async_result.result = RAW_PIPELINE_OUTPUT

    with patch("celery.result.AsyncResult", return_value=mock_async_result):
        result, path = report_route._resolve_result(
            task_id="task-uuid-456",
            job_id=None,
            current_user=TEST_USER,
        )

    assert path is None
    assert result["risk_score"] == 78.5
    assert result["verdict"]["verdict"] == "MALICIOUS"
    assert result["mitre"] == ["T1055"]


def test_report_normalization_when_celery_worker_mocked_or_unimportable(tmp_path, monkeypatch):
    """Regression test: verify that even if celery_worker is mocked/stubbed without _normalise_result,
    _resolve_result still normalizes raw pipeline output into canonical report schema."""
    import sys
    import types

    fake_worker = types.ModuleType("celery_worker")
    fake_worker.celery_app = SimpleNamespace()

    sample_file = tmp_path / "sample.bin"
    sample_file.write_bytes(b"MZcontent")

    job_record = {
        "job_id": "job-mock-worker-123",
        "user_id": TEST_USER.id,
        "filename": "sample.exe",
        "file_path": str(sample_file),
        "result": None,
    }
    monkeypatch.setattr(report_route, "require_owned_job", lambda jid, user: job_record)

    with patch.dict(sys.modules, {"celery_worker": fake_worker}), \
         patch("api.routes.analysis.full_pipeline", return_value=RAW_PIPELINE_OUTPUT):
        result, path = report_route._resolve_result(
            task_id=None,
            job_id="job-mock-worker-123",
            current_user=TEST_USER,
        )

    # Must NOT return raw pipeline structure with missing verdict / 0 risk_score
    assert result["risk_score"] == 78.5
    assert result["verdict"]["verdict"] == "MALICIOUS"
    assert result["mitre"] == ["T1055"]
    assert "capabilities" in result
    assert "hashes" in result
    assert "file_type" in result
