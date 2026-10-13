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

import logging
from unittest.mock import patch, MagicMock
from types import SimpleNamespace
import pytest
from fastapi.testclient import TestClient

import api.routes.report as report_route
from celery_worker import _normalise_result
from utils.normalization import _coerce_cvss_score
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


def test_double_normalization_preserves_cvss_detail():
    """Regression test for C1: repeated normalization is stable and preserves cvss_detail."""
    raw = {
        "cvss_results": {
            "cvss_score": 9.8,
            "risk_level": "CRITICAL",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "technique_count": 5,
            "metrics": {
                "exploitability": 3.9,
                "impact": 5.9,
            },
            "tactics": ["execution", "defense-evasion"],
        },
        "mitre_techniques": ["T1055"],
    }
    norm1 = _normalise_result(raw)
    assert norm1["cvss"] == 9.8
    assert isinstance(norm1["cvss"], float)
    assert norm1["cvss_detail"]["cvss_score"] == 9.8
    assert norm1["cvss_detail"]["risk_level"] == "CRITICAL"
    assert norm1["cvss_detail"]["vector_string"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert norm1["cvss_detail"]["technique_count"] == 5
    assert norm1["cvss_detail"]["metrics"] == {"exploitability": 3.9, "impact": 5.9}
    assert norm1["cvss_detail"]["tactics"] == ["execution", "defense-evasion"]

    # Second normalization pass must NOT overwrite cvss_detail or lose vector_string/CRITICAL/extra fields
    norm2 = _normalise_result(norm1)
    assert norm2["cvss"] == 9.8
    assert isinstance(norm2["cvss"], float)
    assert norm2["cvss_detail"]["cvss_score"] == 9.8
    assert norm2["cvss_detail"]["risk_level"] == "CRITICAL"
    assert norm2["cvss_detail"]["vector_string"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert norm2["cvss_detail"]["technique_count"] == 5
    assert norm2["cvss_detail"]["metrics"] == {"exploitability": 3.9, "impact": 5.9}
    assert norm2["cvss_detail"]["tactics"] == ["execution", "defense-evasion"]

    # Third normalization pass to verify long-term idempotence/stability
    norm3 = _normalise_result(norm2)
    assert norm3["cvss_detail"] == norm2["cvss_detail"]

    # Deep-copy mutation isolation: mutating output cvss_detail must NOT mutate raw input
    norm1["cvss_detail"]["metrics"]["exploitability"] = 999.0
    norm1["cvss_detail"]["tactics"].append("new-tactic")
    assert raw["cvss_results"]["metrics"]["exploitability"] == 3.9
    assert raw["cvss_results"]["tactics"] == ["execution", "defense-evasion"]
    assert norm2["cvss_detail"]["metrics"]["exploitability"] == 3.9
    assert norm2["cvss_detail"]["tactics"] == ["execution", "defense-evasion"]


def test_normalization_preserves_historical_risk_level_mismatch():
    """Verify that inconsistent historical risk_level is preserved without silent rewrite."""
    raw = {
        "cvss_detail": {
            "cvss_score": 9.8,
            "risk_level": "HIGH",  # Mismatch with standard CRITICAL threshold
            "custom_metadata": "audit-v1",
        },
    }
    norm = _normalise_result(raw)
    assert norm["cvss"] == 9.8
    # Must preserve existing risk_level instead of silently rewriting to CRITICAL
    assert norm["cvss_detail"]["risk_level"] == "HIGH"
    assert norm["cvss_detail"]["custom_metadata"] == "audit-v1"


def test_resolve_result_with_already_normalized_task_result(monkeypatch):
    """Verify _resolve_result preserves rich CVSS detail when Celery task result is already normalized."""
    job_record = {
        "job_id": "task-norm-789",
        "user_id": TEST_USER.id,
        "filename": "normalized_task.exe",
    }
    monkeypatch.setattr(report_route, "require_owned_job", lambda jid, user: job_record)

    already_normalized_task_result = _normalise_result({
        "cvss_results": {
            "cvss_score": 9.8,
            "risk_level": "CRITICAL",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "metrics": {"base_score": 9.8, "exploitability": 3.9},
        },
        "mitre_techniques": ["T1055"],
    })

    mock_ar = MagicMock()
    mock_ar.state = "SUCCESS"
    mock_ar.result = already_normalized_task_result

    with patch("celery.result.AsyncResult", return_value=mock_ar):
        resolved, path = report_route._resolve_result(
            task_id="task-norm-789",
            job_id=None,
            current_user=TEST_USER,
        )

    assert path is None
    assert resolved["cvss"] == 9.8
    assert resolved["cvss_detail"]["cvss_score"] == 9.8
    assert resolved["cvss_detail"]["risk_level"] == "CRITICAL"
    assert resolved["cvss_detail"]["vector_string"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert resolved["cvss_detail"]["metrics"] == {"base_score": 9.8, "exploitability": 3.9}

    # Verify deep-copy mutation isolation between resolved report and source task result
    resolved["cvss_detail"]["metrics"]["base_score"] = 0.0
    assert already_normalized_task_result["cvss_detail"]["metrics"]["base_score"] == 9.8


def test_resolve_result_with_already_normalized_job_result(monkeypatch):
    """Verify _resolve_result preserves rich CVSS detail when persisted job['result'] is already normalized."""
    already_normalized = _normalise_result({
        "cvss_results": {
            "cvss_score": 9.8,
            "risk_level": "CRITICAL",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "metrics": {"base_score": 9.8},
        },
        "mitre_techniques": ["T1055"],
    })

    job_record = {
        "job_id": "job-norm-999",
        "user_id": TEST_USER.id,
        "filename": "persisted_norm.exe",
        "file_path": "persisted_norm.bin",
        "result": already_normalized,
    }
    monkeypatch.setattr(report_route, "require_owned_job", lambda jid, user: job_record)

    pipeline_called = []
    def fake_pipeline(path):
        pipeline_called.append(path)
        return {}

    with patch("api.routes.analysis.full_pipeline", fake_pipeline):
        resolved, path = report_route._resolve_result(
            task_id=None,
            job_id="job-norm-999",
            current_user=TEST_USER,
        )

    assert len(pipeline_called) == 0
    assert resolved["cvss"] == 9.8
    assert resolved["cvss_detail"]["cvss_score"] == 9.8
    assert resolved["cvss_detail"]["risk_level"] == "CRITICAL"
    assert resolved["cvss_detail"]["vector_string"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert resolved["cvss_detail"]["metrics"] == {"base_score": 9.8}

    # Verify mutation isolation
    resolved["cvss_detail"]["metrics"]["base_score"] = -1.0
    assert already_normalized["cvss_detail"]["metrics"]["base_score"] == 9.8


def test_double_normalization_zero_cvss_remains_none():
    """Regression test for C1: zero CVSS score must remain risk_level NONE on repeated normalization."""
    raw = {
        "cvss_results": {
            "cvss_score": 0.0,
            "risk_level": "NONE",
        },
    }
    norm1 = _normalise_result(raw)
    assert norm1["cvss"] == 0.0
    assert norm1["cvss_detail"]["cvss_score"] == 0.0
    assert norm1["cvss_detail"]["risk_level"] == "NONE"

    norm2 = _normalise_result(norm1)
    assert norm2["cvss"] == 0.0
    assert norm2["cvss_detail"]["cvss_score"] == 0.0
    assert norm2["cvss_detail"]["risk_level"] == "NONE"


def test_raw_scalar_cvss_receives_correct_risk_level():
    """Verify that raw scalar CVSS values get classified with appropriate risk levels."""
    norm_crit = _normalise_result({"cvss": 9.5})
    assert norm_crit["cvss"] == 9.5
    assert norm_crit["cvss_detail"]["risk_level"] == "CRITICAL"

    norm_high = _normalise_result({"cvss": 7.5})
    assert norm_high["cvss"] == 7.5
    assert norm_high["cvss_detail"]["risk_level"] == "HIGH"

    norm_med = _normalise_result({"cvss": 5.0})
    assert norm_med["cvss"] == 5.0
    assert norm_med["cvss_detail"]["risk_level"] == "MEDIUM"

    norm_low = _normalise_result({"cvss": 2.0})
    assert norm_low["cvss"] == 2.0
    assert norm_low["cvss_detail"]["risk_level"] == "LOW"

    norm_zero = _normalise_result({"cvss": 0.0})
    assert norm_zero["cvss"] == 0.0
    assert norm_zero["cvss_detail"]["risk_level"] == "NONE"


def test_numeric_scalar_strings_parse_consistently():
    """Verify that numeric scalar strings parse consistently with numeric float scores."""
    norm_str_high = _normalise_result({"cvss": "7.5"})
    assert norm_str_high["cvss"] == 7.5
    assert isinstance(norm_str_high["cvss"], float)
    assert norm_str_high["cvss_detail"]["cvss_score"] == 7.5
    assert norm_str_high["cvss_detail"]["risk_level"] == "HIGH"

    norm_str_crit = _normalise_result({"cvss": "  9.8 "})
    assert norm_str_crit["cvss"] == 9.8
    assert norm_str_crit["cvss_detail"]["risk_level"] == "CRITICAL"

    norm_str_score = _normalise_result({"cvss_score": "4.2"})
    assert norm_str_score["cvss"] == 4.2
    assert norm_str_score["cvss_detail"]["risk_level"] == "MEDIUM"

    norm_str_zero = _normalise_result({"cvss": "0.0"})
    assert norm_str_zero["cvss"] == 0.0
    assert norm_str_zero["cvss_detail"]["risk_level"] == "NONE"

    norm_detail_str = _normalise_result({"cvss_detail": {"cvss_score": "8.5"}})
    assert norm_detail_str["cvss"] == 8.5
    assert norm_detail_str["cvss_detail"]["cvss_score"] == 8.5
    assert norm_detail_str["cvss_detail"]["risk_level"] == "HIGH"


def test_booleans_rejected_as_cvss_scores():
    """Verify that boolean values are rejected as CVSS scores rather than treated as 1.0 or 0.0."""
    norm_true = _normalise_result({"cvss": True})
    assert norm_true["cvss"] == 0.0
    assert norm_true["cvss_detail"]["cvss_score"] == 0.0
    assert norm_true["cvss_detail"]["risk_level"] == "NONE"

    norm_false = _normalise_result({"cvss": False})
    assert norm_false["cvss"] == 0.0
    assert norm_false["cvss_detail"]["cvss_score"] == 0.0
    assert norm_false["cvss_detail"]["risk_level"] == "NONE"

    norm_score_bool = _normalise_result({"cvss_score": True})
    assert norm_score_bool["cvss"] == 0.0
    assert norm_score_bool["cvss_detail"]["risk_level"] == "NONE"

    norm_detail_bool = _normalise_result({
        "cvss_detail": {
            "cvss_score": True,
            "vector_string": "CVSS:3.1/AV:N",
        }
    })
    assert norm_detail_bool["cvss"] == 0.0
    assert norm_detail_bool["cvss_detail"]["cvss_score"] == 0.0
    assert norm_detail_bool["cvss_detail"]["risk_level"] == "NONE"
    assert norm_detail_bool["cvss_detail"]["vector_string"] == "CVSS:3.1/AV:N"


def test_non_finite_scores_rejected():
    """Verify that NaN and Infinity are rejected and never enter normalized output."""
    for bad_val in [float("nan"), float("inf"), float("-inf"), "nan", "inf", "-inf"]:
        norm = _normalise_result({"cvss": bad_val})
        assert norm["cvss"] == 0.0
        assert norm["cvss_detail"]["cvss_score"] == 0.0
        assert norm["cvss_detail"]["risk_level"] == "NONE"

    norm_detail_nan = _normalise_result({"cvss_detail": {"cvss_score": float("nan")}})
    assert norm_detail_nan["cvss"] == 0.0
    assert norm_detail_nan["cvss_detail"]["cvss_score"] == 0.0
    assert norm_detail_nan["cvss_detail"]["risk_level"] == "NONE"


def test_out_of_range_scores_safe_handling():
    """Verify safe handling of negative scores and scores above 10 without fabricating trust."""
    for out_of_range in [-2.0, 15.0, "-5.0", "100.0"]:
        norm = _normalise_result({"cvss": out_of_range})
        assert norm["cvss"] == 0.0
        assert norm["cvss_detail"]["cvss_score"] == 0.0
        assert norm["cvss_detail"]["risk_level"] == "NONE"

    # Detail dict with out-of-range score preserves valid metadata but sanitizes score
    norm_detail_bad = _normalise_result({
        "cvss_detail": {
            "cvss_score": 15.0,
            "vector_string": "CVSS:3.1/AV:N",
            "technique_count": 3,
        }
    })
    assert norm_detail_bad["cvss"] == 0.0
    assert norm_detail_bad["cvss_detail"]["cvss_score"] == 0.0
    assert norm_detail_bad["cvss_detail"]["risk_level"] == "NONE"
    assert norm_detail_bad["cvss_detail"]["vector_string"] == "CVSS:3.1/AV:N"
    assert norm_detail_bad["cvss_detail"]["technique_count"] == 3


def test_invalid_cvss_score_resets_stale_risk_level_to_none(caplog):
    """Regression test for C2: invalid CVSS scores paired with stale risk labels must reset to NONE and warn."""
    caplog.set_level(logging.WARNING, logger="arise.normalization")

    # Example 1 from Claude review: out-of-range numeric score with CRITICAL
    caplog.clear()
    norm_crit = _normalise_result({
        "cvss_detail": {
            "cvss_score": 15.0,
            "risk_level": "CRITICAL",
        }
    })
    assert norm_crit["cvss"] == 0.0
    assert norm_crit["cvss_detail"]["cvss_score"] == 0.0
    assert norm_crit["cvss_detail"]["risk_level"] == "NONE"
    assert "normalise_result: invalid or out-of-range cvss score 15.0; falling back to 0.0 NONE" in caplog.text
    assert "preserved cvss risk_level" not in caplog.text

    # Example 2 from Claude review: NaN score with HIGH
    caplog.clear()
    norm_nan = _normalise_result({
        "cvss_results": {
            "cvss_score": float("nan"),
            "risk_level": "HIGH",
        }
    })
    assert norm_nan["cvss"] == 0.0
    assert norm_nan["cvss_detail"]["cvss_score"] == 0.0
    assert norm_nan["cvss_detail"]["risk_level"] == "NONE"
    assert "normalise_result: invalid or out-of-range cvss score nan; falling back to 0.0 NONE" in caplog.text
    assert "preserved cvss risk_level" not in caplog.text

    # Example 3 from Claude review: null (None) score with HIGH
    caplog.clear()
    norm_null = _normalise_result({
        "cvss_detail": {
            "cvss_score": None,
            "risk_level": "HIGH",
        }
    })
    assert norm_null["cvss"] == 0.0
    assert norm_null["cvss_detail"]["cvss_score"] == 0.0
    assert norm_null["cvss_detail"]["risk_level"] == "NONE"
    assert "normalise_result: invalid or out-of-range cvss score None; falling back to 0.0 NONE" in caplog.text
    assert "preserved cvss risk_level" not in caplog.text


def test_all_invalid_cvss_variants_with_stale_risk_labels_reset_to_none(caplog):
    """Exhaustive regression test for C2: verify out-of-range, NaN, Inf, booleans, and strings reset to NONE."""
    caplog.set_level(logging.WARNING, logger="arise.normalization")

    test_cases = [
        # (invalid_score, stale_risk, expected_logged_repr)
        (None, "HIGH", "None"),
        (float("nan"), "CRITICAL", "nan"),
        (float("inf"), "CRITICAL", "inf"),
        (float("-inf"), "HIGH", "-inf"),
        (15.0, "CRITICAL", "15.0"),
        (-2.5, "MEDIUM", "-2.5"),
        (100.0, "CRITICAL", "100.0"),
        (True, "HIGH", "True"),
        (False, "LOW", "False"),
        ("nan", "HIGH", "'nan'"),
        ("inf", "CRITICAL", "'inf'"),
        ("-inf", "HIGH", "'-inf'"),
        ("15.0", "CRITICAL", "'15.0'"),
        ("-5.0", "MEDIUM", "'-5.0'"),
        ("not_a_number", "HIGH", "'not_a_number'"),
    ]

    for bad_score, stale_risk, repr_str in test_cases:
        caplog.clear()
        raw = {
            "cvss_detail": {
                "cvss_score": bad_score,
                "risk_level": stale_risk,
                "vector_string": "CVSS:3.1/AV:N",
            }
        }
        norm = _normalise_result(raw)
        assert norm["cvss"] == 0.0
        assert norm["cvss_detail"]["cvss_score"] == 0.0
        assert norm["cvss_detail"]["risk_level"] == "NONE"
        assert norm["cvss_detail"]["vector_string"] == "CVSS:3.1/AV:N"
        assert f"normalise_result: invalid or out-of-range cvss score {repr_str}; falling back to 0.0 NONE" in caplog.text
        assert "preserved cvss risk_level" not in caplog.text


def test_invalid_cvss_score_preserves_nested_metadata_and_vector(caplog):
    """Verify that invalid CVSS score resets risk_level to NONE while preserving nested metadata and isolation."""
    caplog.set_level(logging.WARNING, logger="arise.normalization")
    caplog.clear()

    raw = {
        "cvss_detail": {
            "cvss_score": 15.0,
            "risk_level": "CRITICAL",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "technique_count": 5,
            "metrics": {
                "exploitability": 3.9,
                "impact": 5.9,
            },
            "tactics": ["execution", "defense-evasion"],
        }
    }
    norm = _normalise_result(raw)
    assert norm["cvss"] == 0.0
    assert norm["cvss_detail"]["cvss_score"] == 0.0
    assert norm["cvss_detail"]["risk_level"] == "NONE"
    assert norm["cvss_detail"]["vector_string"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert norm["cvss_detail"]["technique_count"] == 5
    assert norm["cvss_detail"]["metrics"] == {"exploitability": 3.9, "impact": 5.9}
    assert norm["cvss_detail"]["tactics"] == ["execution", "defense-evasion"]
    assert "normalise_result: invalid or out-of-range cvss score 15.0; falling back to 0.0 NONE" in caplog.text
    assert "preserved cvss risk_level" not in caplog.text

    # Deep-copy mutation isolation: mutating output cvss_detail does not affect input raw
    norm["cvss_detail"]["metrics"]["exploitability"] = 999.0
    norm["cvss_detail"]["tactics"].append("persistence")
    assert raw["cvss_detail"]["metrics"]["exploitability"] == 3.9
    assert raw["cvss_detail"]["tactics"] == ["execution", "defense-evasion"]


def test_missing_cvss_score_key_with_stale_risk_label_resets_to_none(caplog):
    """Verify that dict with missing cvss_score key but stale risk_level resets to NONE and warns."""
    caplog.set_level(logging.WARNING, logger="arise.normalization")
    caplog.clear()

    raw = {
        "cvss_detail": {
            "risk_level": "CRITICAL",
            "vector_string": "CVSS:3.1/AV:N",
        }
    }
    norm = _normalise_result(raw)
    assert norm["cvss"] == 0.0
    assert norm["cvss_detail"]["cvss_score"] == 0.0
    assert norm["cvss_detail"]["risk_level"] == "NONE"
    assert norm["cvss_detail"]["vector_string"] == "CVSS:3.1/AV:N"
    assert "normalise_result: invalid or out-of-range cvss score None; falling back to 0.0 NONE" in caplog.text
    assert "preserved cvss risk_level" not in caplog.text


def test_cvss_overflow_large_integer_handling(caplog):
    """Regression test for Fix 1: integers too large to convert to float (e.g. 10**400) fail safely."""
    caplog.set_level(logging.WARNING, logger="arise.normalization")

    # 1. Direct unit test of _coerce_cvss_score contract with overflow integers
    assert _coerce_cvss_score(10**400) is None
    assert _coerce_cvss_score(-10**400) is None

    # 2. Nested-detail path with large integer, stale risk labels, and existing cvss_risk_level
    caplog.clear()
    raw_nested = {
        "cvss_detail": {
            "cvss_score": 10**400,
            "risk_level": "CRITICAL",
            "cvss_risk_level": "CRITICAL",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "technique_count": 4,
            "tactics": ["execution"],
        }
    }
    norm_nested = _normalise_result(raw_nested)
    assert norm_nested["cvss"] == 0.0
    assert norm_nested["cvss_detail"]["cvss_score"] == 0.0
    assert norm_nested["cvss_detail"]["risk_level"] == "NONE"
    assert norm_nested["cvss_detail"]["cvss_risk_level"] == "NONE"
    assert norm_nested["cvss_detail"]["vector_string"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert norm_nested["cvss_detail"]["technique_count"] == 4
    assert norm_nested["cvss_detail"]["tactics"] == ["execution"]
    assert f"normalise_result: invalid or out-of-range cvss score {10**400!r}; falling back to 0.0 NONE" in caplog.text
    assert "preserved cvss risk_level" not in caplog.text

    # 3. Nested-detail path where cvss_risk_level is absent -> ensure it is not created
    caplog.clear()
    raw_no_crl = {
        "cvss_detail": {
            "cvss_score": 10**400,
            "risk_level": "HIGH",
            "vector_string": "CVSS:3.1/AV:N",
        }
    }
    norm_no_crl = _normalise_result(raw_no_crl)
    assert norm_no_crl["cvss"] == 0.0
    assert norm_no_crl["cvss_detail"]["cvss_score"] == 0.0
    assert norm_no_crl["cvss_detail"]["risk_level"] == "NONE"
    assert "cvss_risk_level" not in norm_no_crl["cvss_detail"]
    assert norm_no_crl["cvss_detail"]["vector_string"] == "CVSS:3.1/AV:N"
    assert f"normalise_result: invalid or out-of-range cvss score {10**400!r}; falling back to 0.0 NONE" in caplog.text

    # 4. Scalar-score path with cvss=10**400
    caplog.clear()
    raw_scalar_cvss = {"cvss": 10**400}
    norm_scalar_cvss = _normalise_result(raw_scalar_cvss)
    assert norm_scalar_cvss["cvss"] == 0.0
    assert norm_scalar_cvss["cvss_detail"]["cvss_score"] == 0.0
    assert norm_scalar_cvss["cvss_detail"]["risk_level"] == "NONE"
    assert "cvss_risk_level" not in norm_scalar_cvss["cvss_detail"]
    assert f"normalise_result: invalid or out-of-range cvss score {10**400!r}; falling back to 0.0 NONE" in caplog.text

    # 5. Scalar-score path with cvss_score=10**400
    caplog.clear()
    raw_scalar_score = {"cvss_score": 10**400}
    norm_scalar_score = _normalise_result(raw_scalar_score)
    assert norm_scalar_score["cvss"] == 0.0
    assert norm_scalar_score["cvss_detail"]["cvss_score"] == 0.0
    assert norm_scalar_score["cvss_detail"]["risk_level"] == "NONE"
    assert "cvss_risk_level" not in norm_scalar_score["cvss_detail"]
    assert f"normalise_result: invalid or out-of-range cvss score {10**400!r}; falling back to 0.0 NONE" in caplog.text

    # 6. Negative large integer path
    caplog.clear()
    raw_neg = {"cvss": -10**400}
    norm_neg = _normalise_result(raw_neg)
    assert norm_neg["cvss"] == 0.0
    assert norm_neg["cvss_detail"]["cvss_score"] == 0.0
    assert norm_neg["cvss_detail"]["risk_level"] == "NONE"
    assert "cvss_risk_level" not in norm_neg["cvss_detail"]


def test_invalid_cvss_score_cvss_risk_level_reset_and_absence(caplog):
    """
    Regression test for Fix 2: cvss_risk_level handling for invalid scores:
    - Existing cvss_detail['cvss_risk_level'] becomes 'NONE'.
    - Absent cvss_risk_level is NOT created.
    - Existing cvss_detail['risk_level'] reset to 'NONE' continues to work.
    """
    caplog.set_level(logging.WARNING, logger="arise.normalization")

    invalid_scores = [
        15.0,              # Out of range float
        -2.5,              # Negative float
        float("nan"),      # NaN
        float("inf"),      # Inf
        None,              # None
        True,              # Boolean
        "not_a_number",    # Non-numeric string
        "15.0",            # Out of range string
        10**400,           # Overflow integer
    ]

    for bad_score in invalid_scores:
        # Case A: cvss_risk_level already exists in cvss_detail -> reset to NONE
        caplog.clear()
        raw_with_crl = {
            "cvss_detail": {
                "cvss_score": bad_score,
                "risk_level": "CRITICAL",
                "cvss_risk_level": "HIGH",
            }
        }
        norm_with_crl = _normalise_result(raw_with_crl)
        assert norm_with_crl["cvss"] == 0.0
        assert norm_with_crl["cvss_detail"]["cvss_score"] == 0.0
        assert norm_with_crl["cvss_detail"]["risk_level"] == "NONE"
        assert norm_with_crl["cvss_detail"]["cvss_risk_level"] == "NONE"
        assert "preserved cvss risk_level" not in caplog.text

        # Case B: cvss_risk_level is absent in cvss_detail -> must NOT be created
        caplog.clear()
        raw_without_crl = {
            "cvss_detail": {
                "cvss_score": bad_score,
                "risk_level": "CRITICAL",
            }
        }
        norm_without_crl = _normalise_result(raw_without_crl)
        assert norm_without_crl["cvss"] == 0.0
        assert norm_without_crl["cvss_detail"]["cvss_score"] == 0.0
        assert norm_without_crl["cvss_detail"]["risk_level"] == "NONE"
        assert "cvss_risk_level" not in norm_without_crl["cvss_detail"]
        assert "preserved cvss risk_level" not in caplog.text


def test_cvss_fallback_and_precedence_cases(caplog):
    """
    Regression test for Fix 3: fallback and precedence coverage.

    Tests:
    1. cvss=True, cvss_score=9.8 -> score 9.8 (boolean flag falls back to numeric cvss_score).
    2. cvss=True alone -> score 0.0 and an appropriate warning.
    3. cvss=15.0, cvss_score=9.8 -> score 0.0.
       Precedence behavior: Top-level scalar 'cvss' takes precedence over 'cvss_score'.
       When 'cvss' is a non-boolean scalar (e.g. 15.0), it is authoritative. Because 15.0
       is invalid/out-of-range, normalization rejects it to 0.0 / NONE rather than falling
       back to secondary fields like 'cvss_score'.
    4. cvss_detail.cvss_score=None, with top-level cvss=9.8 -> score 9.8.
    5. cvss_detail.cvss_score=15.0, with top-level cvss=9.8 -> score 0.0 and risk level 'NONE'.
       Precedence behavior: An explicit cvss_detail dictionary is authoritative over top-level
       scalars. Since cvss_detail has cvss_score=15.0, the invalid score is rejected to 0.0 / NONE
       rather than falling back to top-level cvss=9.8.
    """
    caplog.set_level(logging.WARNING, logger="arise.normalization")

    # 1. cvss=True, cvss_score=9.8 -> score 9.8
    caplog.clear()
    norm_case1 = _normalise_result({"cvss": True, "cvss_score": 9.8})
    assert norm_case1["cvss"] == 9.8
    assert norm_case1["cvss_detail"]["cvss_score"] == 9.8
    assert norm_case1["cvss_detail"]["risk_level"] == "CRITICAL"

    # 2. cvss=True alone -> score 0.0 and an appropriate warning
    caplog.clear()
    norm_case2 = _normalise_result({"cvss": True})
    assert norm_case2["cvss"] == 0.0
    assert norm_case2["cvss_detail"]["cvss_score"] == 0.0
    assert norm_case2["cvss_detail"]["risk_level"] == "NONE"
    assert "normalise_result: invalid or out-of-range cvss score True; falling back to 0.0 NONE" in caplog.text

    # 3. cvss=15.0, cvss_score=9.8 -> score 0.0 and NONE
    caplog.clear()
    norm_case3 = _normalise_result({"cvss": 15.0, "cvss_score": 9.8})
    assert norm_case3["cvss"] == 0.0
    assert norm_case3["cvss_detail"]["cvss_score"] == 0.0
    assert norm_case3["cvss_detail"]["risk_level"] == "NONE"
    assert "normalise_result: invalid or out-of-range cvss score 15.0; falling back to 0.0 NONE" in caplog.text

    # 4. cvss_detail.cvss_score=None, with top-level cvss=9.8 -> score 9.8
    caplog.clear()
    norm_case4 = _normalise_result({
        "cvss_detail": {
            "cvss_score": None,
            "vector_string": "CVSS:3.1/AV:N",
        },
        "cvss": 9.8,
    })
    assert norm_case4["cvss"] == 9.8
    assert norm_case4["cvss_detail"]["cvss_score"] == 9.8
    assert norm_case4["cvss_detail"]["risk_level"] == "CRITICAL"
    assert norm_case4["cvss_detail"]["vector_string"] == "CVSS:3.1/AV:N"

    # 5. cvss_detail.cvss_score=15.0, with top-level cvss=9.8 -> score 0.0 and risk level 'NONE'
    caplog.clear()
    norm_case5 = _normalise_result({
        "cvss_detail": {
            "cvss_score": 15.0,
            "vector_string": "CVSS:3.1/AV:N",
        },
        "cvss": 9.8,
    })
    assert norm_case5["cvss"] == 0.0
    assert norm_case5["cvss_detail"]["cvss_score"] == 0.0
    assert norm_case5["cvss_detail"]["risk_level"] == "NONE"
    assert norm_case5["cvss_detail"]["vector_string"] == "CVSS:3.1/AV:N"
    assert "normalise_result: invalid or out-of-range cvss score 15.0; falling back to 0.0 NONE" in caplog.text
