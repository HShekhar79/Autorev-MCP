"""
api/routes/analysis.py

Full analysis pipeline router.

FIXES (original):
1. normalize_behaviour() was called but never imported — was imported as
   normalize_behavior from utils.normalization. Renamed call sites to match.
2. full_pipeline() ran the ENTIRE pipeline on every endpoint call, which means
   /behaviours, /mitre, /cvss etc. each re-ran r2 analysis from scratch.
   Fixed with a simple in-memory job result cache (keyed by file path).
3. /ranking and /risk endpoints were missing — added.
4. report endpoint was passing ranked_functions=[] (hardcoded empty list) —
   now passes the actual ranked output.
5. feature_engine.extract_features() signature mismatch fixed (was 4-arg,
   called with 1 arg in pipeline). Wrapper added to pass correct args.
6. collect_all_behaviours() referenced normalize_behaviour (British) — fixed
   to normalize_behavior (American) matching the import.

GHIDRA INTEGRATION (new):
7. Extraction layer replaced by engines.unified_extractor.unified_extractor
   which runs Radare2 + Ghidra in sequence and merges results transparently.
   All downstream code is unchanged — same data contracts.
8. analysis_meta now includes ghidra_available flag from unified extractor.
9. Fallback: if Ghidra fails / is not installed, radare2-only mode proceeds
   automatically.  No exception propagates to the caller.
"""

import os
from functools import lru_cache

from fastapi import APIRouter, Depends, HTTPException
from core.job_manager import get_job

from auth.dependencies import get_current_user, require_user_ownership
from models import User

from engines.report_engine.report_engine import generate_final_report

# ── Shared authoritative pipeline (framework-neutral service) ────────────────
#   The pipeline implementation lives in services/analysis_pipeline.py.
#   This module is only the HTTP adapter + path resolver.
from services.analysis_pipeline import (
    run_analysis_pipeline,
    collect_all_behaviours,          # re-exported for existing importers
    _pipeline_cache,                 # same dict object as the service cache
    _invalidate_cache,
)

router = APIRouter()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "storage", "uploads"))

# ---------------------------------------------------------------------------
# PATH RESOLVER
# ---------------------------------------------------------------------------
def resolve_path(job_id: str):
    job = get_job(job_id)
    if not job:
        return None, None
    # Task 8/integration fix: job["file_path"] is the authoritative stored
    # sample path (UUID-based, written by upload.py). Previously this
    # rebuilt a path from job["filename"] (the client-supplied DISPLAY
    # name) joined with UPLOAD_DIR, which no longer matches the actual
    # <job_id>.bin storage convention at all.
    file_path = job.get("file_path")
    if not file_path:
        return job, os.path.join(UPLOAD_DIR, job["filename"])
    return job, file_path


# ---------------------------------------------------------------------------
# OWNERSHIP-ENFORCED RESOLVER
#
# Every job-specific endpoint goes through this. A missing job and a job
# owned by someone else produce the SAME 404 response, so job_ids cannot be
# probed for existence (no IDOR / enumeration oracle).
# ---------------------------------------------------------------------------
def _resolve_owned_path(job_id: str, current_user: User):
    job, path = resolve_path(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Resource not found.")
    require_user_ownership(job.get("user_id"), current_user)
    return job, path


# ---------------------------------------------------------------------------
# FULL PIPELINE  (adapter → shared authoritative pipeline, cached per path)
# ---------------------------------------------------------------------------
def full_pipeline(path: str) -> dict:
    return run_analysis_pipeline(path)


# ===========================================================================
# API ENDPOINTS
# ===========================================================================

@router.get("/analysis/{job_id}")
def get_analysis(job_id: str, current_user: User = Depends(get_current_user)):
    job, path = _resolve_owned_path(job_id, current_user)
    return full_pipeline(path)


@router.get("/behaviours/{job_id}")
def get_behaviours(job_id: str, current_user: User = Depends(get_current_user)):
    job, path = _resolve_owned_path(job_id, current_user)
    result = full_pipeline(path)
    # FIX: was returning {"behaviors": result.get("behaviors", ...)} which
    # wrapped the already-structured dict in a redundant key
    return result.get("behaviors", {"behaviors": [], "_detail": []})


@router.get("/mitre/{job_id}")
def get_mitre(job_id: str, current_user: User = Depends(get_current_user)):
    job, path = _resolve_owned_path(job_id, current_user)
    result = full_pipeline(path)
    return {
        "mitre_results": result.get("mitre_results", {}),
        "capability_mitre_results": result.get("capability_mitre_results", {}),
        "final_mitre": result.get("final_mitre", {}),
    }


@router.get("/capabilities/{job_id}")
def get_capabilities(job_id: str, current_user: User = Depends(get_current_user)):
    job, path = _resolve_owned_path(job_id, current_user)
    result = full_pipeline(path)
    return {
        "capabilities": result.get("capabilities", []),
        "scores": result.get("capability_scores", {}),
    }


@router.get("/cvss/{job_id}")
def get_cvss(job_id: str, current_user: User = Depends(get_current_user)):
    job, path = _resolve_owned_path(job_id, current_user)
    result = full_pipeline(path)
    return result.get("cvss_results", {})


@router.get("/report/{job_id}")
def get_report(job_id: str, current_user: User = Depends(get_current_user)):
    job, path = _resolve_owned_path(job_id, current_user)
    result = full_pipeline(path)
    report = generate_final_report(
        file_path=path,
        imports_data=result.get("imports"),
        strings_data=result.get("strings"),
        function_results=result.get("analysis", {}).get("results", []),
        ranked_functions=result.get("ranked_functions", []),  # FIX: was hardcoded []
        capa_results=result.get("capa_results"),
        mitre_results=result.get("mitre_results"),
        cvss_results=result.get("cvss_results"),
        capabilities=result.get("capabilities"),
        capability_scores=result.get("capability_scores"),
    )
    return report


# FIX: /ranking endpoint was missing — added
@router.get("/ranking/{job_id}")
def get_ranking(job_id: str, current_user: User = Depends(get_current_user)):
    job, path = _resolve_owned_path(job_id, current_user)
    result = full_pipeline(path)
    return {
        "ranked_functions": result.get("ranked_functions", []),
        "total": len(result.get("ranked_functions", [])),
    }


# FIX: /risk endpoint was missing — added
@router.get("/risk/{job_id}")
def get_risk(job_id: str, current_user: User = Depends(get_current_user)):
    job, path = _resolve_owned_path(job_id, current_user)
    result = full_pipeline(path)
    risk = result.get("risk", {})
    cvss = result.get("cvss_results", {})

    # Derive threat level from combined score
    combined = risk.get("combined_score", 0)
    if combined >= 75:
        threat_level = "CRITICAL"
    elif combined >= 50:
        threat_level = "HIGH"
    elif combined >= 25:
        threat_level = "MEDIUM"
    elif combined > 0:
        threat_level = "LOW"
    else:
        threat_level = "NONE"

    return {
        "risk": risk,
        "threat_level": threat_level,
        "cvss_score": cvss.get("cvss_score", 0.0),
        "cvss_risk_level": cvss.get("risk_level", "NONE"),
    }
