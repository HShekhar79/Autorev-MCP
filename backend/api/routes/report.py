"""
backend/api/routes/report.py — FINAL AUTHORITATIVE VERSION

PDF report download with customisable section selection.

FIXES:
  - _normalise_legacy import removed (it doesn't exist in analysis route);
    legacy job_id path now calls full_pipeline and wraps result directly
  - Preview endpoint now works without task_id for demo/local results
  - Section validation returns canonical order regardless of checkbox order
  - Error messages are specific and actionable
"""

import os
import sys
import logging
from typing import Optional

# Ensure backend/ directory is always in Python path.
# Required on Windows where the server may be launched from the project root
# rather than the backend/ directory, causing "No module named engines.*" errors.
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, JSONResponse
from pydantic import BaseModel

log = logging.getLogger("arise.report")
router = APIRouter()

# ---------------------------------------------------------------------------
# SECTION DEFINITIONS  (order = PDF section order)
# ---------------------------------------------------------------------------

SECTION_DEFINITIONS = [
    {"key": "cover",        "label": "Cover Page",               "description": "Title, verdict badge, file info, hashes"},
    {"key": "executive",    "label": "Executive Summary",         "description": "Summary + recommended actions"},
    {"key": "metadata",     "label": "File Metadata & Hashes",   "description": "MD5, SHA-1, SHA-256, file size, engine"},
    {"key": "verdict",      "label": "Verdict & Risk Assessment", "description": "Verdict, confidence, CVSS, risk score"},
    {"key": "capabilities", "label": "Capabilities",              "description": "Detected capability groups"},
    {"key": "mitre",        "label": "MITRE ATT&CK Mapping",     "description": "Full technique table with descriptions"},
    {"key": "ioc",          "label": "IOC Indicators",            "description": "URLs, IPs, registry keys, paths from strings"},
    {"key": "strings",      "label": "Strings",                   "description": "Top 100 strings sorted by suspicion score"},
    {"key": "imports",      "label": "Imports",                   "description": "All detected import names"},
    {"key": "functions",    "label": "Functions",                 "description": "Top 50 functions with sizes"},
    {"key": "risk",         "label": "Risk Breakdown",            "description": "Detailed risk metric table"},
    {"key": "json",         "label": "Raw JSON Appendix",         "description": "Machine-readable JSON summary"},
]

ALL_SECTION_KEYS = [s["key"] for s in SECTION_DEFINITIONS]

# ---------------------------------------------------------------------------
# REQUEST MODELS
# ---------------------------------------------------------------------------

class ReportRequest(BaseModel):
    task_id:   Optional[str] = None
    job_id:    Optional[str] = None
    sections:  Optional[list[str]] = None
    file_path: Optional[str] = None


class PreviewRequest(BaseModel):
    task_id: Optional[str] = None
    job_id:  Optional[str] = None


# ---------------------------------------------------------------------------
# RESULT RESOLUTION
# ---------------------------------------------------------------------------

def _resolve_result(task_id: Optional[str], job_id: Optional[str]) -> tuple[dict, Optional[str]]:
    """
    Resolve a pipeline result dict from either:
      task_id → Celery backend (upload_api.py path)
      job_id  → In-memory job store (main.py legacy path)
    """
    if task_id:
        try:
            from celery_worker import celery_app
            from celery.result import AsyncResult
            ar = AsyncResult(task_id, app=celery_app)
            if ar.state != "SUCCESS":
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Task {task_id} is not complete (state={ar.state}). "
                        "Wait for analysis to finish before downloading the report."
                    )
                )
            result = ar.result
            if not isinstance(result, dict):
                raise HTTPException(status_code=500, detail="Task result is not a valid analysis dict")
            return result, None
        except ImportError:
            raise HTTPException(status_code=500, detail="Celery worker not available in this environment")

    elif job_id:
        try:
            from core.job_manager import get_job
            from api.routes.analysis import full_pipeline, UPLOAD_DIR
            job = get_job(job_id)
            if not job:
                raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
            file_path = os.path.join(UPLOAD_DIR, job.get("filename", ""))
            if not os.path.isfile(file_path):
                # Job may have result cached
                cached = job.get("result")
                if cached and isinstance(cached, dict):
                    return cached, None
                raise HTTPException(status_code=404, detail="Uploaded file no longer available — cannot regenerate report")
            raw = full_pipeline(file_path)
            if not isinstance(raw, dict):
                raise HTTPException(status_code=500, detail="Pipeline returned unexpected output")
            return raw, file_path
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Pipeline error: {exc}")

    raise HTTPException(status_code=400, detail="Provide either task_id or job_id")


def _validate_sections(sections: Optional[list]) -> list:
    if not sections:
        return ALL_SECTION_KEYS
    valid = [s for s in ALL_SECTION_KEYS if s in sections]  # canonical order
    if not valid:
        raise HTTPException(
            status_code=400,
            detail=f"No valid section keys. Valid: {ALL_SECTION_KEYS}"
        )
    return valid

# ---------------------------------------------------------------------------
# ENDPOINTS
# ---------------------------------------------------------------------------

@router.get("/report/sections")
def list_sections():
    return {"sections": SECTION_DEFINITIONS, "total": len(SECTION_DEFINITIONS)}


@router.post("/report/generate")
def generate_report(req: ReportRequest):
    """
    Generate and stream a PDF report.

    Body:
        task_id  — Celery task ID from /upload-analyze
        job_id   — Legacy job ID from /upload
        sections — Section keys to include (null = full report)
    """
    try:
        from engines.pdf_engine.pdf_engine import generate_pdf_report
    except ImportError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"PDF engine unavailable: {exc}. Install: pip install reportlab"
        )

    result, resolved_path = _resolve_result(req.task_id, req.job_id)
    file_path = req.file_path or resolved_path
    sections  = _validate_sections(req.sections)

    meta      = result.get("analysis_meta", {})
    filename  = meta.get("filename", "analysis")
    safe_name = "".join(c for c in filename if c.isalnum() or c in "._-")[:60]
    section_tag = "full" if len(sections) == len(ALL_SECTION_KEYS) else "custom"
    pdf_filename = f"ARISE_Report_{safe_name}_{section_tag}.pdf"

    log.info(f"Generating PDF: sections={sections} file={filename}")

    try:
        pdf_bytes = generate_pdf_report(
            result=result,
            file_path=file_path,
            sections=sections,
        )
    except Exception as exc:
        log.error(f"PDF generation failed: {exc}")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")

    log.info(f"PDF generated: {len(pdf_bytes)} bytes")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{pdf_filename}"',
            "Content-Length": str(len(pdf_bytes)),
            "X-ARISE-Sections": ",".join(sections),
        },
    )


@router.post("/report/preview")
def preview_report(req: PreviewRequest):
    """Return per-section item counts for the frontend checkbox preview."""
    result, _ = _resolve_result(req.task_id, req.job_id)

    meta         = result.get("analysis_meta", {})
    verdict_raw  = result.get("verdict", {})
    label        = verdict_raw.get("verdict") or verdict_raw.get("label") or "UNKNOWN"
    caps         = result.get("capabilities", [])
    mitre_list   = result.get("mitre", [])
    imports_list = result.get("imports", [])
    strings_list = result.get("strings", [])
    funcs_list   = result.get("functions", [])

    import re
    ioc_pat = re.compile(r"https?://|HKEY_|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|cmd\.exe|powershell", re.I)
    ioc_count = sum(1 for s in strings_list[:500] if ioc_pat.search(str(s)))

    preview = {
        "cover":        {"count": 1,                   "note": f"Verdict: {label}"},
        "executive":    {"count": 1,                   "note": result.get("summary", "")[:100] or "Summary available"},
        "metadata":     {"count": 11,                  "note": f"Engine: {meta.get('extraction_engine','radare2')}"},
        "verdict":      {"count": 8,                   "note": f"{label}"},
        "capabilities": {"count": len(caps),           "note": f"{len(caps)} capability group(s)"},
        "mitre":        {"count": len(mitre_list),     "note": f"{len(mitre_list)} technique(s)"},
        "ioc":          {"count": ioc_count,           "note": f"~{ioc_count} indicator(s)"},
        "strings":      {"count": len(strings_list),   "note": f"{len(strings_list)} strings (top 100 in PDF)"},
        "imports":      {"count": len(imports_list),   "note": f"{len(imports_list)} import(s)"},
        "functions":    {"count": len(funcs_list),     "note": f"{len(funcs_list)} function(s) (top 50 in PDF)"},
        "risk":         {"count": 9,                   "note": f"Risk {result.get('risk_score', 0):.0f}/100"},
        "json":         {"count": 1,                   "note": "Raw JSON appendix"},
    }

    return {"sections": preview, "filename": meta.get("filename", "unknown")}
