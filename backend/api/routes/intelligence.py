"""
api/routes/intelligence.py

High-level threat intelligence endpoints.
"""

from fastapi import APIRouter
from core.job_manager import get_job

# Reuse pipeline
from api.routes.analysis import full_pipeline, resolve_path

router = APIRouter()


# ---------------------------------------------------------------------------
# INTELLIGENCE SUMMARY
# ---------------------------------------------------------------------------
@router.get("/summary/{job_id}")
def intelligence_summary(job_id: str):
    job, path = resolve_path(job_id)

    if not job:
        return {"error": "job not found"}

    try:
        result = full_pipeline(path)

        cvss = result.get("cvss_results", {})

        behaviours = (
            result.get("behaviors")
            or result.get("behaviour")
            or {}
        )

        final_mitre = result.get("final_mitre", {})

        mitre_list = (
            final_mitre.get("mitre_techniques")
            or final_mitre.get("final_mitre")
            or []
        )

        return {
            "job_id": job_id,
            "file": job["filename"],
            "imports_count": len(result.get("imports", [])),
            "strings_count": len(result.get("strings", [])),
            "functions_analyzed": len(result.get("analysis", {}).get("results", [])),
            "behaviors": behaviours.get("behaviors", []),
            "capabilities": result.get("capabilities", []),
            "mitre_techniques": mitre_list,
            "cvss_score": cvss.get("cvss_score", 0.0),
            "risk_level": cvss.get("risk_level", "NONE"),
        }

    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# GLOBAL BEHAVIOURS
# ---------------------------------------------------------------------------
@router.get("/behaviours/{job_id}")
def intelligence_behaviours(job_id: str):
    job, path = resolve_path(job_id)

    if not job:
        return {"error": "job not found"}

    try:
        result = full_pipeline(path)

        behaviours = (
            result.get("behaviors")
            or result.get("behaviour")
            or {}
        )

        return {
            "job_id": job_id,
            "behaviors": behaviours.get("behaviors", []),
            "behavior_detail": behaviours.get("_detail", []),
            "global_behaviours": result.get("analysis", {}).get("global_behaviours", []),
        }

    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# MITRE INTELLIGENCE
# ---------------------------------------------------------------------------
@router.get("/mitre/{job_id}")
def intelligence_mitre(job_id: str):
    job, path = resolve_path(job_id)

    if not job:
        return {"error": "job not found"}

    try:
        result = full_pipeline(path)

        return {
            "job_id": job_id,
            "behaviour_mitre": result.get("mitre_results", {}),
            "capability_mitre": result.get("capability_mitre_results", {}),
            "final_mitre": result.get("final_mitre", {}),
        }

    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# THREAT SCORE
# ---------------------------------------------------------------------------
@router.get("/threat-score/{job_id}")
def threat_score(job_id: str):
    job, path = resolve_path(job_id)

    if not job:
        return {"error": "job not found"}

    try:
        result = full_pipeline(path)

        cvss = result.get("cvss_results", {})
        risk = result.get("risk", {})

        cvss_score = cvss.get("cvss_score", 0.0)
        combined_score = risk.get("combined_score", 0)

        # Threat level
        if cvss_score >= 9:
            threat_level = "critical"
        elif cvss_score >= 7:
            threat_level = "high"
        elif cvss_score >= 4:
            threat_level = "medium"
        elif cvss_score > 0:
            threat_level = "low"
        else:
            threat_level = "none"

        return {
            "job_id": job_id,
            "cvss_score": cvss_score,
            "combined_risk_score": combined_score,
            "threat_level": threat_level,
            "tactic_coverage": cvss.get("tactic_coverage", []),
            "technique_count": cvss.get("technique_count", 0),
        }

    except Exception as e:
        return {"error": str(e)}