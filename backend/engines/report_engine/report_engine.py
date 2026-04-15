import hashlib
import os
from datetime import datetime
from utils.normalization import normalize_behavior

# ----------------------------------
# FILE METADATA
# ----------------------------------
def get_file_metadata(file_path):
    try:
        if not file_path or not os.path.exists(file_path):
            return {
                "file_size": 0,
                "md5": None,
                "sha1": None,
                "sha256": None,
                "note": "file not found"
            }

        with open(file_path, "rb") as f:
            data = f.read()

        return {
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()
        }

    except Exception as e:
        return {"error": str(e)}


# ----------------------------------
# BEHAVIOUR SUMMARY (FIXED)
# ----------------------------------
def summarize_behaviours(function_results):
    behaviour_count = {}

    if not function_results:
        return behaviour_count

    for func in function_results:

        for b in (
            func.get("behaviors")
            or func.get("behaviour")
            or func.get("behavior")
            or []
        ):

            if isinstance(b, dict):
                raw = b.get("name") or b.get("behavior") or b.get("behaviour")
            else:
                raw = b

            canonical = normalize_behavior(raw)

            if not canonical:
                continue

            behaviour_count[canonical] = behaviour_count.get(canonical, 0) + 1

    return behaviour_count


# ----------------------------------
# FINAL REPORT GENERATOR (FULL FIX)
# ----------------------------------
def generate_final_report(
    file_path,
    imports_data,
    strings_data,
    function_results,
    ranked_functions,
    capa_results,
    mitre_results,
    cvss_results,
    capabilities=None,
    capability_scores=None
):

    file_name = os.path.basename(file_path) if file_path else "unknown"

    metadata = get_file_metadata(file_path)
    behaviour_summary = summarize_behaviours(function_results)

    timestamp = datetime.utcnow().isoformat() + "Z"

    # -------------------------
    # SAFE EXTRACTION (FIXED)
    # -------------------------
    mitre_results = mitre_results or {}
    cvss_results = cvss_results or {}
    capa_results = capa_results or {}

    mitre_techniques = mitre_results.get("mitre_techniques", [])
    cvss_score = cvss_results.get("cvss_score", 0.0)
    risk_level = cvss_results.get("risk_level", "NONE")

    capa_caps = capa_results.get("capabilities", [])

    final_capabilities = capabilities if capabilities is not None else capa_caps
    capability_scores = capability_scores or {}

    # -------------------------
    # FINAL REPORT
    # -------------------------
    report = {

        # =====================
        # METADATA
        # =====================
        "report_metadata": {
            "file_name": file_name,
            "analysis_timestamp": timestamp,
            "engine_version": "2.2"
        },

        "file_metadata": metadata,

        # =====================
        # SUMMARY
        # =====================
        "analysis_summary": {
            "total_functions": len(function_results or []),
            "suspicious_functions": len(ranked_functions or []),
            "total_imports": len(imports_data or []),
            "total_strings": len(strings_data or []),

            "capabilities_detected": len(final_capabilities),

            "mitre_techniques": mitre_techniques,
            "mitre_technique_count": len(mitre_techniques),

            "cvss_score": cvss_score,
            "risk_level": risk_level
        },

        # =====================
        # BEHAVIOUR
        # =====================
        "behaviour_analysis": {
            "summary": behaviour_summary,
            "unique_behaviours": list(behaviour_summary.keys())
        },

        # =====================
        # THREAT INTELLIGENCE
        # =====================
        "threat_intelligence": {
            "mitre_mapping": mitre_results,
            "capa_capabilities": capa_caps,
            "capabilities": final_capabilities,
            "capability_scores": capability_scores,
            "threat_scoring": cvss_results
        },

        # =====================
        # STATIC
        # =====================
        "static_analysis": {
            "imports": imports_data or [],
            "strings": strings_data or []
        },

        # =====================
        # FUNCTION LEVEL
        # =====================
        "function_analysis": function_results or [],
        "top_suspicious_functions": ranked_functions or []
    }

    return report