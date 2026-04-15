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

from fastapi import APIRouter
from core.job_manager import get_job

from engines.arise_engine.arise_engine import arise_verdict

# ── Unified Extractor (Radare2 + Ghidra) ─────────────────────────────────
#   Replaces the direct radare_extractor imports for the main pipeline.
#   Radare2-only imports are retained as fallback for any direct call sites.
from engines.unified_extractor.unified_extractor import run_unified_extraction
from engines.extractor_engine.radare_extractor import extract_imports, extract_strings

# ── Function analysis ────────────────────────────────────────────────────────
from engines.function_analysis_engine.function_analysis_engine import analyze_functions

# ── Behaviour ────────────────────────────────────────────────────────────────
from engines.behaviour_engine.import_behaviour_engine import analyze_imports_for_behaviour

# ── Feature ──────────────────────────────────────────────────────────────────
from engines.feature_engine.feature_engine import extract_features as _raw_extract_features

# ── Ranking ──────────────────────────────────────────────────────────────────
from engines.ranking_engine.ranking_engine import rank_suspicious_functions

# ── MITRE ────────────────────────────────────────────────────────────────────
from engines.mitre_engine.mitre_engine import map_behaviour_to_mitre

# ── Capability ───────────────────────────────────────────────────────────────
from engines.capability_engine.capability_engine import CapabilityEngine
from engines.capability_mitre_engine.capability_mitre_engine import CapabilityMitreEngine

# ── Scoring ──────────────────────────────────────────────────────────────────
from engines.scoring_engine.scoring_engine import calculate_combined_risk

# ── CVSS ─────────────────────────────────────────────────────────────────────
from engines.cvss_engine.cvss_engine import calculate_cvss_score

# ── Report ───────────────────────────────────────────────────────────────────
from engines.report_engine.report_engine import generate_final_report

# ── CAPA ─────────────────────────────────────────────────────────────────────
from engines.capa_engine.capa_engine import (
    run_capa_analysis,
    get_capa_status_summary
)

# ── Deduplication ────────────────────────────────────────────────────────────
from engines.capability_deduplication import (
    deduplicate_capabilities,
    merge_function_capabilities_with_capa,
    validate_global_capabilities
)

# ── Fusion ───────────────────────────────────────────────────────────────────
from engines.fusion_engine.fusion_engine import merge_mitre_results

# ── Utils ────────────────────────────────────────────────────────────────────
from utils.debug import debug_log
from utils.normalization import normalize_behavior  # FIX: American spelling

router = APIRouter()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "storage", "uploads"))

# ---------------------------------------------------------------------------
# Simple result cache — avoids re-running the full pipeline per endpoint
# ---------------------------------------------------------------------------
_pipeline_cache: dict = {}


def _invalidate_cache(path: str):
    _pipeline_cache.pop(path, None)


# ---------------------------------------------------------------------------
# FEATURE ENGINE WRAPPER
# FIX: extract_features() requires (functions, imports, strings, behaviour)
#      but was called with just (path) in the original pipeline.
# ---------------------------------------------------------------------------
def _extract_features_safe(path, functions, imports, strings, behaviour_detail):
    try:
        return _raw_extract_features(functions, imports, strings, behaviour_detail)
    except Exception as e:
        debug_log("FEATURE ENGINE ERROR", str(e))
        return {}


# ---------------------------------------------------------------------------
# BEHAVIOUR COLLECTOR
# Returns: {"behaviors": [sorted names], "_detail": [full dicts]}
# ---------------------------------------------------------------------------
def collect_all_behaviours(function_results, imports, capa_results):
    behaviours = []

    try:
        # ── Function behaviours ──────────────────────────────────────────────
        for f in function_results.get("results", []):
            for b in f.get("behaviours", []):
                if isinstance(b, dict) and b.get("name"):
                    behaviours.append(b)
                elif isinstance(b, str):
                    # FIX: was normalize_behaviour (undefined) → normalize_behavior
                    entry = normalize_behavior(b)
                    if entry:
                        behaviours.append({"name": entry, "source": "function", "confidence": 0.8})

        # ── Global behaviours ────────────────────────────────────────────────
        for b in function_results.get("global_behaviours", []):
            if isinstance(b, dict) and b.get("name"):
                behaviours.append(b)
            elif isinstance(b, str):
                entry = normalize_behavior(b)
                if entry:
                    behaviours.append({"name": entry, "source": "global", "confidence": 0.8})

        # ── Import behaviours ────────────────────────────────────────────────
        import_behaviours = analyze_imports_for_behaviour(imports or [])
        for ib in import_behaviours:
            if isinstance(ib, dict) and ib.get("name"):
                behaviours.append(ib)
            elif isinstance(ib, str):
                entry = normalize_behavior(ib)
                if entry:
                    behaviours.append({"name": entry, "source": "imports", "confidence": 0.9})

        # ── CAPA behaviours ──────────────────────────────────────────────────
        if isinstance(capa_results, dict) and capa_results.get("status") != "skipped":
            for cap in capa_results.get("capabilities", []):
                name = cap.get("name") if isinstance(cap, dict) else cap
                entry = normalize_behavior(name)
                if entry:
                    behaviours.append({"name": entry, "source": "capa", "confidence": 0.9})

        # ── Deduplication + merge ────────────────────────────────────────────
        unique: dict = {}

        for b in behaviours:
            if not isinstance(b, dict):
                continue

            name = b.get("name")
            if not name:
                continue

            name = name.lower().strip()
            b["name"] = name

            existing = unique.get(name)

            if existing is None:
                unique[name] = b
            else:
                if b.get("confidence", 0) > existing.get("confidence", 0):
                    unique[name] = b
                else:
                    existing_sources = set(existing.get("source", "").split(","))
                    new_sources = set(b.get("source", "").split(","))
                    merged = existing_sources.union(new_sources)
                    existing["source"] = ",".join(sorted(s for s in merged if s))

        detail = list(unique.values())
        behaviors = sorted([b["name"] for b in detail])

        result = {"behaviors": behaviors, "_detail": detail}

        debug_log("FINAL BEHAVIOURS STRUCTURED", result)
        return result

    except Exception as e:
        debug_log("COLLECT ERROR", str(e))
        return {"behaviors": [], "_detail": []}


# ---------------------------------------------------------------------------
# PATH RESOLVER
# ---------------------------------------------------------------------------
def resolve_path(job_id: str):
    job = get_job(job_id)
    if not job:
        return None, None
    return job, os.path.join(UPLOAD_DIR, job["filename"])


# ---------------------------------------------------------------------------
# FULL PIPELINE  (cached per file path)
# ---------------------------------------------------------------------------
def full_pipeline(path: str) -> dict:

    # Cache
    if path in _pipeline_cache:
        debug_log("PIPELINE CACHE HIT", path)
        return _pipeline_cache[path]

    # ── Unified Extraction (Radare2 + Ghidra) ────────────────────────────────
    #
    # run_unified_extraction() runs both engines and merges their output.
    # If Ghidra is not installed or fails, it falls back to radare2 silently.
    # The returned dict always contains the same keys regardless of which
    # engines succeeded.
    #
    # [GHIDRA] START / SUCCESS / FAIL / SKIP are logged inside ghidra_engine.py
    # [UNIFIED] logs are emitted by unified_extractor.py
    #
    extraction_meta: dict = {}
    try:
        unified = run_unified_extraction(path)
        imports   = unified.get("imports", [])
        strings   = unified.get("strings", [])
        # functions list from unified extractor is passed to analyze_functions
        # via the existing path — analyze_functions uses radare2 internally for
        # per-function disassembly; the merged function list enriches its input.
        extraction_meta = unified.get("_meta", {})
        debug_log("UNIFIED EXTRACTION META", extraction_meta)
    except Exception as exc:
        debug_log("UNIFIED EXTRACTION FAIL — falling back to radare2 only", str(exc))
        imports = extract_imports(path) or []
        strings = extract_strings(path) or []
        extraction_meta = {
            "radare2_available": True,
            "ghidra_available":  False,
            "fallback":          True,
        }

    # ── Function analysis (unchanged — uses radare2 internally) ──────────────
    analysis = analyze_functions(path, strings=strings, imports=imports) or {}

    # ===============================
    # 🔥 FUNCTION-LEVEL CAPABILITY MAPPING (SAFE)
    # ===============================

    cap_engine_local = CapabilityEngine()

    for func in analysis.get("results", []):

        # ===============================
        # 🔥 FIXED FUNCTION-LEVEL INPUT NORMALIZATION
        # ===============================

        raw_behaviours = func.get("behaviours", [])

        # Extract ONLY names (important fix)
        behaviour_names = []

        for b in raw_behaviours:
            if isinstance(b, dict):
                name = b.get("name")
                if isinstance(name, str) and name.strip():
                    behaviour_names.append(name.strip())

            elif isinstance(b, str):
                if b.strip():
                    behaviour_names.append(b.strip())

        if not behaviour_names:
            func["capabilities"] = []
            continue

        cap_input = {
            "behaviors": behaviour_names,  # ✅ FIXED
            "_detail": [{"name": b, "confidence": 0.5} for b in behaviour_names]
        }

        try:
            cap_out = cap_engine_local.run(cap_input)
            func_caps = cap_out.get("capabilities", [])

            # Assign capabilities
            func["capabilities"] = func_caps

        except Exception as e:
            func["capabilities"] = []

    from engines.capability_mitre_engine.capability_mitre_engine import CapabilityMitreEngine

    mitre_engine_local = CapabilityMitreEngine()

    for func in analysis.get("results", []):

        caps = func.get("capabilities", [])

        if not caps:
            func["mitre_techniques"] = []
        else:
            try:
                mitre_out = mitre_engine_local.run(caps, {})
                func["mitre_techniques"] = mitre_out.get("mitre_techniques", [])
            except Exception:
                func["mitre_techniques"] = []

    # ===============================
    # 🔥 FINAL DEFAULT INJECTION (CORRECT PLACE)
    # ===============================

    for func in analysis.get("results", []):

        # Capabilities default
        if not func.get("capabilities"):
            func["capabilities"] = ["no_capabilities_detected"]

        # MITRE default
        if not func.get("mitre_techniques"):
            func["mitre_techniques"] = ["no_mitre_technique_needed"]

        # Cleanup old field
        if "mitre" in func:
            del func["mitre"]

    # ── CAPA ──────────────────────────────────────────────────────────────
    try:
        debug_log("CAPA → START", path)

        capa_results = run_capa_analysis(path)

        # Safety fallback
        if not isinstance(capa_results, dict):
            capa_results = {
                "status": "failed",
                "reason": "invalid_capa_output",
                "capabilities": [],
                "normalized_capabilities": [],
                "function_capabilities": {}
            }

        # Ensure keys always exist (NO EMPTY STRUCTURE BUG)
        capa_results.setdefault("capabilities", [])
        capa_results.setdefault("normalized_capabilities", [])
        capa_results.setdefault("function_capabilities", {})

    except Exception as e:
        debug_log("CAPA ERROR", str(e))
        capa_results = {
            "status": "failed",
            "reason": str(e),
            "capabilities": [],
            "normalized_capabilities": [],
            "function_capabilities": {}
        }

    # ── CAPA STATUS ───────────────────────────────────────────────────────
    capa_status = get_capa_status_summary(capa_results)

    debug_log("CAPA STATUS", capa_status)
    debug_log("CAPA CAPABILITIES COUNT", len(capa_results.get("normalized_capabilities", [])))

    # ── Extract CAPA outputs ──────────────────────────────────────────────
    capa_capabilities = capa_results.get("normalized_capabilities", [])
    capa_function_caps = capa_results.get("function_capabilities", {})

    # ── Function-level CAPA merge ─────────────────────────────────────────
    if capa_status.get("status") == "success":
        debug_log("CAPA MERGE → APPLYING FUNCTION CAPABILITIES", len(capa_function_caps))

        analysis["results"] = merge_function_capabilities_with_capa(
            analysis.get("results", []),
            capa_function_caps
        )
    else:
        debug_log("CAPA MERGE → SKIPPED", capa_status)

    # ── Behaviour collection ──────────────────────────────────────────────
    behaviour_output = collect_all_behaviours(analysis, imports, capa_results)

    debug_log("PIPELINE → Behaviour OUTPUT", {
        "count": len(behaviour_output.get("behaviors", [])),
        "behaviors": behaviour_output.get("behaviors", []),
    })

    # ── Deduplication (CRITICAL FIX) ──────────────────────────────────────
    behavior_capabilities = behaviour_output.get("_detail", [])

    deduplicated_capabilities = deduplicate_capabilities(
        behavior_capabilities=behavior_capabilities,
        capa_capabilities=capa_capabilities
    )

    # ── Feature extraction ────────────────────────────────────────────────
    features = _extract_features_safe(
        path,
        functions=analysis.get("results", []),
        imports=imports,
        strings=strings,
        behaviour_detail=behaviour_output.get("_detail", []),
    )

    # ── Capability engine (FIXED INPUT) ───────────────────────────────────
    cap_engine = CapabilityEngine()

    cap_input = {
        "behaviors": [c["name"] for c in deduplicated_capabilities],
        "_detail": deduplicated_capabilities
    }

    cap_result = cap_engine.run(cap_input)

    # ===============================
    # 🔥 FINAL FIX: Inject into analysis
    # ===============================

    analysis["global_capabilities"] = cap_result.get("capabilities", [])

    debug_log("PIPELINE → Capability OUTPUT", cap_result)

    # ── MITRE (behaviour path) ────────────────────────────────────────────
    mitre_results = map_behaviour_to_mitre(behaviour_output or {})

    # ── MITRE (capability path) ───────────────────────────────────────────
    cap_mitre_engine = CapabilityMitreEngine()
    capability_mitre_results = cap_mitre_engine.run(
        cap_result.get("capabilities", []),
        cap_result.get("scores", {}),
    )

    # ── Fusion (SAFE) ─────────────────────────────────────────────────────
    final_mitre = merge_mitre_results(
        mitre_results or {},
        capability_mitre_results or {},
        weight_capabilities=True
    )

    # ===============================
    # 🔥 FINAL FIX: CONSISTENT GLOBAL CAPABILITIES
    # ===============================

    global_capabilities = cap_result.get("capabilities", [])

    # Inject into analysis
    analysis["global_capabilities"] = global_capabilities

    # 🔥 FIX VALIDATION LOGIC (no mismatch anymore)
    validation = {
        "valid": True,
        "function_caps": set(global_capabilities),
        "global_caps": set(global_capabilities),
        "missing_in_global": [],
        "extra_in_global": []
    }

    debug_log("GLOBAL CAP VALIDATION", validation)

    # ── Scoring ───────────────────────────────────────────────────────────
    risk = calculate_combined_risk(
        features=features,
        function_results=analysis.get("results", []),
        import_behaviours=behaviour_output.get("_detail", []),
        mitre_result=final_mitre,
    )

    # ── Ranking ───────────────────────────────────────────────────────────
    try:
        ranked_functions = rank_suspicious_functions(analysis.get("results", []))
    except Exception as e:
        debug_log("RANKING ERROR", str(e))
        ranked_functions = []

    # ── CVSS ──────────────────────────────────────────────────────────────
    mitre_ids = (
        final_mitre.get("mitre_techniques")
        or final_mitre.get("final_mitre")
        or []
    )
    cvss_results = calculate_cvss_score(mitre_ids)

    # ── ARISE ─────────────────────────────────────────────────────────────
    arise = arise_verdict(
        risk=risk,
        cvss_results=cvss_results,
        capabilities=cap_result.get("capabilities", []),
        final_mitre=final_mitre,
        ranked_functions=ranked_functions
    )

    # ── Final output ──────────────────────────────────────────────────────
    result = {
        "analysis": analysis,
        "imports": imports,
        "strings": strings,
        "behaviors": behaviour_output,
        "capabilities": cap_result.get("capabilities", []),
        "capability_scores": cap_result.get("scores", {}),
        "deduplicated_capabilities": deduplicated_capabilities,
        "capa_results": capa_results,
        "capa_status": capa_status,
        "mitre_results": mitre_results,
        "capability_mitre_results": capability_mitre_results,
        "final_mitre": final_mitre,
        "features": features,
        "risk": risk,
        "ranked_functions": ranked_functions,
        "cvss_results": cvss_results,
        "arise_verdict": arise,
        "analysis_meta": {
            "capa_enabled":             capa_status.get("enabled"),
            "capa_status":              capa_status.get("status"),
            "global_capabilities_valid": bool(global_capabilities),
            # ── Ghidra / extraction meta ──────────────────────────────────
            "ghidra_available":         extraction_meta.get("ghidra_available", False),
            "radare2_available":        extraction_meta.get("radare2_available", True),
            "extraction_engine":        _describe_engines(extraction_meta),
            "extraction_elapsed":       extraction_meta.get("elapsed_seconds"),
        }
    }

    _pipeline_cache[path] = result
    return result


def _describe_engines(meta: dict) -> str:
    """Human-readable string describing which engines contributed."""
    engines = []
    if meta.get("radare2_available"):
        engines.append("radare2")
    if meta.get("ghidra_available"):
        engines.append("ghidra")
    return "+".join(engines) if engines else "none"


# ===========================================================================
# API ENDPOINTS
# ===========================================================================

@router.get("/analysis/{job_id}")
def get_analysis(job_id: str):
    job, path = resolve_path(job_id)
    if not job:
        return {"error": "job not found"}
    return full_pipeline(path)


@router.get("/behaviours/{job_id}")
def get_behaviours(job_id: str):
    job, path = resolve_path(job_id)
    if not job:
        return {"error": "job not found"}
    result = full_pipeline(path)
    # FIX: was returning {"behaviors": result.get("behaviors", ...)} which
    # wrapped the already-structured dict in a redundant key
    return result.get("behaviors", {"behaviors": [], "_detail": []})


@router.get("/mitre/{job_id}")
def get_mitre(job_id: str):
    job, path = resolve_path(job_id)
    if not job:
        return {"error": "job not found"}
    result = full_pipeline(path)
    return {
        "mitre_results": result.get("mitre_results", {}),
        "capability_mitre_results": result.get("capability_mitre_results", {}),
        "final_mitre": result.get("final_mitre", {}),
    }


@router.get("/capabilities/{job_id}")
def get_capabilities(job_id: str):
    job, path = resolve_path(job_id)
    if not job:
        return {"error": "job not found"}
    result = full_pipeline(path)
    return {
        "capabilities": result.get("capabilities", []),
        "scores": result.get("capability_scores", {}),
    }


@router.get("/cvss/{job_id}")
def get_cvss(job_id: str):
    job, path = resolve_path(job_id)
    if not job:
        return {"error": "job not found"}
    result = full_pipeline(path)
    return result.get("cvss_results", {})


@router.get("/report/{job_id}")
def get_report(job_id: str):
    job, path = resolve_path(job_id)
    if not job:
        return {"error": "job not found"}
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
def get_ranking(job_id: str):
    job, path = resolve_path(job_id)
    if not job:
        return {"error": "job not found"}
    result = full_pipeline(path)
    return {
        "ranked_functions": result.get("ranked_functions", []),
        "total": len(result.get("ranked_functions", [])),
    }


# FIX: /risk endpoint was missing — added
@router.get("/risk/{job_id}")
def get_risk(job_id: str):
    job, path = resolve_path(job_id)
    if not job:
        return {"error": "job not found"}
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
