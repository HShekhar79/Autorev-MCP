"""
services/analysis_pipeline.py

Framework-neutral, AUTHORITATIVE malware-analysis pipeline.

Single implementation shared by the FastAPI route (api/routes/analysis.py),
the Celery worker (celery_worker.py), the MCP server (mcp_server.py) and the
legacy analysis.py wrapper. Moved from api/routes/analysis.py::full_pipeline
with orchestration-only changes (progress callback, failure boundary, extra
``function_analysis`` / ``functions`` / ``calls`` result keys). No FastAPI,
APIRouter, Celery or job_manager dependency.
"""

import collections
import copy
import os
import threading
from contextlib import contextmanager

from utils.debug import debug_log

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
from utils.normalization import normalize_behavior  # FIX: American spelling


class PipelineExtractionFailedError(RuntimeError):
    """Total primary extraction failure: no usable evidence was produced."""


def _has_usable_evidence(functions, imports, strings, calls, function_analysis) -> bool:
    return bool(
        functions or imports or strings or calls
        or (function_analysis or {}).get("results")
    )


def _notify(progress_cb, stage: str, pct: int) -> None:
    """Best-effort progress notification. Only the callback is protected."""
    if progress_cb is None:
        return
    try:
        progress_cb(stage, pct)
    except Exception as exc:  # progress must never fail an analysis
        debug_log("PROGRESS CALLBACK ERROR", f"{stage}: {exc}")


# ---------------------------------------------------------------------------
# Thread-safe Bounded Result Cache
# Keyed by canonical file identity (path, size, mtime) to avoid stale entries
# and bounded to prevent memory growth. Returns isolated deep copies.
# ---------------------------------------------------------------------------
class BoundedPipelineCache(collections.OrderedDict):
    def __init__(self, max_size: int = 32, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_size = max_size
        self._lock = threading.RLock()
        self._path_to_identity: dict[str, tuple] = {}

    def get_entry(self, identity: tuple, path: str):
        with self._lock:
            if identity in self:
                self.move_to_end(identity)
                return copy.deepcopy(super().__getitem__(identity))
            if path in self:
                self.move_to_end(path)
                return copy.deepcopy(super().__getitem__(path))
            return None

    def set_entry(self, identity: tuple, path: str, result: dict):
        with self._lock:
            val = copy.deepcopy(result)
            old_ident = self._path_to_identity.get(path)
            if old_ident and old_ident != identity:
                super().pop(old_ident, None)

            self._path_to_identity[path] = identity
            self[identity] = val
            while len(self) > self.max_size:
                popped_key, _ = self.popitem(last=False)
                for p, id_key in list(self._path_to_identity.items()):
                    if id_key == popped_key or p == popped_key:
                        self._path_to_identity.pop(p, None)

    def invalidate_path(self, path: str):
        with self._lock:
            ident = self._path_to_identity.pop(path, None)
            if ident:
                super().pop(ident, None)
            super().pop(path, None)

    def __getitem__(self, key):
        with self._lock:
            return copy.deepcopy(super().__getitem__(key))

    def __setitem__(self, key, value):
        with self._lock:
            super().__setitem__(key, copy.deepcopy(value))
            self.move_to_end(key)
            while len(self) > self.max_size:
                popped_key, _ = self.popitem(last=False)
                for p, id_key in list(self._path_to_identity.items()):
                    if id_key == popped_key or p == popped_key:
                        self._path_to_identity.pop(p, None)

    def __contains__(self, key):
        with self._lock:
            return super().__contains__(key)

    def pop(self, key, default=None):
        with self._lock:
            if isinstance(key, str):
                self.invalidate_path(key)
            return super().pop(key, default)

    def clear(self):
        with self._lock:
            self._path_to_identity.clear()
            super().clear()


def _get_file_identity(path: str) -> tuple:
    try:
        if os.path.isfile(path):
            st = os.stat(path)
            mtime_ns = getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))
            return (os.path.realpath(path), st.st_size, mtime_ns)
    except OSError:
        pass
    return (os.path.abspath(path), None, None)


_pipeline_cache: BoundedPipelineCache = BoundedPipelineCache(max_size=32)

# Per-file single-flight coordination. Different file identities use
# different locks, so unrelated analyses remain concurrent.
_pipeline_lock_registry_guard = threading.Lock()
_pipeline_lock_registry: dict[tuple, tuple[threading.Lock, int]] = {}


@contextmanager
def _pipeline_lock_for(identity: tuple):
    """Hold a reference-counted lock for one file identity."""
    with _pipeline_lock_registry_guard:
        entry = _pipeline_lock_registry.get(identity)
        if entry is None:
            lock = threading.Lock()
            users = 1
        else:
            lock, users = entry
            users += 1
        _pipeline_lock_registry[identity] = (lock, users)

    lock.acquire()
    try:
        yield
    finally:
        lock.release()
        with _pipeline_lock_registry_guard:
            current = _pipeline_lock_registry.get(identity)
            if current is not None and current[0] is lock:
                remaining_users = current[1] - 1
                if remaining_users == 0:
                    _pipeline_lock_registry.pop(identity, None)
                else:
                    _pipeline_lock_registry[identity] = (
                        lock,
                        remaining_users,
                    )

def _invalidate_cache(path: str):
    _pipeline_cache.invalidate_path(path)


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
        results_list = function_results.get("results", []) if isinstance(function_results, dict) else []
        for f in results_list:
            func_name = f.get("function_name") if isinstance(f, dict) else None
            for b in (f.get("behaviours", []) if isinstance(f, dict) else []):
                if isinstance(b, dict) and b.get("name"):
                    entry = dict(b)  # copy to prevent mutating function_results
                    entry.setdefault("source", "function")
                    if func_name:
                        if "function" not in entry:
                            entry["function"] = func_name
                        entry["functions"] = [func_name]
                    behaviours.append(entry)
                elif isinstance(b, str):
                    entry = normalize_behavior(b)
                    if entry:
                        item = {"name": entry, "source": "function", "confidence": 0.8}
                        if func_name:
                            item["function"] = func_name
                            item["functions"] = [func_name]
                        behaviours.append(item)

        # ── Global behaviours ────────────────────────────────────────────────
        global_b = function_results.get("global_behaviours", []) if isinstance(function_results, dict) else []
        for b in global_b:
            if isinstance(b, dict) and b.get("name"):
                entry = dict(b)
                entry.setdefault("source", "global")
                behaviours.append(entry)
            elif isinstance(b, str):
                entry = normalize_behavior(b)
                if entry:
                    behaviours.append({"name": entry, "source": "global", "confidence": 0.8})

        # ── Import behaviours ────────────────────────────────────────────────
        import_behaviours = analyze_imports_for_behaviour(imports or [])
        for ib in import_behaviours:
            if isinstance(ib, dict) and ib.get("name"):
                entry = dict(ib)
                entry.setdefault("source", "imports")
                behaviours.append(entry)
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
            item = dict(b)  # copy to avoid aliasing
            item["name"] = name

            existing = unique.get(name)

            if existing is None:
                if "function" in item and "functions" not in item:
                    item["functions"] = [item["function"]]
                elif "functions" not in item:
                    item["functions"] = []
                unique[name] = item
            else:
                existing_sources = set(existing.get("source", "").split(","))
                new_sources = set(item.get("source", "").split(","))
                merged_sources = ",".join(sorted(s for s in existing_sources.union(new_sources) if s))

                existing_funcs = set(existing.get("functions", []))
                if existing.get("function"):
                    existing_funcs.add(existing["function"])
                new_funcs = set(item.get("functions", []))
                if item.get("function"):
                    new_funcs.add(item["function"])
                all_funcs = sorted(list(s for s in existing_funcs.union(new_funcs) if s))

                primary_func = existing.get("function") or item.get("function")

                if item.get("confidence", 0) > existing.get("confidence", 0):
                    item["source"] = merged_sources
                    if primary_func:
                        item["function"] = primary_func
                    item["functions"] = all_funcs
                    unique[name] = item
                else:
                    existing["source"] = merged_sources
                    if primary_func:
                        existing["function"] = primary_func
                    existing["functions"] = all_funcs

        detail = list(unique.values())
        behaviors = sorted([b["name"] for b in detail])

        result = {"behaviors": behaviors, "_detail": detail}

        debug_log("FINAL BEHAVIOURS STRUCTURED", result)
        return result

    except Exception as e:
        debug_log("COLLECT ERROR", str(e))
        return {"behaviors": [], "_detail": []}


# ---------------------------------------------------------------------------
# FULL PIPELINE  (cached per file path)
# ---------------------------------------------------------------------------
def _run_analysis_pipeline_locked(path: str, progress_cb=None) -> dict:
    """
    THE authoritative malware-analysis pipeline (single implementation).

    progress_cb: optional ``callable(stage: str, pct: int)`` invoked at major
    stages only. It is purely informational: an exception raised by the
    callback is swallowed (see _notify) and never affects the analysis.

    Raises PipelineExtractionFailedError on total primary-extraction failure.
    Results are cached per file path (callers use unique UUID-based paths).
    """

    # Cache
    file_identity = _get_file_identity(path)
    cached_result = _pipeline_cache.get_entry(file_identity, path)
    if cached_result is not None:
        debug_log("PIPELINE CACHE HIT", path)
        return copy.deepcopy(cached_result)

    # ── Unified Extraction (Radare2 + Ghidra) ────────────────────────────────
    
    # run_unified_extraction() runs both engines and merges their output.
    # If Ghidra is not installed or fails, it falls back to radare2 silently.
    # The returned dict always contains the same keys regardless of which
    # engines succeeded.
    
    # [GHIDRA] START / SUCCESS / FAIL / SKIP are logged inside ghidra_engine.py
    # [UNIFIED] logs are emitted by unified_extractor.py
    
    extraction_meta: dict = {}
    extracted_functions: list = []
    extracted_calls: list = []
    try:
        unified = run_unified_extraction(path)
        imports   = unified.get("imports", [])
        strings   = unified.get("strings", [])
        extracted_functions = unified.get("functions", []) or []
        extracted_calls     = unified.get("calls", []) or []
        # functions list from unified extractor is passed to analyze_functions
        # via the existing path — analyze_functions uses radare2 internally for
        # per-function disassembly; the merged function list enriches its input.
        extraction_meta = unified.get("_meta", {})
        debug_log("UNIFIED EXTRACTION META", extraction_meta)
    except Exception as exc:
        debug_log("UNIFIED EXTRACTION FAIL — falling back to radare2 only", str(exc))
        imports = []
        strings = []
        r2_avail = False
        try:
            imports = extract_imports(path) or []
            strings = extract_strings(path) or []
            r2_avail = bool(imports or strings)
        except Exception:
            pass
        extraction_meta = {
            "radare2_available": r2_avail,
            "ghidra_available":  False,
            "fallback":          True,
            "reason":            str(exc),
        }

    _notify(progress_cb, "extraction", 10)

    # ── Function analysis (unchanged — uses radare2 internally) ──────────────
    analysis = analyze_functions(path, strings=strings, imports=imports) or {}

    # ── Failure boundary: total primary extraction failure → FAILED ──────────
    if not _has_usable_evidence(extracted_functions, imports, strings,
                                extracted_calls, analysis):
        reason = extraction_meta.get("reason") or "unknown"
        raise PipelineExtractionFailedError(
            f"Primary extraction produced no usable evidence (reason: {reason})"
        )

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

    _notify(progress_cb, "function_analysis", 30)

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

    _notify(progress_cb, "capa", 50)

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
    _notify(progress_cb, "behaviour_capability", 65)

    # ── MITRE (behaviour path) ────────────────────────────────────────────
    mitre_results = map_behaviour_to_mitre(behaviour_output or {})

    # ── MITRE (capability path) ───────────────────────────────────────────
    cap_mitre_engine = CapabilityMitreEngine()
    capability_mitre_results = cap_mitre_engine.run(
        cap_result.get("capabilities", []),
        cap_result.get("scores", {}),
    )

    # ── Fusion (SAFE) ─────────────────────────────────────────────────────
    # final_mitre = evidence-supported techniques only (behaviour, optionally
    # corroborated by capability). Capability-only techniques are returned as
    # final_mitre["mitre_candidates"]: visible hypotheses, not findings, and
    # not used by risk scoring / CVSS. capability_mitre_results (raw) is kept
    # unchanged below for analyst/debug visibility.
    final_mitre = merge_mitre_results(
        mitre_results or {},
        capability_mitre_results or {},
        weight_capabilities=True
    )
    _notify(progress_cb, "mitre", 80)

    # ===============================
    # ===============================
    # REAL GLOBAL CAPABILITY VALIDATION (Fix 4)
    # ===============================

    global_capabilities = cap_result.get("capabilities", [])

    # Inject into analysis
    analysis["global_capabilities"] = global_capabilities

    validation = validate_global_capabilities(
        analysis.get("results", []),
        global_capabilities
    )
    analysis["capability_validation"] = validation

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
    _notify(progress_cb, "scoring", 95)

    # ── Final output ──────────────────────────────────────────────────────
    result = {
        "analysis": analysis,
        # function_analysis aliases the FINAL analysis["results"] (post CAPA merge)
        "function_analysis": analysis.get("results", []),
        "functions": extracted_functions,
        "calls": extracted_calls,
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
        "mitre_candidates": (final_mitre or {}).get("mitre_candidates", []),
        "features": features,
        "risk": risk,
        "ranked_functions": ranked_functions,
        "cvss_results": cvss_results,
        "arise_verdict": arise,
        "analysis_meta": {
            "capa_enabled":             capa_status.get("enabled"),
            "capa_status":              capa_status.get("status"),
            "global_capabilities_valid": bool(validation.get("valid", False)),
            # ── Ghidra / extraction meta ──────────────────────────────────
            "ghidra_available":         bool(extraction_meta.get("ghidra_available", False)),
            "radare2_available":        bool(extraction_meta.get("radare2_available", False)),
            "extraction_engine":        _describe_engines(extraction_meta),
            "extraction_elapsed":       extraction_meta.get("elapsed_seconds"),
        }
    }

    _pipeline_cache.set_entry(file_identity, path, result)
    _notify(progress_cb, "complete", 100)
    return copy.deepcopy(result)


def run_analysis_pipeline(path: str, progress_cb=None) -> dict:
    """Run one analysis at a time per file identity, sharing cached results."""
    file_identity = _get_file_identity(path)

    with _pipeline_lock_for(file_identity):
        # Recheck cache inside the lock. A previous caller may have
        # completed and populated it while this caller was waiting.
        return _run_analysis_pipeline_locked(path, progress_cb)


def _describe_engines(meta: dict) -> str:
    """Human-readable string describing which engines contributed."""
    engines = []
    if meta.get("radare2_available"):
        engines.append("radare2")
    if meta.get("ghidra_available"):
        engines.append("ghidra")
    return "+".join(engines) if engines else "none"


def _mitre_ids(final_mitre) -> list:
    if isinstance(final_mitre, dict):
        ids = final_mitre.get("mitre_techniques") or final_mitre.get("final_mitre") or []
    else:
        ids = final_mitre or []
    return list(ids) if isinstance(ids, (list, tuple)) else []


def to_legacy_result(raw: dict) -> dict:
    """
    Add the legacy compatibility fields (functions, calls, behaviours, mitre,
    risk_score, cvss, cvss_score, verdict) used by Celery/upload_api and MCP.
    Returns a NEW shallow-copied dict; the cached authoritative result is not
    mutated and every authoritative key is preserved.
    """
    out = dict(raw)
    beh = raw.get("behaviors")
    names = beh.get("behaviors", []) if isinstance(beh, dict) else (beh or [])
    cvss_results = raw.get("cvss_results") or {}
    out.setdefault("behaviours", list(names))
    out["mitre"] = _mitre_ids(raw.get("final_mitre"))
    out["risk_score"] = (raw.get("risk") or {}).get("combined_score", 0)
    out["cvss"] = cvss_results
    out["cvss_score"] = cvss_results.get("cvss_score", 0) if isinstance(cvss_results, dict) else 0
    out["verdict"] = raw.get("arise_verdict", {})
    return out
