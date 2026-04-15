from engines.unified_extractor.unified_extractor import run_unified_extraction
from engines.capability_engine.capability_engine import CapabilityEngine
from engines.capability_mitre_engine.capability_mitre_engine import CapabilityMitreEngine
from engines.mitre_engine.mitre_engine import map_behaviour_to_mitre
from engines.behaviour_engine.behaviour_engine import detect_behaviour_from_calls
from engines.scoring_engine.scoring_engine import calculate_combined_risk
from engines.cvss_engine.cvss_engine import calculate_cvss_score
from engines.arise_engine.arise_engine import arise_verdict
from utils.debug import debug_log


def run_analysis_pipeline(file_path: str) -> dict:
    debug_log("[PIPELINE]", f"START: {file_path}")

    # -------------------------------
    # 1. Extraction (Radare2 + Ghidra)
    # -------------------------------
    extraction = run_unified_extraction(file_path)

    functions = extraction.get("functions", [])
    imports   = extraction.get("imports", [])
    strings   = extraction.get("strings", [])
    calls     = extraction.get("calls", [])

    meta = extraction.get("_meta", {})

    # -------------------------------
    # 2. Behaviour Analysis
    # -------------------------------
    behaviours = detect_behaviour_from_calls(calls)

    # -------------------------------
    # 3. Capability Detection
    # -------------------------------
    cap_engine = CapabilityEngine()
    cap_result = cap_engine.run(behaviours)

    capabilities = cap_result.get("capabilities", [])
    cap_scores   = cap_result.get("scores", {})

    # -------------------------------
    # 4. MITRE Mapping
    # -------------------------------

    # Behaviour → MITRE
    mitre_result = map_behaviour_to_mitre(behaviours)
    mitre_from_behaviour = mitre_result.get("mitre_techniques", [])

    # Capability → MITRE
    cap_mitre_engine = CapabilityMitreEngine()
    mitre_cap_result = cap_mitre_engine.run(capabilities, cap_scores)

    mitre_from_capability = mitre_cap_result.get("mitre_techniques", [])

    # Final merge
    final_mitre = list(set(mitre_from_behaviour + mitre_from_capability))

    # -------------------------------
    # 5. Scoring
    # -------------------------------
    score_result = calculate_combined_risk(
        features={
            "import_count": len(imports),
            "function_count": len(functions),
            "suspicious_strings": len(strings),
        },
        function_results=[],
        import_behaviours=capabilities,
        mitre_result={"mitre_techniques": final_mitre}
    )

    risk_score = score_result.get("combined_score", 0)

    # -------------------------------
    # 6. CVSS
    # -------------------------------
    cvss = calculate_cvss_score(capabilities, final_mitre)

    # -------------------------------
    # 7. Verdict (FINAL FIX)
    # -------------------------------
    verdict_result = arise_verdict(
        risk={"combined_score": risk_score},
        cvss_results={"cvss_score": cvss if isinstance(cvss, (int, float)) else 0},
        capabilities=capabilities,
        final_mitre={"mitre_techniques": final_mitre},
        ranked_functions=[]
    )

    debug_log("[PIPELINE]", "COMPLETE")

    return {
        "functions": functions,
        "imports": imports,
        "strings": strings,
        "calls": calls,
        "capabilities": capabilities,
        "mitre": final_mitre,
        "risk_score": risk_score,
        "cvss": cvss,
        "verdict": verdict_result,
        "analysis_meta": {
            "ghidra_available": meta.get("ghidra_available", False),
            "radare2_available": meta.get("radare2_available", True),
            "extraction_engine": meta.get("extraction_engine", "unknown"),
        }
    }