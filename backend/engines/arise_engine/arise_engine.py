from typing import Any, Dict


def arise_verdict(
    risk: Dict[str, Any],
    cvss_results: Dict[str, Any],
    capabilities: list,
    final_mitre: Dict[str, Any],
    ranked_functions: list,
) -> Dict[str, Any]:

    combined = risk.get("combined_score", 0)

    cvss = (
        cvss_results.get("cvss_score")
        or cvss_results.get("base_score")
        or 0.0
    )
    cvss = float(cvss or 0.0)

    technique_list = final_mitre.get("mitre_techniques", [])
    technique_count = len(technique_list)

    cap_strength = len(capabilities or [])

    # Rule-based verdict
    if combined >= 60 or cvss >= 7.0 or technique_count >= 5 or cap_strength >= 4:
        verdict = "MALICIOUS"
        confidence = max(0, min(100, int(combined * 1.2)))

    elif combined >= 30 or cvss >= 4.0 or technique_count >= 2:
        verdict = "SUSPICIOUS"
        confidence = min(100, int(combined))

    else:
        verdict = "BENIGN"
        confidence = max(0, 100 - combined * 2)

    top_techniques = technique_list[:5]

    return {
        "verdict": verdict,
        "confidence": confidence,
        "summary": (
            f"{verdict} binary with combined risk score {combined}/100, "
            f"CVSS {cvss:.1f}, {technique_count} MITRE technique(s) detected."
        ),
        "top_techniques": top_techniques,
    }