"""
engines/fusion_engine.py

MITRE technique fusion: evidence-supported findings vs capability candidates.

Evidence model
--------------
    behaviour-only            -> SUPPORTED   sources ["behavior"]
    behaviour + capability    -> SUPPORTED   sources ["behavior", "capability"]  (corroborated)
    capability-only           -> CANDIDATE   sources ["capability"]  (hypothesis)

Direct behaviour evidence is sufficient on its own. A capability-derived
technique is never promoted to a finding without behaviour support; it stays
visible to analysts in ``mitre_candidates`` as an investigative hypothesis
(NOT a confirmed finding, and NOT automatically a false positive).

Only SUPPORTED techniques appear in ``mitre_techniques`` / ``final_mitre`` /
``scores`` and therefore only they feed risk scoring and CVSS.

Scores: behaviour base 1.5 (2.0 if weight_capabilities=False); a corroborated
technique takes MAX(behaviour base, capability score) - never a sum.
"""

import math

from utils.debug import debug_log
from typing import Dict, Any, List, Optional


SOURCE_BEHAVIOR = "behavior"
SOURCE_CAPABILITY = "capability"


def _valid_ids(values) -> List[str]:
    if not isinstance(values, (list, tuple, set)):
        return []
    return [v for v in values if isinstance(v, str) and v]


def _safe_score(value) -> float:
    try:
        score = float(value)
    except Exception:
        return 0.0
    return score if math.isfinite(score) else 0.0


def _rank(scores: Dict[str, float]) -> List[str]:
    # score DESC, then technique ID ASC -> deterministic regardless of input order
    return sorted(scores.keys(), key=lambda t: (-scores[t], t))


def _empty_result(message: str) -> dict:
    return {
        "mitre_techniques": [],
        "final_mitre": [],
        "scores": {},
        "total_techniques": 0,
        "tactics": {},
        "sources": {},
        "support_level": {},
        "mitre_candidates": [],
        "candidate_scores": {},
        "candidate_details": [],
        "total_candidates": 0,
        "message": message,
    }


def merge_mitre_results(
    behaviour_mitre: dict,
    capability_mitre: dict,
    weight_capabilities: bool = True
) -> dict:
    """
    Fuse behaviour->MITRE and capability->MITRE into supported findings and
    capability-only candidates.

    Args:
        behaviour_mitre: Output from mitre_engine.map_behaviour_to_mitre()
        capability_mitre: Output from capability_mitre_engine.run()
        weight_capabilities: if True behaviour base score is 1.5, else 2.0

    Returns:
        {
            # ---- evidence-supported (risk-eligible) ----
            "mitre_techniques": list[str],      # supported IDs, ranked
            "final_mitre": list[str],           # alias for compatibility
            "scores": dict[str, float],         # supported techniques only
            "total_techniques": int,            # supported count
            "tactics": dict[str, list[str]],    # preserved from behaviour engine
            "sources": dict[str, list[str]],    # supported: ["behavior"] or
                                                #            ["behavior", "capability"]
            "support_level": dict[str, str],    # "behavior" | "corroborated"

            # ---- capability-only hypotheses (NOT risk-eligible) ----
            "mitre_candidates": list[str],      # ranked IDs
            "candidate_scores": dict[str, float],
            "candidate_details": list[dict],    # id, score, sources, status,
                                                # derived_from_capabilities
            "total_candidates": int,
        }
    """
    behaviour_mitre = behaviour_mitre or {}
    capability_mitre = capability_mitre or {}

    base_score = 1.5 if weight_capabilities else 2.0

    # -------------------------
    # 1. Behaviour MITRE (direct evidence -> supported)
    # -------------------------
    behaviour_list = behaviour_mitre.get("mitre_techniques", [])
    behaviour_ids = set(_valid_ids(behaviour_list))

    supported_scores: Dict[str, float] = {}
    sources: Dict[str, List[str]] = {}

    for tech in behaviour_ids:
        supported_scores[tech] = base_score
        sources[tech] = [SOURCE_BEHAVIOR]

    # -------------------------
    # 2. Capability MITRE (corroborates or becomes a candidate)
    # -------------------------
    cap_scores = capability_mitre.get("scores", {})
    derived_from = capability_mitre.get("derived_from", {})
    if not isinstance(derived_from, dict):
        derived_from = {}

    candidate_scores: Dict[str, float] = {}

    if isinstance(cap_scores, dict):
        for tech, raw_score in cap_scores.items():
            if not isinstance(tech, str) or not tech:
                continue

            score = _safe_score(raw_score)

            if tech in behaviour_ids:
                # Corroborated: keep MAX, never sum
                supported_scores[tech] = max(supported_scores[tech], score)
                if SOURCE_CAPABILITY not in sources[tech]:
                    sources[tech].append(SOURCE_CAPABILITY)
            else:
                candidate_scores[tech] = max(candidate_scores.get(tech, 0.0), score)

    # -------------------------
    # EMPTY SAFE CASE
    # -------------------------
    if not supported_scores and not candidate_scores:
        return _empty_result("No MITRE techniques detected")

    # -------------------------
    # Normalize + rank (deterministic)
    # -------------------------
    supported_scores = {t: round(s, 2) for t, s in supported_scores.items()}
    candidate_scores = {t: round(s, 2) for t, s in candidate_scores.items()}

    ranked = _rank(supported_scores)
    candidate_ranked = _rank(candidate_scores)

    support_level = {
        t: ("corroborated" if SOURCE_CAPABILITY in sources[t] else "behavior")
        for t in ranked
    }

    candidate_details = []
    for tech in candidate_ranked:
        caps = derived_from.get(tech, [])
        caps = sorted({c for c in caps if isinstance(c, str)}) if isinstance(caps, (list, tuple, set)) else []
        candidate_details.append({
            "technique": tech,
            "score": candidate_scores[tech],
            "sources": [SOURCE_CAPABILITY],
            "status": "candidate",
            "derived_from_capabilities": caps,
        })

    # -------------------------
    # Preserve tactics from behaviour engine
    # -------------------------
    tactics = behaviour_mitre.get("tactics", {})

    result = {
        "mitre_techniques": ranked,
        "final_mitre": list(ranked),  # alias for backward compatibility
        "scores": supported_scores,
        "total_techniques": len(ranked),
        "tactics": tactics,
        "sources": {t: list(sources[t]) for t in ranked},
        "support_level": support_level,
        "mitre_candidates": candidate_ranked,
        "candidate_scores": candidate_scores,
        "candidate_details": candidate_details,
        "total_candidates": len(candidate_ranked),
    }

    if not ranked:
        result["message"] = (
            "No evidence-supported MITRE techniques; capability-derived "
            "candidates only"
        )

    debug_log("[FUSION] Merged MITRE techniques", {
        "supported": len(ranked),
        "candidates": len(candidate_ranked),
        "from_behavior": len(behaviour_ids),
        "from_capability": len(cap_scores) if isinstance(cap_scores, dict) else 0,
    })

    debug_log("[FUSION] Supported scores", supported_scores)
    debug_log("[FUSION] Candidate scores", candidate_scores)

    return result


def validate_mitre_deduplication(fusion_result: dict) -> dict:
    """
    Validate that MITRE fusion result has no duplicates.
    
    Args:
        fusion_result: Output from merge_mitre_results()
        
    Returns:
        {
            "valid": bool,
            "duplicate_count": int,
            "duplicates": list[str]
        }
    """
    techniques = fusion_result.get("mitre_techniques", [])
    
    seen = set()
    duplicates = []
    
    for tech in techniques:
        if tech in seen:
            duplicates.append(tech)
        else:
            seen.add(tech)
    
    result = {
        "valid": len(duplicates) == 0,
        "duplicate_count": len(duplicates),
        "duplicates": duplicates
    }
    
    if not result["valid"]:
        debug_log("[VALIDATION] MITRE duplicates detected", result)
    
    return result


def merge_capability_lists(
    behavior_capabilities: List[str],
    capa_capabilities: List[str]
) -> List[str]:
    """
    Merge capability lists from behavior and CAPA engines.
    
    Simple set union with deduplication.
    
    Args:
        behavior_capabilities: List from behavior->capability mapping
        capa_capabilities: List from CAPA analysis
        
    Returns:
        Deduplicated merged list, sorted
    """
    all_capabilities = set()
    
    if behavior_capabilities:
        all_capabilities.update(behavior_capabilities)
    
    if capa_capabilities:
        all_capabilities.update(capa_capabilities)
    
    return sorted(list(all_capabilities))
