"""
engines/fusion_engine.py

MITRE technique fusion with deduplication and optional weighting.

FIXES:
1. Prevent duplicate MITRE IDs when combining behavior + capability MITRE
2. Add optional weighting (capability MITRE scores > behavior MITRE scores)
3. Safe empty-case handling
4. Preserve all existing output fields for backward compatibility

Fusion strategy:
    - Behavior MITRE: base score 1.5
    - Capability MITRE: uses capability engine scores (typically 2-3)
    - Final score: MAX of all sources (no addition to prevent inflation)
"""

from utils.debug import debug_log
from typing import Dict, Any, List, Optional


def merge_mitre_results(
    behaviour_mitre: dict,
    capability_mitre: dict,
    weight_capabilities: bool = True
) -> dict:
    """
    Merge MITRE techniques from behavior and capability engines.
    
    Deduplicates MITRE IDs and combines scores using MAX strategy
    to prevent score inflation from duplicate detections.
    
    Args:
        behaviour_mitre: Output from mitre_engine.map_behaviour_to_mitre()
        capability_mitre: Output from capability_mitre_engine.run()
        weight_capabilities: If True, give capability MITRE higher weight
        
    Returns:
        {
            "mitre_techniques": list[str],      # sorted unique IDs
            "final_mitre": list[str],           # alias for compatibility
            "scores": dict[str, float],         # technique -> score
            "total_techniques": int,
            "tactics": dict[str, list[str]],    # preserved from behavior
            "sources": dict[str, list[str]]     # ✅ NEW: technique -> sources
        }
    """
    behaviour_mitre = behaviour_mitre or {}
    capability_mitre = capability_mitre or {}

    final_scores = {}
    technique_sources = {}  # ✅ NEW: track which engine detected each technique

    # -------------------------
    # 1. Behaviour MITRE
    # -------------------------
    behaviour_list = behaviour_mitre.get("mitre_techniques", [])

    if isinstance(behaviour_list, list):
        for tech in behaviour_list:
            if isinstance(tech, str) and tech:
                # Base score for behavior detections
                base_score = 1.5 if weight_capabilities else 2.0
                final_scores[tech] = max(final_scores.get(tech, 0.0), base_score)
                
                # Track source
                if tech not in technique_sources:
                    technique_sources[tech] = []
                technique_sources[tech].append("behavior")

    # -------------------------
    # 2. Capability MITRE
    # -------------------------
    cap_scores = capability_mitre.get("scores", {})

    if isinstance(cap_scores, dict):
        for tech, score in cap_scores.items():
            if not isinstance(tech, str) or not tech:
                continue

            try:
                score = float(score)
            except Exception:
                score = 0.0

            # Use MAX to prevent inflation
            final_scores[tech] = max(final_scores.get(tech, 0.0), score)
            
            # Track source
            if tech not in technique_sources:
                technique_sources[tech] = []
            if "capability" not in technique_sources[tech]:
                technique_sources[tech].append("capability")

    # -------------------------
    # EMPTY SAFE CASE
    # -------------------------
    if not final_scores:
        return {
            "mitre_techniques": [],
            "final_mitre": [],
            "scores": {},
            "total_techniques": 0,
            "tactics": {},
            "sources": {},
            "message": "No MITRE techniques detected"
        }

    # -------------------------
    # Normalize scores
    # -------------------------
    final_scores = {
        t: round(s, 2)
        for t, s in final_scores.items()
    }

    # -------------------------
    # Sort (descending by score, then alphabetically)
    # -------------------------
    ranked = sorted(
        final_scores.keys(),
        key=lambda t: (-final_scores[t], t)
    )

    # -------------------------
    # Preserve tactics from behavior engine
    # -------------------------
    tactics = behaviour_mitre.get("tactics", {})

    result = {
        "mitre_techniques": ranked,
        "final_mitre": ranked,  # alias for backward compatibility
        "scores": final_scores,
        "total_techniques": len(ranked),
        "tactics": tactics,
        "sources": technique_sources  # ✅ NEW: source attribution
    }

    debug_log("[FUSION] Merged MITRE techniques", {
        "total": len(ranked),
        "from_behavior": len(behaviour_list) if isinstance(behaviour_list, list) else 0,
        "from_capability": len(cap_scores) if isinstance(cap_scores, dict) else 0,
        "deduplicated": len(ranked)
    })

    debug_log("[FUSION] Final scores", final_scores)

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
