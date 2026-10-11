"""
Focused tests: evidence-supported MITRE findings vs capability-only candidates.

Run from the backend directory:
    python -m pytest tests/test_mitre_evidence_separation.py -v
"""

import pytest

from engines.capability_mitre_engine.capability_mitre_engine import (
    CAPABILITY_MITRE_MAP,
    CapabilityMitreEngine,
)
from engines.fusion_engine.fusion_engine import merge_mitre_results
from engines.mitre_engine.mitre_engine import (
    MITRE_LOOKUP,
    map_behaviour_to_mitre,
)
from engines.scoring_engine.scoring_engine import calculate_combined_risk


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _behaviour_mitre(*techniques, tactics=None):
    return {
        "mitre_techniques": sorted(techniques),
        "tactics": tactics or {},
        "total_techniques": len(techniques),
    }


def _capability_mitre(capabilities, scores=None):
    return CapabilityMitreEngine().run(capabilities, scores or {})


def _mapped_techniques(behaviour):
    return {t for _tactic, techs in MITRE_LOOKUP.get(behaviour, []) for t in techs}


def _risk(mitre_result):
    return calculate_combined_risk(
        features={}, function_results=[], import_behaviours=[],
        mitre_result=mitre_result,
    )


# ---------------------------------------------------------------------------
# 1. behaviour-only technique stays a final finding
# ---------------------------------------------------------------------------
def test_behavior_only_technique_stays_in_final_mitre():
    fused = merge_mitre_results(_behaviour_mitre("T1055"), _capability_mitre([]))

    assert fused["final_mitre"] == ["T1055"]
    assert fused["mitre_techniques"] == ["T1055"]
    assert fused["sources"] == {"T1055": ["behavior"]}
    assert fused["support_level"] == {"T1055": "behavior"}
    assert fused["mitre_candidates"] == []


def test_behavior_evidence_is_sufficient_without_any_capability():
    fused = merge_mitre_results(_behaviour_mitre("T1622"), {})
    assert "T1622" in fused["final_mitre"]
    assert fused["scores"]["T1622"] == 1.5


# ---------------------------------------------------------------------------
# 2. capability-only technique -> candidates, NOT final
# ---------------------------------------------------------------------------
def test_capability_only_technique_is_candidate_not_final():
    cap = _capability_mitre(["credential_access"], {"credential_access": 2.5})
    fused = merge_mitre_results(_behaviour_mitre(), cap)

    assert fused["final_mitre"] == []
    assert fused["mitre_techniques"] == []
    assert fused["scores"] == {}
    assert fused["total_techniques"] == 0
    assert fused["mitre_candidates"] == ["T1003"]
    assert fused["candidate_scores"] == {"T1003": 2.5}
    assert "T1003" not in fused["sources"]

    detail = fused["candidate_details"][0]
    assert detail["technique"] == "T1003"
    assert detail["sources"] == ["capability"]
    assert detail["status"] == "candidate"
    assert detail["derived_from_capabilities"] == ["credential_access"]


def test_mixed_supported_and_candidates_are_disjoint():
    cap = _capability_mitre(["execution", "discovery"],
                            {"execution": 2.0, "discovery": 1.0})
    fused = merge_mitre_results(_behaviour_mitre("T1059", "T1082"), cap)

    assert set(fused["final_mitre"]) == {"T1059", "T1082"}
    assert set(fused["mitre_candidates"]) == {"T1204", "T1057"}
    assert not set(fused["final_mitre"]) & set(fused["mitre_candidates"])


# ---------------------------------------------------------------------------
# 3. technique in both sources -> final with both sources
# ---------------------------------------------------------------------------
def test_corroborated_technique_keeps_both_sources_in_final():
    cap = _capability_mitre(["defense_evasion"], {"defense_evasion": 2.4})
    fused = merge_mitre_results(_behaviour_mitre("T1055"), cap)

    assert "T1055" in fused["final_mitre"]
    assert fused["sources"]["T1055"] == ["behavior", "capability"]
    assert fused["support_level"]["T1055"] == "corroborated"
    assert "T1055" not in fused["mitre_candidates"]
    # MAX, never a sum (behaviour base 1.5, capability 2.4)
    assert fused["scores"]["T1055"] == 2.4
    # the other defense_evasion technique has no behaviour support
    assert "T1027" in fused["mitre_candidates"]
    assert "T1027" not in fused["final_mitre"]


def test_corroboration_does_not_lower_behavior_score():
    cap = _capability_mitre(["defense_evasion"], {"defense_evasion": 0.5})
    fused = merge_mitre_results(_behaviour_mitre("T1055"), cap)
    assert fused["scores"]["T1055"] == 1.5


# ---------------------------------------------------------------------------
# 4. capability-only candidates must not raise mitre_bonus
# ---------------------------------------------------------------------------
def test_capability_only_candidates_do_not_increase_mitre_bonus():
    many_caps = list(CAPABILITY_MITRE_MAP.keys())
    cap = _capability_mitre(many_caps, {c: 3.0 for c in many_caps})

    no_evidence = merge_mitre_results(_behaviour_mitre(), cap)
    assert len(no_evidence["mitre_candidates"]) > 10
    assert _risk(no_evidence)["mitre_bonus"] == 0
    assert _risk(no_evidence)["combined_score"] == _risk({})["combined_score"]


def test_bonus_counts_supported_only_and_matches_with_or_without_candidates():
    behaviour = _behaviour_mitre("T1055", "T1082")
    with_caps = merge_mitre_results(
        behaviour, _capability_mitre(["impact", "exfiltration", "persistence"]))
    without_caps = merge_mitre_results(behaviour, {})

    assert _risk(with_caps)["mitre_bonus"] == 4
    assert _risk(with_caps)["mitre_bonus"] == _risk(without_caps)["mitre_bonus"]


def test_scoring_ignores_candidate_keys_directly():
    result = {"mitre_techniques": ["T1055"], "mitre_candidates": ["T1003", "T1486"]}
    assert _risk(result)["mitre_bonus"] == 2


def test_bonus_still_capped_at_20_and_formula_unchanged():
    ids = [f"T{1000 + i}" for i in range(15)]
    assert _risk({"mitre_techniques": ids})["mitre_bonus"] == 20
    # int(20 * 0.20) with all other inputs zero
    assert _risk({"mitre_techniques": ids})["combined_score"] == 4


def test_scoring_dedupes_ids_and_falls_back_to_final_mitre():
    assert _risk({"mitre_techniques": ["T1055", "T1055"]})["mitre_bonus"] == 2
    assert _risk({"final_mitre": ["T1055", "T1082"]})["mitre_bonus"] == 4


# ---------------------------------------------------------------------------
# 5. conservative behaviour->MITRE mappings intact
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("behaviour, expected", [
    ("process_injection", {"T1055"}),
    ("process_hollowing", {"T1055.012"}),
    ("command_execution", {"T1059", "T1059.003"}),
    ("registry_persistence", {"T1547", "T1547.001"}),
    ("registry_modification", {"T1112"}),
    ("system_discovery", {"T1082"}),
    ("system_information_discovery", {"T1082"}),
    ("process_enumeration", {"T1057"}),
    ("anti_debugging", {"T1622"}),
])
def test_conservative_mappings_remain(behaviour, expected):
    assert _mapped_techniques(behaviour) == expected


@pytest.mark.parametrize("behaviour", [
    "memory_allocation",
    "memory_protection_change",
    "file_creation",
    "file_modification",
    "dynamic_loading",
    "dynamic_api_resolution",
    "network_activity",
    "network_communication",
])
def test_over_broad_behaviours_remain_unmapped(behaviour):
    assert behaviour not in MITRE_LOOKUP
    result = map_behaviour_to_mitre({"behaviors": [behaviour]})
    assert result["mitre_techniques"] == []


def test_capability_map_itself_is_unchanged():
    assert CAPABILITY_MITRE_MAP["execution"] == ["T1059", "T1204"]
    assert CAPABILITY_MITRE_MAP["impact"] == ["T1485", "T1486"]
    assert CAPABILITY_MITRE_MAP["privilege_escalation"] == ["T1068", "T1134"]


# ---------------------------------------------------------------------------
# 6. empty / malformed input is safe
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("beh, cap", [
    ({}, {}),
    (None, None),
    ({"mitre_techniques": []}, {"scores": {}}),
    ({"mitre_techniques": None}, {"scores": None}),
])
def test_empty_input_is_safe(beh, cap):
    fused = merge_mitre_results(beh, cap)
    assert fused["final_mitre"] == []
    assert fused["mitre_techniques"] == []
    assert fused["mitre_candidates"] == []
    assert fused["candidate_details"] == []
    assert fused["sources"] == {}
    assert fused["total_techniques"] == 0
    assert fused["total_candidates"] == 0
    assert _risk(fused)["mitre_bonus"] == 0


def test_malformed_entries_are_ignored():
    fused = merge_mitre_results(
        {"mitre_techniques": ["T1055", None, 7, ""]},
        {"scores": {"T1003": "not-a-number", "": 1.0, 5: 1.0, "T1071": float("nan")}},
    )
    assert fused["final_mitre"] == ["T1055"]
    assert fused["mitre_candidates"] == ["T1003", "T1071"]
    assert fused["candidate_scores"] == {"T1003": 0.0, "T1071": 0.0}


def test_capability_engine_empty_and_unknown_are_safe():
    for caps in ([], None, ["not_a_capability"], [123, None]):
        out = CapabilityMitreEngine().run(caps, {})
        assert out["mitre_techniques"] == []
        assert out["scores"] == {}
        assert out["ranked"] == []


# ---------------------------------------------------------------------------
# 7. backward-compatible fields
# ---------------------------------------------------------------------------
def test_fusion_keeps_all_legacy_fields():
    cap = _capability_mitre(["execution"], {"execution": 2.0})
    fused = merge_mitre_results(
        _behaviour_mitre("T1059", tactics={"execution": ["T1059"]}), cap)

    for key in ("mitre_techniques", "final_mitre", "scores",
                "total_techniques", "tactics", "sources"):
        assert key in fused
    assert fused["mitre_techniques"] == fused["final_mitre"]
    assert fused["total_techniques"] == len(fused["final_mitre"])
    assert fused["tactics"] == {"execution": ["T1059"]}
    assert set(fused["scores"]) == set(fused["final_mitre"])


def test_empty_fusion_keeps_legacy_fields_and_message():
    fused = merge_mitre_results({}, {})
    for key in ("mitre_techniques", "final_mitre", "scores",
                "total_techniques", "tactics", "sources", "message"):
        assert key in fused


def test_raw_capability_output_keeps_legacy_fields_and_adds_provenance():
    out = _capability_mitre(["execution", "discovery"], {"execution": 2.0})
    for key in ("mitre_techniques", "scores", "ranked"):
        assert key in out
    assert out["derived_from"]["T1059"] == ["execution"]
    assert out["derived_from"]["T1057"] == ["discovery"]
    assert out["scores"]["T1059"] == 2.0
    assert out["scores"]["T1082"] == 1.0  # default when score missing


def test_combined_risk_keeps_legacy_fields():
    risk = _risk({"mitre_techniques": ["T1055"]})
    for key in ("combined_score", "static_score", "import_score",
                "function_max_score", "mitre_bonus"):
        assert key in risk


# ---------------------------------------------------------------------------
# 8. stable deterministic ordering
# ---------------------------------------------------------------------------
def test_ordering_is_deterministic_regardless_of_input_order():
    caps_a = ["impact", "execution", "discovery", "persistence"]
    scores = {"impact": 3.0, "execution": 2.0, "discovery": 2.0, "persistence": 1.0}

    a = merge_mitre_results(_behaviour_mitre("T1082", "T1055", "T1059"),
                            _capability_mitre(caps_a, scores))
    b = merge_mitre_results(
        {"mitre_techniques": ["T1059", "T1055", "T1082"], "tactics": {}},
        _capability_mitre(list(reversed(caps_a)), scores))

    assert a == b
    assert merge_mitre_results(_behaviour_mitre("T1082", "T1055", "T1059"),
                               _capability_mitre(caps_a, scores)) == a


def test_ranking_is_score_desc_then_id_asc():
    cap = _capability_mitre(["impact", "execution", "exfiltration"],
                            {"impact": 3.0, "execution": 2.0, "exfiltration": 2.0})
    fused = merge_mitre_results(_behaviour_mitre(), cap)

    assert fused["mitre_candidates"] == ["T1485", "T1486", "T1041", "T1059", "T1204"]
    assert [d["technique"] for d in fused["candidate_details"]] == fused["mitre_candidates"]

    supported = merge_mitre_results(_behaviour_mitre("T1622", "T1055", "T1082"), {})
    assert supported["final_mitre"] == ["T1055", "T1082", "T1622"]  # equal scores -> by ID
