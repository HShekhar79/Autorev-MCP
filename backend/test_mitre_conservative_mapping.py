"""Regression: conservative MITRE mapping (behaviour evidence != ATT&CK proof).

Run from backend/:  python -m pytest -q test_mitre_conservative_mapping.py
Uses the real project modules (no stubs, mocks, or monkeypatching).

Generic behaviours are only mapped to an ATT&CK technique when the behaviour name
itself establishes the technique. Process injection, reflective code loading,
application-layer protocol use and automated collection need context/correlation,
so the generic behaviours below are deliberately left unmapped.
"""
from engines.mitre_engine.mitre_engine import (
    MITRE_DATABASE,
    MITRE_LOOKUP,
    map_behaviour_to_mitre,
)
from utils.normalization import normalize_behavior

# Exact expected database: the previous database minus the 8 corrected entries.
# Any unrelated mapping change makes test_database_matches_reviewed_snapshot fail.
EXPECTED_DATABASE = {'execution': {'command_execution': ['T1059', 'T1059.003'],
               'powershell': ['T1059.001']},
 'persistence': {'registry_persistence': ['T1547', 'T1547.001'],
                 'startup_persistence': ['T1547.001'],
                 'service_creation': ['T1543', 'T1543.003'],
                 'scheduled_task_creation': ['T1053.005']},
 'defense_evasion': {'anti_debugging': ['T1622'],
                     'anti_vm': ['T1497'],
                     'anti_sandbox': ['T1497'],
                     'process_hollowing': ['T1055.012'],
                     'process_injection': ['T1055'],
                     'packing_detection': ['T1027.002'],
                     'registry_modification': ['T1112']},
 'credential_access': {'credential_dumping': ['T1003'],
                       'keylogging': ['T1056'],
                       'token_manipulation': ['T1134']},
 'discovery': {'system_discovery': ['T1082'],
               'system_information_discovery': ['T1082'],
               'process_enumeration': ['T1057'],
               'module_enumeration': ['T1057'],
               'user_enumeration': ['T1033'],
               'directory_enumeration': ['T1083'],
               'registry_query': ['T1012']},
 'collection': {'keylogging': ['T1056']},
 'exfiltration': {'data_exfiltration': ['T1041']},
 'command_and_control': {'payload_download': ['T1105']},
 'impact': {'file_deletion': ['T1485'],
            'shutdown_system': ['T1529'],
            'reboot_system': ['T1529']},
 'privilege_escalation': {'token_manipulation': ['T1134']}}

UNMAPPED = [
    "memory_allocation", "memory_protection_change",
    "file_creation", "file_modification",
    "dynamic_loading", "dynamic_api_resolution",
    "network_activity", "network_communication",
]


def _techniques(*behaviours):
    return map_behaviour_to_mitre(list(behaviours))["mitre_techniques"]


# ------------------------------------------------------------ corrected mappings
def test_memory_behaviours_do_not_produce_t1055():
    assert "T1055" not in _techniques("memory_allocation")
    assert "T1055" not in _techniques("memory_protection_change")
    assert _techniques("memory_allocation", "memory_protection_change") == []


def test_file_behaviours_do_not_produce_t1119():
    assert "T1119" not in _techniques("file_creation")
    assert "T1119" not in _techniques("file_modification")
    assert _techniques("file_creation", "file_modification") == []


def test_dynamic_loading_behaviours_do_not_produce_t1027_or_t1620():
    for behaviour in ["dynamic_loading", "dynamic_api_resolution"]:
        techniques = _techniques(behaviour)
        assert "T1027" not in techniques, behaviour
        assert "T1620" not in techniques, behaviour
        assert techniques == [], behaviour


def test_network_behaviours_do_not_produce_t1071():
    assert "T1071" not in _techniques("network_activity")
    assert "T1071" not in _techniques("network_communication")
    assert _techniques("network_activity", "network_communication") == []


def test_corrected_behaviours_are_absent_from_lookup_and_reported_unmapped():
    for behaviour in UNMAPPED:
        assert behaviour not in MITRE_LOOKUP, behaviour
        result = map_behaviour_to_mitre([behaviour])
        assert result["mitre_techniques"] == []
        assert result["tactics"] == {}
        assert result["total_techniques"] == 0
        assert result["behaviour_mitre_detail"] == [
            {"behavior": behaviour, "mitre": [], "note": "no mitre mapping"}
        ], behaviour


# ----------------------------------------------------- mappings that must remain
def test_process_injection_and_hollowing_still_mapped():
    assert _techniques("process_injection") == ["T1055"]
    assert _techniques("process_hollowing") == ["T1055.012"]
    assert map_behaviour_to_mitre(["process_injection"])["tactics"] == {
        "defense_evasion": ["T1055"]
    }


def test_existing_valid_mappings_unchanged():
    expected = {
        "command_execution": ["T1059", "T1059.003"],
        "registry_persistence": ["T1547", "T1547.001"],
        "registry_modification": ["T1112"],
        "system_discovery": ["T1082"],
        "system_information_discovery": ["T1082"],
        "process_enumeration": ["T1057"],
        "anti_debugging": ["T1622"],
        "payload_download": ["T1105"],
        "file_deletion": ["T1485"],
        "credential_dumping": ["T1003"],
    }
    for behaviour, techniques in expected.items():
        assert _techniques(behaviour) == techniques, behaviour


def test_database_matches_reviewed_snapshot():
    assert MITRE_DATABASE == EXPECTED_DATABASE

def test_remote_execution_does_not_claim_t1021_without_evidence():
    assert normalize_behavior("remote_execution") == "remote_execution"
    assert "remote_execution" not in MITRE_LOOKUP

    result = map_behaviour_to_mitre(["remote_execution"])

    assert result["mitre_techniques"] == []
    assert result["tactics"] == {}
    assert result["total_techniques"] == 0
    assert result["behaviour_mitre_detail"] == [
        {
            "behavior": "remote_execution",
            "mitre": [],
            "note": "no mitre mapping",
        }
    ]

# ------------------------------------------------------------ combined / contract
def test_reference_style_behaviour_set_only_yields_justified_techniques():
    # Behaviours named for test_mitre.c (synthetic reference sample). This pins the
    # mapping decisions only; it is not an accuracy claim.
    behaviours = [
        "memory_allocation", "memory_protection_change",
        "dynamic_loading", "dynamic_api_resolution",
        "network_communication", "network_activity",
        "file_creation", "file_modification",
        "registry_persistence", "command_execution",
        "anti_debugging", "system_discovery", "process_enumeration",
    ]
    result = map_behaviour_to_mitre(behaviours)
    assert result["mitre_techniques"] == [
        "T1057", "T1059", "T1059.003", "T1082", "T1547", "T1547.001", "T1622",
    ]
    for forbidden in ["T1055", "T1119", "T1027", "T1620", "T1071"]:
        assert forbidden not in result["mitre_techniques"], forbidden
    unmapped = {
        d["behavior"] for d in result["behaviour_mitre_detail"]
        if d.get("note") == "no mitre mapping"
    }
    assert unmapped == set(UNMAPPED)


def test_output_schema_sorted_and_input_shapes_unchanged():
    behaviours = ["process_injection", "command_execution", "memory_allocation"]
    from_list = map_behaviour_to_mitre(behaviours)
    from_dict = map_behaviour_to_mitre({"behaviors": behaviours})
    from_dicts = map_behaviour_to_mitre([{"name": b} for b in behaviours])

    assert set(from_list) == {
        "mitre_techniques", "tactics", "total_techniques", "behaviour_mitre_detail",
    }
    assert from_list == from_dict == from_dicts
    assert from_list["mitre_techniques"] == sorted(from_list["mitre_techniques"])
    assert from_list["total_techniques"] == len(from_list["mitre_techniques"])
    for techniques in from_list["tactics"].values():
        assert techniques == sorted(techniques)
    assert map_behaviour_to_mitre(behaviours) == from_list  # deterministic


def test_empty_input_contract_unchanged():
    assert map_behaviour_to_mitre([]) == {
        "mitre_techniques": [],
        "tactics": {},
        "total_techniques": 0,
        "behaviour_mitre_detail": [],
    }

def test_indirect_call_execution_is_unmapped_observational_fallback():
    # Benign/observational fallback (risk weight 0) must not assert ATT&CK T1059.
    assert _techniques("indirect_call_execution") == []
    assert "indirect_call_execution" not in MITRE_LOOKUP
    result = map_behaviour_to_mitre(["indirect_call_execution"])
    assert result["mitre_techniques"] == []
    assert result["tactics"] == {}
    assert result["total_techniques"] == 0
    assert result["behaviour_mitre_detail"] == [
        {
            "behavior": "indirect_call_execution",
            "mitre": [],
            "note": "no mitre mapping",
        }
    ]
    # Genuine command_execution keeps its T1059 mapping.
    assert _techniques("command_execution") == ["T1059", "T1059.003"]



REMOVED_DIRECT_MAPPINGS = [
    "process_creation", "random_generation", "file_copy", "file_move",
    "cryptographic_activity", "command_and_control", "http_communication",
    "ftp_communication", "dns_activity", "data_encryption",
    "process_termination", "privilege_escalation",
]


def test_removed_direct_mappings_assert_no_mitre_techniques():
    # API-level behaviour evidence alone does not establish these ATT&CK techniques.
    # The engine reports the NORMALIZED behaviour name (e.g. data_encryption is an
    # alias of cryptographic_activity), so the expectation is derived from the
    # project's own normalize_behavior() rather than hardcoded.
    for behaviour in REMOVED_DIRECT_MAPPINGS:
        canonical = normalize_behavior(behaviour)
        assert canonical, behaviour
        assert behaviour not in MITRE_LOOKUP, behaviour
        assert canonical not in MITRE_LOOKUP, behaviour
        assert _techniques(behaviour) == [], behaviour
        result = map_behaviour_to_mitre([behaviour])
        assert result["mitre_techniques"] == [], behaviour
        assert result["tactics"] == {}, behaviour
        assert result["total_techniques"] == 0, behaviour
        assert result["behaviour_mitre_detail"] == [
            {"behavior": canonical, "mitre": [], "note": "no mitre mapping"}
        ], behaviour

    # ftp_communication is gone from every tactic, not just one.
    for tactic_map in MITRE_DATABASE.values():
        assert "ftp_communication" not in tactic_map
