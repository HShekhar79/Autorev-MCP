"""Focused tests for the conservative CAPA -> canonical translation layer.

Uses the REAL project utils.normalization (no stubs, mocks, or monkeypatching).
Run from backend/:  python -m pytest -q test_capa_translation.py
"""
from engines.capa_engine.capa_engine import (
    CAPA_NOT_PROMOTED,
    CAPA_TO_CANONICAL,
    parse_capa_results,
    translate_capa_name,
)

SAFE = [
    ("allocate_memory", "memory_allocation"),
    ("change_memory_protection", "memory_protection_change"),
    ("connect_socket", "network_communication"),
    ("act_as_tcp_client", "network_communication"),
    ("execute_command", "command_execution"),
    ("persist_via_run_registry_key", "registry_persistence"),
    ("inject_into_process", "process_injection"),
    ("hollow_process", "process_hollowing"),
    ("create_remote_thread", "process_injection"),
    ("create_or_open_file", "file_creation"),
]

UNSAFE = [
    ("reference_google_public_dns_server", "dns_activity"),
    ("delay_execution", "command_execution"),
    ("execute_shellcode_via_indirect_call", "indirect_call_execution"),
    ("reference_anti_vm_strings", "anti_vm"),
    ("contain_loop", "indirect_call_execution"),
    ("contain_a_thread_local_storage_(.tls)_section", "indirect_call_execution"),
    ("get_thread_local_storage_value", "indirect_call_execution"),
    ("calculate_modulo_256_via_x86_assembly", "indirect_call_execution"),
    ("terminate_process", "process_termination"),
    ("parse_pe_header", "dynamic_loading"),
    ("enumerate_pe_sections", "dynamic_loading"),
]

# Raw CAPA rule names as CAPA prints them (spaces / hyphens / mixed case).
RAW_NOT_PROMOTED = [
    "reference Google Public DNS server",
    "delay execution",
    "execute shellcode via indirect call",
    "reference anti-VM strings",
    "contain loop",
    "contain a thread local storage (.tls) section",
    "get thread local storage value",
    "calculate modulo 256 via x86 assembly",
    "terminate process",
    "parse PE header",
    "enumerate PE sections",
]


def _rule(name, technique=None, location="0x401000"):
    meta = {"name": name}
    if technique:
        meta["att&ck"] = [
            {"id": technique, "tactic": "Defense Evasion", "technique": "Test technique"}
        ]
    return {"meta": meta, "matches": {location: {"type": "match"}}}


# ---------------------------------------------------------- translate_capa_name
def test_supported_translations_unchanged():
    for name, expected in SAFE:
        assert translate_capa_name(name) == expected, name


def test_not_promoted_names_return_empty_string():
    for name, _ in UNSAFE:
        assert translate_capa_name(name) == "", name


def test_not_promoted_raw_capa_spellings_return_empty_string():
    for raw in RAW_NOT_PROMOTED:
        assert translate_capa_name(raw) == "", raw


def test_unsupported_names_not_promoted_to_old_behaviors():
    for name, forbidden in UNSAFE:
        assert translate_capa_name(name) != forbidden, name


def test_removed_keys_absent_from_map():
    for name, _ in UNSAFE:
        assert name not in CAPA_TO_CANONICAL, name


def test_not_promoted_set_is_exactly_the_11_names():
    assert CAPA_NOT_PROMOTED == frozenset(n for n, _ in UNSAFE)


def test_registry_mapping_left_unchanged():
    assert CAPA_TO_CANONICAL["create_or_open_registry_key"] == "registry_persistence"


def test_empty_input_still_returns_empty_string():
    assert translate_capa_name("") == ""
    assert translate_capa_name(None) == ""


# ------------------------------------------------ normalized_capabilities output
def test_non_promoted_rule_never_reaches_normalized_capabilities():
    data = {"rules": {
        "reference anti-VM strings": _rule("reference anti-VM strings", "T1497.001"),
        "persist via Run registry key": _rule("persist via Run registry key", "T1547.001", "0x402000"),
        "allocate memory": _rule("allocate memory", None, "0x403000"),
    }}
    result = parse_capa_results(data)

    names = [c["name"] for c in result["normalized_capabilities"]]
    assert names == ["registry_persistence", "memory_allocation"]
    assert "reference_anti_vm_strings" not in names
    assert "" not in names
    assert result["capabilities"] == names
    assert result["capabilities_detected"] == 2
    for c in result["normalized_capabilities"]:
        assert set(c) == {"name", "source", "confidence"}
        assert c["source"] == "capa" and c["confidence"] == 0.9


def test_all_non_promoted_rules_together_yield_no_capabilities():
    data = {"rules": {r: _rule(r, None, "0x40%04x" % i) for i, r in enumerate(RAW_NOT_PROMOTED)}}
    result = parse_capa_results(data)
    assert result["status"] == "success"
    assert result["normalized_capabilities"] == []
    assert result["capabilities"] == []
    assert result["capabilities_detected"] == 0


def test_list_format_rules_behave_the_same():
    data = {"rules": [
        _rule("terminate process", "T1106"),
        _rule("act as TCP client", None, "0x402000"),
    ]}
    names = [c["name"] for c in parse_capa_results(data)["normalized_capabilities"]]
    assert names == ["network_communication"]


# -------------------------------- raw evidence / MITRE behaviour is unchanged
def test_mitre_and_raw_evidence_for_non_promoted_rule_unchanged():
    data = {"rules": {
        "reference anti-VM strings": _rule("reference anti-VM strings", "T1497.001"),
    }}
    result = parse_capa_results(data)

    assert result["normalized_capabilities"] == []
    # MITRE technique still extracted
    assert result["mitre_techniques"] == ["T1497.001"]
    # raw CAPA evidence keeps the cleaned rule name (never an empty key)
    assert result["capability_details"] == [{
        "capability": "reference_anti_vm_strings",
        "mitre_id": "T1497.001",
        "tactic": "Defense Evasion",
        "technique": "Test technique",
    }]
    assert result["capability_to_mitre"] == {"reference_anti_vm_strings": ["T1497.001"]}
    assert result["behaviour_to_mitre"] == result["capability_to_mitre"]
    assert result["function_capabilities"] == {"0x401000": ["reference_anti_vm_strings"]}
    assert "" not in result["capability_to_mitre"]
    for caps in result["function_capabilities"].values():
        assert "" not in caps
