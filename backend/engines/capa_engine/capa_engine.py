"""
engines/capa_engine/capa_engine.py

CAPA integration engine.

ROOT CAUSE FIX:
    CAPA produces descriptive rule names like "persist_via_run_registry_key",
    "act_as_tcp_client", "allocate_memory" etc. These are NOT in CANONICAL_BEHAVIORS
    and NOT in NORMALIZATION_MAP, so they passed through normalize_behavior()
    unchanged and were never recognized by CapabilityEngine.mapping.

    Fix: Added CAPA_TO_CANONICAL translation map applied during normalization
    of CAPA output, converting CAPA rule names to canonical behavior names
    BEFORE they enter the capability pipeline.
"""

import subprocess
import json
import os
from typing import Dict, List, Any

from utils.normalization import normalize_behavior
from utils.debug import debug_log


# =============================================================================
# CAPA RULE NAME → CANONICAL BEHAVIOR TRANSLATION MAP
#
# CAPA produces long descriptive rule names. This map translates them to the
# canonical snake_case behavior names used throughout the pipeline.
# Applied BEFORE normalize_behavior() so the canonical name passes correctly
# through CapabilityEngine.mapping and MITRE lookup.
# =============================================================================

CAPA_TO_CANONICAL: Dict[str, str] = {
    # ── Network ──────────────────────────────────────────────────────────────
    "act_as_tcp_client":                            "network_communication",
    "create_tcp_socket":                            "network_communication",
    "connect_tcp_socket":                           "network_communication",
    "connect_socket":                               "network_communication",
    "create_socket":                                "network_communication",
    "create_udp_socket":                            "network_communication",
    "act_as_udp_client":                            "network_communication",
    "receive_data_on_socket":                       "network_communication",
    "send_data_on_socket":                          "data_exfiltration",
    "initialize_winsock_library":                   "network_activity",
    "resolve_dns":                                  "dns_activity",
    "get_hostname":                                 "system_discovery",
    "reference_google_public_dns_server":           "dns_activity",
    "download_url":                                 "payload_download",
    "communicate_using_http":                       "http_communication",
    "communicate_using_https":                      "http_communication",
    "communicate_using_ftp":                        "ftp_communication",
    "send_and_receive_data_using_http":             "http_communication",

    # ── Memory ───────────────────────────────────────────────────────────────
    "allocate_memory":                              "memory_allocation",
    "allocate_heap_memory":                         "memory_allocation",
    "allocate_rwx_memory":                          "memory_allocation",
    "allocate_or_change_rwx_memory":                "memory_protection_change",
    "change_memory_protection":                     "memory_protection_change",
    "write_to_process_memory":                      "process_injection",
    "inject_shellcode":                             "process_injection",

    # ── Execution ─────────────────────────────────────────────────────────────
    "execute_command":                              "command_execution",
    "run_a_shell_command":                          "command_execution",
    "spawn_process":                                "process_creation",
    "create_process":                               "process_creation",
    "create_process_with_modified_environment":     "process_creation",
    "create_thread":                                "process_creation",
    "create_remote_thread":                         "process_injection",
    "delay_execution":                              "command_execution",
    "execute_shellcode":                            "process_injection",
    "execute_shellcode_via_indirect_call":          "indirect_call_execution",

    # ── Registry ─────────────────────────────────────────────────────────────
    "set_registry_value":                           "registry_modification",
    "create_or_open_registry_key":                  "registry_persistence",
    "persist_via_run_registry_key":                 "registry_persistence",
    "persist_via_runonce_registry_key":             "registry_persistence",
    "delete_registry_key":                          "registry_modification",
    "query_or_enumerate_registry_key":              "registry_query",
    "query_registry_value":                         "registry_query",

    # ── Filesystem ────────────────────────────────────────────────────────────
    "create_or_open_file":                          "file_creation",
    "write_file":                                   "file_modification",
    "write_file_on_windows":                        "file_modification",
    "read_file_on_windows":                         "file_creation",
    "copy_file":                                    "file_copy",
    "move_file":                                    "file_move",
    "delete_file":                                  "file_deletion",
    "enumerate_files":                              "directory_enumeration",
    "list_directory_contents":                      "directory_enumeration",

    # ── Process ───────────────────────────────────────────────────────────────
    "terminate_process":                            "process_termination",
    "enumerate_processes":                          "process_enumeration",
    "get_process_information":                      "process_enumeration",
    "inject_into_process":                          "process_injection",
    "hollow_process":                               "process_hollowing",

    # ── Discovery ─────────────────────────────────────────────────────────────
    "get_system_information_on_windows":            "system_information_discovery",
    "get_os_information":                           "system_information_discovery",
    "get_computer_name":                            "system_discovery",
    "get_username":                                 "system_discovery",
    "get_system_time":                              "system_discovery",
    "enumerate_network_interfaces":                 "system_discovery",
    "get_memory_status":                            "system_discovery",

    # ── Dynamic loading / obfuscation ─────────────────────────────────────────
    "link_function_at_runtime_on_windows":          "dynamic_loading",
    "resolve_function_by_hash":                     "dynamic_api_resolution",
    "load_library":                                 "dynamic_loading",
    "parse_pe_header":                              "dynamic_loading",
    "enumerate_pe_sections":                        "dynamic_loading",

    # ── Anti-analysis ─────────────────────────────────────────────────────────
    "reference_anti_vm_strings":                    "anti_vm",
    "detect_debugger":                              "anti_debugging",
    "check_for_debugger":                           "anti_debugging",
    "detect_virtual_machine":                       "anti_vm",
    "detect_sandbox":                               "anti_sandbox",
    "evade_analysis":                               "anti_debugging",

    # ── Persistence ───────────────────────────────────────────────────────────
    "persist_via_scheduled_task":                   "scheduled_task_creation",
    "install_service":                              "service_creation",
    "create_service":                               "service_creation",

    # ── Credentials ───────────────────────────────────────────────────────────
    "steal_credential":                             "credential_dumping",
    "dump_lsass_memory":                            "credential_dumping",
    "capture_keystrokes":                           "keylogging",

    # ── Crypto ────────────────────────────────────────────────────────────────
    "encrypt_data":                                 "cryptographic_activity",
    "decrypt_data":                                 "cryptographic_activity",
    "calculate_checksum":                           "cryptographic_activity",

    # ── Structural / misc (map to nearest semantic behavior) ──────────────────
    "contain_loop":                                 "indirect_call_execution",
    "contain_a_thread_local_storage_(.tls)_section": "indirect_call_execution",
    "get_thread_local_storage_value":               "indirect_call_execution",
    "calculate_modulo_256_via_x86_assembly":        "indirect_call_execution",
}


def translate_capa_name(raw_name: str) -> str:
    """
    Translate a raw CAPA rule name to a canonical behavior name.

    Pipeline:
        1. Clean and lowercase the raw CAPA name
        2. Check CAPA_TO_CANONICAL translation map (handles CAPA-specific names)
        3. Fall back to normalize_behavior() for any remaining cases
        4. Return the best available canonical form

    Args:
        raw_name: Raw CAPA rule name (e.g. "persist_via_run_registry_key")

    Returns:
        Canonical behavior name (e.g. "registry_persistence") or cleaned raw name
    """
    if not raw_name:
        return ""

    cleaned = str(raw_name).lower().strip().replace(" ", "_").replace("-", "_")

    # Step 1: CAPA-specific translation map
    if cleaned in CAPA_TO_CANONICAL:
        canonical = CAPA_TO_CANONICAL[cleaned]
        debug_log("[CAPA TRANSLATE]", "%r → %r" % (raw_name, canonical))
        return canonical

    # Step 2: Standard normalization (handles already-canonical names)
    normalized = normalize_behavior(raw_name)
    if normalized:
        return normalized

    # Step 3: Return cleaned form — preserves CAPA name in output
    # (still useful for deduplicated_capabilities, just won't map to a tactic)
    return cleaned


def _empty_result(status: str, reason: str, detail: str = "") -> dict:
    return {
        "status": status,
        "reason": reason,
        "detail": detail,
        "capabilities_detected": 0,
        "capabilities": [],
        "normalized_capabilities": [],
        "function_capabilities": {},
        "behaviour_to_mitre": {},
        "capability_to_mitre": {},
        "mitre_techniques": [],
        "capability_details": []
    }


def run_capa_analysis(binary_path: str) -> dict:
    """
    Run CAPA analysis on binary and return normalized results.

    Returns normalized_capabilities where each name is translated through
    CAPA_TO_CANONICAL so downstream CapabilityEngine receives canonical names.
    """
    try:
        PROJECT_ROOT = os.path.dirname(
            os.path.dirname(
                os.path.dirname(
                    os.path.dirname(os.path.abspath(__file__))
                )
            )
        )

        capa_path = os.path.join(PROJECT_ROOT, "capa.exe")
        rules_path = os.path.join(PROJECT_ROOT, "backend", "capa-rules")

        if not os.path.exists(capa_path):
            debug_log("[CAPA] exe not found", capa_path)
            return _empty_result("failed", "capa_exe_not_found", capa_path)

        cmd = [capa_path, "-j", "-r", rules_path, binary_path]
        debug_log("[CAPA] running", cmd)

        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            cwd=PROJECT_ROOT
        )

        if process.returncode != 0:
            return _empty_result("failed", "capa_nonzero_exit", process.stderr[:500])

        try:
            data = json.loads(process.stdout)
        except json.JSONDecodeError as e:
            return _empty_result("failed", "capa_json_parse_error", str(e))

        return _parse_and_normalize(data)

    except subprocess.TimeoutExpired:
        return _empty_result("failed", "capa_timeout", "timeout >180s")
    except Exception as e:
        return _empty_result("failed", "capa_exception", str(e))


def _parse_and_normalize(data: dict) -> dict:
    """
    Parse raw CAPA JSON output.

    KEY FIX: Each rule name is translated through CAPA_TO_CANONICAL before
    being added to normalized_capabilities. This is what was missing — CAPA
    names like "persist_via_run_registry_key" were passing through as-is,
    not recognized by CapabilityEngine.mapping, and silently falling through.
    """
    # Extract rules dict — handle both CAPA v1 and v2 formats
    if "rules" in data:
        rules = data["rules"]
    elif "analysis" in data and "rules" in data["analysis"]:
        rules = data["analysis"]["rules"]
    else:
        rules = {}

    if isinstance(rules, list):
        # CAPA v2 can emit rules as a list with meta inside each entry
        rules_iterable = rules
        is_list_format = True
    else:
        rules_iterable = rules.values()
        is_list_format = False

    raw_names: List[str] = []
    function_capabilities: Dict[str, List[str]] = {}
    mitre_ids: set = set()
    mitre_map: Dict[str, List[str]] = {}
    capability_details: List[dict] = []
    seen_details: set = set()

    for rule_entry in rules_iterable:
        if is_list_format:
            rule_data = rule_entry
        else:
            rule_data = rule_entry

        meta = rule_data.get("meta", {})
        raw_name = meta.get("name") if is_list_format else meta.get("name", "")

        # For dict format, rule_name is the key — use meta.name if available
        if not raw_name:
            continue

        raw_names.append(raw_name)

        # Extract MITRE techniques
        mitre_entries = meta.get("att&ck", [])
        canonical = translate_capa_name(raw_name)
        mapped_ids: set = set()

        for entry in mitre_entries:
            if not isinstance(entry, dict):
                continue
            technique = entry.get("id")
            tactic = entry.get("tactic")
            technique_name = entry.get("technique")
            if not technique:
                continue
            mapped_ids.add(technique)
            mitre_ids.add(technique)
            key = (canonical, technique)
            if key not in seen_details:
                seen_details.add(key)
                capability_details.append({
                    "capability": canonical,
                    "mitre_id": technique,
                    "tactic": tactic,
                    "technique": technique_name
                })

        if mapped_ids:
            mitre_map[canonical] = sorted(mapped_ids)

        # Extract function-level matches
        matches = rule_data.get("matches", {})
        if isinstance(matches, dict):
            for location in matches.keys():
                if isinstance(location, str) and "0x" in location:
                    func_addr = location.split(":")[0]
                    if func_addr not in function_capabilities:
                        function_capabilities[func_addr] = []
                    if canonical not in function_capabilities[func_addr]:
                        function_capabilities[func_addr].append(canonical)

    # Translate all raw CAPA names → canonical behavior names
    # DEDUP: multiple CAPA rules may translate to the same canonical behavior
    seen_canonical: set = set()
    normalized_capabilities: List[dict] = []

    for raw in raw_names:
        canonical = translate_capa_name(raw)
        if not canonical:
            continue
        # Keep one entry per canonical name (highest confidence = 0.9 for all CAPA)
        if canonical not in seen_canonical:
            seen_canonical.add(canonical)
            normalized_capabilities.append({
                "name": canonical,
                "source": "capa",
                "confidence": 0.9
            })

    debug_log("[CAPA] total rules parsed", len(raw_names))
    debug_log("[CAPA] unique canonical behaviors", len(normalized_capabilities))
    debug_log("[CAPA] normalized_capabilities", [c["name"] for c in normalized_capabilities])

    return {
        "status": "success",
        "capabilities_detected": len(normalized_capabilities),
        "capabilities": [c["name"] for c in normalized_capabilities],
        "normalized_capabilities": normalized_capabilities,
        "function_capabilities": function_capabilities,
        "behaviour_to_mitre": mitre_map,
        "capability_to_mitre": mitre_map,
        "mitre_techniques": sorted(mitre_ids),
        "capability_details": capability_details
    }


def parse_capa_results(capa_json: dict) -> dict:
    """Alias for _parse_and_normalize for direct use with raw CAPA JSON."""
    return _parse_and_normalize(capa_json)


def get_capa_status_summary(capa_results: dict) -> dict:
    """Extract status summary from CAPA results."""
    status = capa_results.get("status", "skipped")
    return {
        "enabled": status not in ("skipped", "failed"),
        "status": status,
        "capabilities_found": capa_results.get("capabilities_detected", 0),
        "message": capa_results.get("detail", capa_results.get("reason", ""))
    }
