from utils.debug import debug_log
from utils.normalization import normalize_behavior, extract_behavior_name


# =========================
# FULL MITRE DATABASE
# =========================
MITRE_DATABASE = {

    "execution": {
        "command_execution": ["T1059", "T1059.003"],
        "powershell": ["T1059.001"],
    },

    "persistence": {
        "registry_persistence": ["T1547", "T1547.001"],
        "startup_persistence": ["T1547.001"],
        "service_creation": ["T1543", "T1543.003"],
        "scheduled_task_creation": ["T1053.005"],
    },

    "defense_evasion": {
        "anti_debugging": ["T1622"],
        "anti_vm": ["T1497"],
        "anti_sandbox": ["T1497"],
        # Conservative mapping: generic behaviours are NOT ATT&CK proof. Deliberately
        # unmapped (context/correlation required before any technique is asserted):
        #   memory_allocation, memory_protection_change  (T1055 needs injection context)
        #   dynamic_loading, dynamic_api_resolution      (T1027 / T1620 need
        #                                                 obfuscation / reflective-loading context)
        "process_hollowing": ["T1055.012"],
        "process_injection": ["T1055"],
        "packing_detection": ["T1027.002"],
        "registry_modification": ["T1112"],
    },

    "credential_access": {
        "credential_dumping": ["T1003"],
        "keylogging": ["T1056"],
        "token_manipulation": ["T1134"],
    },

    "discovery": {
        "system_discovery": ["T1082"],
        "system_information_discovery": ["T1082"],
        "process_enumeration": ["T1057"],
        "module_enumeration": ["T1057"],
        "user_enumeration": ["T1033"],
        "directory_enumeration": ["T1083"],
        "registry_query": ["T1012"],
    },


    "collection": {
        "keylogging": ["T1056"],
        # file_creation / file_modification deliberately unmapped: generic file I/O does
        # not establish automated collection (T1119).
    },

    "exfiltration": {
        "data_exfiltration": ["T1041"],
    },

    "command_and_control": {
        # network_communication / network_activity deliberately unmapped: generic socket
        # use does not establish an application-layer protocol (T1071).
        "payload_download": ["T1105"],
    },

    "impact": {
        "file_deletion": ["T1485"],
        "shutdown_system": ["T1529"],
        "reboot_system": ["T1529"],
    },

    "privilege_escalation": {
        "token_manipulation": ["T1134"],
    },
}


# =========================
# FAST LOOKUP (AUTO BUILD)
# =========================
MITRE_LOOKUP = {}

for tactic, behaviour_map in MITRE_DATABASE.items():
    for behaviour, techniques in behaviour_map.items():
        MITRE_LOOKUP.setdefault(behaviour, []).append((tactic, techniques))


# =========================
# INPUT NORMALIZATION
# =========================
def _extract_names_from_input(behaviours):

    if isinstance(behaviours, dict):
        return [str(n) for n in behaviours.get("behaviors", []) if n]

    if isinstance(behaviours, list):
        names = []
        for b in behaviours:
            name = extract_behavior_name(b) if isinstance(b, dict) else str(b)
            if name:
                names.append(name)
        return names

    return []


# =========================
# CORE MAPPING
# =========================
def map_behaviour_to_mitre(behaviours):

    if not behaviours:
        return {
            "mitre_techniques": [],
            "tactics": {},
            "total_techniques": 0,
            "behaviour_mitre_detail": [],
        }

    raw_names = _extract_names_from_input(behaviours)
    debug_log("MITRE raw_names", raw_names)

    techniques_set = set()
    tactic_map = {}
    behaviour_detail = []
    seen = set()

    for raw in raw_names:

        canonical = normalize_behavior(raw)

        if not canonical or canonical in seen:
            continue

        seen.add(canonical)

        entries = MITRE_LOOKUP.get(canonical)

        if not entries:
            debug_log("[MITRE MISS]", canonical)

            behaviour_detail.append({
                "behavior": canonical,
                "mitre": [],
                "note": "no mitre mapping"
            })
            continue

        matched = set()

        for tactic, techniques in entries:
            matched.update(techniques)
            techniques_set.update(techniques)
            tactic_map.setdefault(tactic, set()).update(techniques)

            debug_log("[MITRE MATCH]", f"{canonical} → {tactic} → {techniques}")

        behaviour_detail.append({
            "behavior": canonical,   # ✅ ONLY THIS KEY
            "mitre": sorted(matched),
        })

    result = {
        "mitre_techniques": sorted(techniques_set),
        "tactics": {k: sorted(v) for k, v in tactic_map.items()},
        "total_techniques": len(techniques_set),
        "behaviour_mitre_detail": behaviour_detail,
    }

    debug_log("MITRE FINAL", result)
    return result
