"""
utils/normalization.py

Centralized behavior name normalization for the malware analysis pipeline.

Normalization pipeline (applied in order):
    1. Lowercase + strip whitespace
    2. Replace hyphens and spaces → underscores
    3. Apply explicit NORMALIZATION_MAP (aliases, raw API tokens, British spelling)
    4. Apply fuzzy matching via difflib (cutoff=0.80) — typo correction only
    5. Fallback to cleaned input if nothing matches

Convention: all canonical names are snake_case American English.
            "behavior" not "behaviour", "file_creation" not "filecreation".

Usage:
    from utils.normalization import normalize_behavior, CANONICAL_BEHAVIORS

    name = normalize_behavior("registry_persistance")   # → "registry_persistence"
    name = normalize_behavior("cmd_exec")               # → "command_execution"
    name = normalize_behavior("anti_debug")             # → "anti_debugging"
"""

import difflib
from utils.debug import debug_log


# =============================================================================
# CANONICAL BEHAVIOR NAMES
# Single source of truth. Every engine validates against this list.
# =============================================================================

CANONICAL_BEHAVIORS: list[str] = [
    # Network
    "network_activity",
    "payload_download",
    "command_and_control",
    "http_communication",
    "ftp_communication",
    "dns_activity",
    "data_exfiltration",
    "network_communication",

    # Process
    "process_creation",
    "process_termination",
    "process_injection",
    "process_hollowing",

    # Filesystem
    "file_creation",
    "file_modification",
    "file_deletion",
    "file_copy",
    "file_move",
    "directory_enumeration",

    # Registry
    "registry_persistence",
    "registry_modification",
    "registry_query",

    # Persistence
    "startup_persistence",
    "service_creation",
    "scheduled_task_creation",

    # Anti-Analysis
    "anti_debugging",
    "anti_vm",
    "anti_sandbox",

    # Credentials
    "credential_dumping",
    "keylogging",

    # Discovery
    "system_information_discovery",
    "system_discovery",
    "user_enumeration",
    "process_enumeration",
    "module_enumeration",

    # Memory
    "memory_allocation",
    "memory_protection_change",

    # Crypto
    "cryptographic_activity",
    "random_generation",

    # Privileges
    "privilege_escalation",
    "token_manipulation",

    # System Control
    "shutdown_system",
    "reboot_system",

    # Obfuscation / Loading
    "packing_detection",
    "dynamic_loading",
    "dynamic_api_resolution",

    # Execution
    "command_execution",

    # Informational (no capability mapping, but valid pipeline names)
    "indirect_call_execution",
    "unknown_external_activity",
    "internal_function_calls",
    "no_external_activity",
]

# Fast lookup set for O(1) membership tests
_CANONICAL_SET: set[str] = set(CANONICAL_BEHAVIORS)


# =============================================================================
# NORMALIZATION MAP
# Explicit alias → canonical name mappings.
# Applied BEFORE fuzzy matching so short/ambiguous aliases are handled precisely.
#
# Covers:
#   - British spellings        (behaviour → behavior*)
#   - Raw Windows API tokens   (CreateFile → file_creation)
#   - Short aliases            (cmd_exec → command_execution)
#   - feature_engine orphans   (file_encryption → cryptographic_activity)
#   - Informational names      (internal_function_calls → internal_function_calls)
#
# * The pipeline key is "name", not "behavior" — this map normalizes the VALUE,
#   not the dict key. The dict key inconsistency is fixed in each engine directly.
# =============================================================================

NORMALIZATION_MAP: dict[str, str] = {
    # ── British → American spelling ─────────────────────────────────────────
    "anti_behaviour":               "anti_debugging",

    # ── Short aliases / legacy names ────────────────────────────────────────
    "cmd_exec":                     "command_execution",
    "exec":                         "command_execution",
    "shell":                        "command_execution",
    "indirect_call":                "indirect_call_execution",
    "indirect_calls":               "indirect_call_execution",
    "file_encrypt":                 "cryptographic_activity",
    "file_encryption":              "cryptographic_activity",  # feature_engine orphan
    "data_encryption":              "cryptographic_activity",
    "startup_execution":            "startup_persistence",
    "remote_execution":             "process_creation",
    "data_collection":              "file_creation",           # collection category alias
    "obfuscation":                  "dynamic_api_resolution",

    # ── Raw Windows API token → canonical behaviour ──────────────────────────
    # These appear when raw import names leak into the behaviour name field.
    # The NORMALIZATION_MAP in mitre_engine previously handled a subset of these;
    # they are now unified here so all engines benefit.
    "socket":                       "network_communication",
    "connect":                      "network_communication",
    "recv":                         "network_communication",
    "send":                         "data_exfiltration",
    "wsastartup":                   "network_activity",
    "wsaconnect":                   "network_communication",
    "internetopen":                 "network_activity",
    "internetconnect":              "network_activity",
    "internetreadfile":             "payload_download",
    "urldownloadtofile":            "payload_download",
    "httpopenrequest":              "http_communication",
    "httpsendrequestex":            "http_communication",
    "winhttpopenrequest":           "http_communication",
    "winhttpsendrequest":           "command_and_control",
    "dnsquery":                     "dns_activity",
    "dnsquerya":                    "dns_activity",
    "gethostbyname":                "dns_activity",
    "getaddrinfo":                  "dns_activity",
    "ftpputfile":                   "ftp_communication",
    "ftpgetfile":                   "ftp_communication",
    "ftpopenfile":                  "ftp_communication",
    "createprocess":                "process_creation",
    "createprocessa":               "process_creation",
    "createprocessw":               "process_creation",
    "winexec":                      "process_creation",
    "shellexecute":                 "process_creation",
    "shellexecuteex":               "process_creation",
    "terminateprocess":             "process_termination",
    "exitprocess":                  "process_termination",
    "createremotethread":           "process_injection",
    "writeprocessmemory":           "process_injection",
    "openprocess":                  "process_injection",
    "virtualallocex":               "process_injection",
    "zwunmapviewofsection":         "process_hollowing",
    "ntunmapviewofsection":         "process_hollowing",
    "createfile":                   "file_creation",
    "createfilea":                  "file_creation",
    "createfilew":                  "file_creation",
    "writefile":                    "file_modification",
    "setfileattributes":            "file_modification",
    "deletefile":                   "file_deletion",
    "deletefilea":                  "file_deletion",
    "deletefilew":                  "file_deletion",
    "copyfile":                     "file_copy",
    "copyfileex":                   "file_copy",
    "movefile":                     "file_move",
    "movefileex":                   "file_move",
    "findfirstfile":                "directory_enumeration",
    "findnextfile":                 "directory_enumeration",
    "regsetvalue":                  "registry_persistence",
    "regsetvalueexa":               "registry_persistence",
    "regsetvalueexw":               "registry_persistence",
    "regcreatekey":                 "registry_persistence",
    "regcreatekeya":                "registry_persistence",
    "regcreatekeyex":               "registry_persistence",
    "regdeletevalue":               "registry_modification",
    "regdeletekey":                 "registry_modification",
    "regqueryvalue":                "registry_query",
    "regqueryvalueex":              "registry_query",
    "regopenkeyex":                 "registry_query",
    "createservice":                "service_creation",
    "createservicea":               "service_creation",
    "createservicew":               "service_creation",
    "startservice":                 "service_creation",
    "openscmanager":                "service_creation",
    "isdebuggerpresent":            "anti_debugging",
    "checkremotedebuggerpresent":   "anti_debugging",
    "ntqueryinformationprocess":    "anti_debugging",
    "outputdebugstring":            "anti_debugging",
    "debugbreak":                   "anti_debugging",
    "minidumpwritedump":            "credential_dumping",
    "lsaopenpolicy":                "credential_dumping",
    "lsaretrieveprivatedata":       "credential_dumping",
    "credenumerate":                "credential_dumping",
    "setwindowshook":               "keylogging",
    "setwindowshookexa":            "keylogging",
    "setwindowshookexw":            "keylogging",
    "getasynckeystate":             "keylogging",
    "getkeystate":                  "keylogging",
    "getsysteminfo":                "system_discovery",
    "getnativesysteminfo":          "system_information_discovery",
    "getversion":                   "system_information_discovery",
    "rtlgetversion":                "system_discovery",
    "getcomputername":              "system_discovery",
    "getusername":                  "system_discovery",
    "netuserenum":                  "user_enumeration",
    "netusergetinfo":               "user_enumeration",
    "createtoolhelp32snapshot":     "process_enumeration",
    "process32first":               "process_enumeration",
    "process32next":                "process_enumeration",
    "enumprocesses":                "process_enumeration",
    "module32first":                "module_enumeration",
    "module32next":                 "module_enumeration",
    "enumprocessmodules":           "module_enumeration",
    "virtualalloc":                 "memory_allocation",
    "heapalloc":                    "memory_allocation",
    "rtlallocateheap":              "memory_allocation",
    "virtualprotect":               "memory_protection_change",
    "virtualprotectex":             "memory_protection_change",
    "cryptencrypt":                 "cryptographic_activity",
    "cryptdecrypt":                 "cryptographic_activity",
    "cryptacquirecontext":          "cryptographic_activity",
    "bcryptencrypt":                "cryptographic_activity",
    "bcryptdecrypt":                "cryptographic_activity",
    "bcryptopenalgorithmprovider":  "cryptographic_activity",
    "cryptgenrandom":               "random_generation",
    "rtlgenrandom":                 "random_generation",
    "bcryptgenrandom":              "random_generation",
    "adjusttokenprivileges":        "privilege_escalation",
    "lookupprivilegevalue":         "privilege_escalation",
    "openprocesstoken":             "token_manipulation",
    "duplicatetoken":               "token_manipulation",
    "impersonateloggedonuser":      "token_manipulation",
    "createprocesswithtokenw":      "token_manipulation",
    "exitwindowsex":                "shutdown_system",
    "initiatesystemshutdown":       "reboot_system",
    "loadlibrary":                  "dynamic_loading",
    "loadlibrarya":                 "dynamic_loading",
    "loadlibraryw":                 "dynamic_loading",
    "ldrloaddll":                   "dynamic_loading",
    "getprocaddress":               "dynamic_api_resolution",
    "system":                       "command_execution",
    "cmd":                          "command_execution",
    "powershell":                   "command_execution",
}


# =============================================================================
# CORE NORMALIZATION FUNCTION
# =============================================================================

def normalize_behavior(name: str) -> str | None:

    if not name or not isinstance(name, str):
        return None

    original = name
    cleaned = name.lower().strip()
    cleaned = cleaned.replace("-", "_").replace(" ", "_")

    if cleaned in _CANONICAL_SET:
        return cleaned

    if cleaned in NORMALIZATION_MAP:
        result = NORMALIZATION_MAP[cleaned]
        debug_log("[NORMALIZED] explicit map", "%r → %r" % (original, result))
        return result

    # 🔥 FIX: avoid fuzzy on short strings
    if len(cleaned) > 5:
        matches = difflib.get_close_matches(cleaned, CANONICAL_BEHAVIORS, n=1, cutoff=0.80)
        if matches:
            result = matches[0]
            debug_log("[NORMALIZED] fuzzy match", "%r → %r" % (original, result))
            return result

    debug_log("[NORMALIZED] fallback", "%r → %r" % (original, cleaned))
    return cleaned


def normalize_behavior_list(names: list[str], source: str = "unknown") -> list[dict]:
    """
    Normalize a list of raw behavior name strings into standardized dicts.

    Returns:
        list of {"name": str, "source": str, "confidence": float}
        Duplicates (post-normalization) are deduplicated, keeping first occurrence.
    """
    seen: set[str] = set()
    result: list[dict] = []

    for raw in names:
        canonical = normalize_behavior(raw)
        if not canonical or canonical in seen:
            continue
        seen.add(canonical)
        result.append({
            "name": canonical,
            "source": source,
            "confidence": 0.8,
        })

    return result


def extract_behavior_name(b) -> str | None:
    """
    Safely extract the behavior name from any of the supported input shapes:
        - str                      → used directly
        - dict with "name" key     → preferred
        - dict with "behavior" key → legacy American spelling
        - dict with "behaviour" key→ legacy British spelling

    Returns the normalized canonical name, or None if extraction fails.
    """
    if isinstance(b, str):
        raw = b
    elif isinstance(b, dict):
        raw = (
            b.get("name")
            or b.get("behavior")
            or b.get("behaviour")
            or ""
        )
    else:
        return None

    return normalize_behavior(raw) if raw else None