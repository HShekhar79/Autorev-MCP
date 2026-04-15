# engines/function_analysis_engine/function_analysis_engine.py
import r2pipe
import re
from typing import List, Dict, Any, Optional
from utils.debug import debug_log
from utils.normalization import normalize_behavior

# -----------------------
# Normalization & helpers
# -----------------------

def normalize_api(call: str) -> str:
    if not call:
        return ""
    call = str(call).lower()
    for prefix in ("sym.imp.", "sym.", "imp.", "reloc.", "ptr."):
        call = call.replace(prefix, "")
    call = call.split()[0]
    call = re.sub(r"(a|w)$", "", call)
    call = re.sub(r"^(nt|zw)", "", call)
    return call.strip()

# -----------------------
# Behaviour & MITRE maps
# -----------------------

BEHAVIOUR_PATTERNS = {
    "network_activity": [
        "internetopen", "internetconnect", "internetreadfile",
        "winhttpsendrequest", "winhttpreaddata",
        "urldownloadtofile", "socket", "connect", "send", "recv",
        "wsastartup", "wsaconnect"
    ],
    "payload_download": [
        "urldownloadtofile", "internetreadfile", "winhttpreaddata",
        "urldownloadtocacheentry"
    ],
    "command_and_control": [
        "internetconnect", "httpsendrequestex", "winhttpsendrequest",
        "connect", "httpopenrequest"
    ],
    "process_injection": [
        "createremotethread", "createremotethreadex",
        "writeprocessmemory", "writevirtualmemory",
        "createthreadex", "setthreadcontext",
        "virtualallocex", "openprocess"
    ],
    "process_hollowing": ["unmapviewofsection"],
    "process_creation": [
        "createprocess", "winexec", "shellexecute", "shellexecuteex"
    ],
    "registry_persistence": [
        "regcreatekey", "regsetvalue", "regsetvalueex",
        "regopenkey", "regcreatekeyex"
    ],
    "file_creation": ["createfile", "writefile"],
    "file_deletion": ["deletefile", "ntdeletefile"],
    "file_modification": ["writefile", "movefile", "copyfile", "setfileattributes"],
    "directory_enumeration": ["findfirstfile", "findnextfile"],
    "anti_debugging": [
        "isdebuggerpresent", "checkremotedebuggerpresent",
        "queryinformationprocess", "outputdebugstring"
    ],
    "dynamic_loading": ["loadlibrary", "getprocaddress", "ldrloaddll"],
    "dynamic_api_resolution": ["getprocaddress", "loadlibrary", "ldrloaddll"],
    "memory_allocation": ["virtualalloc", "virtualallocex", "heapalloc"],
    "memory_protection_change": ["virtualprotect", "virtualprotectex"],
    "data_exfiltration": ["send", "wsasend", "ftpputfile"],
    "keylogging": ["setwindowshook", "getasynckeystate", "getkeystate"],
    "credential_dumping": [
        "lsaopenpolicy", "lsaretrieveprivatedata",
        "credenumerate", "minidumpwritedump", "samopendb"
    ],
    "system_discovery": [
        "getsysteminfo", "getcomputername", "getusername",
        "getversion", "rtlgetversion"
    ],
    "process_enumeration": [
        "createtoolhelp32snapshot", "process32first",
        "process32next", "enumprocesses"
    ],
    "privilege_escalation": ["adjusttokenprivileges", "lookupprivilegevalue"],
    "token_manipulation": [
        "openprocesstoken", "duplicatetoken",
        "impersonateloggedonuser", "createprocesswithtokenw"
    ],
    "cryptographic_activity": [
        "cryptencrypt", "cryptdecrypt", "cryptacquirecontext",
        "bcryptencrypt", "bcryptdecrypt"
    ],
    "command_execution": [
        "createprocess", "winexec", "shellexecute",
        "system", "cmd.exe", "powershell"
    ],
    "service_creation": [
        "createservice", "startservice", "openscmanager"
    ],
}

# Complete MITRE mapping for all behaviour types
MITRE_MAPPING = {
    "process_injection":            "T1055",
    "process_hollowing":            "T1055.012",
    "registry_persistence":         "T1547",
    "registry_modification":        "T1112",
    "command_and_control":          "T1071",
    "network_activity":             "T1071",
    "payload_download":             "T1105",
    "credential_dumping":           "T1003",
    "anti_debugging":               "T1622",
    "dynamic_loading":              "T1620",
    "dynamic_api_resolution":       "T1620",
    "memory_allocation":            "T1055",
    "data_exfiltration":            "T1041",
    "process_creation":             "T1059.003",
    "command_execution":            "T1059",
    "system_discovery":             "T1082",
    "process_enumeration":          "T1057",
    "privilege_escalation":         "T1068",
    "token_manipulation":           "T1134",
    "cryptographic_activity":       "T1560",
    "keylogging":                   "T1056",
    "service_creation":             "T1543",
    "file_deletion":                "T1485",
    "memory_protection_change":     "T1055",
    "directory_enumeration":        "T1083",
    "file_creation":                "T1119",
    "file_modification":            "T1119",
}

# Behaviour names that are benign fallbacks — no MITRE, not suspicious
BENIGN_BEHAVIOURS = {
    "no_external_activity",
    "internal_function_calls",
    "system_runtime_function",
    "indirect_call_execution",
    "unknown_external_activity",
}

# -----------------------
# Behaviour fallback resolver
# -----------------------

SYSTEM_RUNTIME_PREFIX = (
    "__", "_", "crt", "mingw", "gcc", "atexit", "exit", "abort"
)

REGISTER_CALLS = {"rax", "rbx", "rcx", "rdx", "r8", "r9"}


def resolve_unknown_behaviour(function_name: str, calls: List[str]) -> str:
    """Returns a single benign fallback behaviour name."""
    if not calls:
        return "no_external_activity"

    if any(function_name.startswith(p) for p in SYSTEM_RUNTIME_PREFIX):
        return "system_runtime_function"

    internal_calls = [c for c in calls if c.startswith(("sym.", "fcn.", "sub.", "entry"))]
    if len(internal_calls) == len(calls):
        return "internal_function_calls"

    if any(c.lower() in REGISTER_CALLS for c in calls):
        return "indirect_call_execution"

    return "unknown_external_activity"


# -----------------------
# Behaviour detection — builds reverse lookup table
# -----------------------

_API_TO_BEHAVIOUR: Dict[str, List[str]] = {}
for _b, _patterns in BEHAVIOUR_PATTERNS.items():
    for _p in _patterns:
        _API_TO_BEHAVIOUR.setdefault(_p.lower(), []).append(_b)


def detect_behaviours(calls: List[str]) -> Dict[str, str]:
    """
    Detect all suspicious behaviours from a list of API call names.

    Returns:
        dict mapping behaviour_name → mitre_id (or None)
        Only one entry per unique behaviour name — NO duplicates.
    """
    detected: Dict[str, str] = {}  # {behaviour_name: mitre_id}

    for raw in calls:
        api = normalize_api(raw).lower()
        if not api:
            continue
        for key, behaviours in _API_TO_BEHAVIOUR.items():
            if key in api:
                for bname in behaviours:
                    if bname not in detected:
                        detected[bname] = MITRE_MAPPING.get(bname)

    return detected


# -----------------------
# Capability detection — CAPA-like
# -----------------------

# Each rule: (capability_name, [any one of these APIs triggers it], mitre_id)
CAPABILITY_RULES = [
    ("file_write",              ["createfile", "writefile"],                "T1119"),
    ("process_injection",       ["virtualalloc", "writeprocessmemory",
                                  "createremotethread"],                    "T1055"),
    ("dynamic_api_resolution",  ["loadlibrary", "getprocaddress"],          "T1620"),
    ("command_execution",       ["createprocess", "winexec",
                                  "shellexecute", "system"],                "T1059"),
    ("network_communication",   ["socket", "connect", "wsaconnect"],        "T1071"),
    ("registry_write",          ["regsetvalue", "regcreatekey"],            "T1547"),
    ("anti_debugging",          ["isdebuggerpresent",
                                  "checkremotedebuggerpresent"],            "T1622"),
    ("process_enumeration",     ["createtoolhelp32snapshot",
                                  "process32first", "enumprocesses"],       "T1057"),
    ("memory_manipulation",     ["virtualalloc", "heapalloc"],              "T1055"),
]


def detect_capabilities(calls: List[str]) -> Dict[str, str]:
    """
    Returns dict of {capability_name: mitre_id} detected from calls.
    Only adds a capability if its behaviour equivalent is NOT already in
    detected behaviours (to avoid duplicate entries in the behaviour list).
    """
    normalized = {normalize_api(c).lower() for c in calls if c}
    caps: Dict[str, str] = {}
    for cap_name, required_apis, mitre_id in CAPABILITY_RULES:
        if any(req in normalized for req in required_apis):
            caps[cap_name] = mitre_id
    return caps


# -----------------------
# Hidden API detection (strings & imports) — global only
# -----------------------

SUSPICIOUS_API_STRINGS = [
    "virtualalloc", "writeprocessmemory", "createremotethread",
    "loadlibrary", "getprocaddress", "createprocess", "cmd.exe", "powershell"
]


def detect_hidden_api_behaviour(
    strings: List[str],
    imports: Optional[List[Any]] = None
) -> Dict[str, str]:
    """
    Scan strings and imports for hidden behaviour clues.
    Returns dict of {behaviour_name: mitre_id}.
    Runs ONCE globally, not per-function.
    """
    found: Dict[str, str] = {}
    imports_lower = []

    if imports:
        for imp in imports:
            name = imp.get("name", "") if isinstance(imp, dict) else str(imp)
            imports_lower.append(name.lower())

    has_loadlib = any("loadlibrary" in x for x in imports_lower)
    has_gpa = any("getprocaddress" in x for x in imports_lower)

    if has_loadlib or has_gpa:
        suspicious_in_strings = any(
            tok in str(s).lower()
            for s in (strings or [])
            for tok in ["virtualalloc", "writeprocessmemory", "createremotethread"]
        )
        if suspicious_in_strings:
            found["dynamic_api_resolution"] = MITRE_MAPPING.get("dynamic_api_resolution")

    for s in (strings or []):
        low = str(s).lower()
        for token in SUSPICIOUS_API_STRINGS:
            if token in low:
                if token in ("virtualalloc", "writeprocessmemory", "createremotethread"):
                    found.setdefault("process_injection", MITRE_MAPPING.get("process_injection"))
                elif token in ("createprocess", "cmd.exe", "powershell", "winexec", "shellexecute"):
                    found.setdefault("command_execution", MITRE_MAPPING.get("command_execution"))
                elif token in ("loadlibrary", "getprocaddress"):
                    found.setdefault("dynamic_api_resolution", MITRE_MAPPING.get("dynamic_api_resolution"))

    return found


# -----------------------
# Risk scoring
# -----------------------

BEHAVIOUR_WEIGHTS = {
    "process_injection":            40,
    "process_hollowing":            45,
    "credential_dumping":           40,
    "privilege_escalation":         35,
    "payload_download":             30,
    "registry_persistence":         30,
    "command_and_control":          30,
    "network_activity":             15,
    "keylogging":                   30,
    "anti_debugging":               25,
    "dynamic_loading":              20,
    "dynamic_api_resolution":       35,
    "data_exfiltration":            25,
    "memory_protection_change":     20,
    "process_creation":             15,
    "service_creation":             20,
    "token_manipulation":           25,
    "process_enumeration":          10,
    "memory_allocation":            10,
    "cryptographic_activity":       15,
    "file_deletion":                10,
    "command_execution":            30,
    "system_discovery":             10,
    "file_write":                   20,
    "network_communication":        20,
    "registry_write":               25,
    "memory_manipulation":          15,
    "indirect_call_execution":      15,
    "internal_function_calls":       2,
    "system_runtime_function":       1,
    "unknown_external_activity":     5,
    "no_external_activity":          0,
}


def calculate_risk(behaviour_map: Dict[str, str], calls: List[str]) -> int:
    score = sum(BEHAVIOUR_WEIGHTS.get(b, 5) for b in behaviour_map)
    score += len(calls) * 2
    return min(score, 100)


# -----------------------
# Format helpers
# -----------------------

def _format_behaviours(behaviour_map: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Convert behaviour dict → clean list for API output.
    - Suspicious behaviours: include mitre field
    - Benign behaviours: mitre = null (expected)
    - NO duplicates (guaranteed by dict keys)
    """
    result = []
    for bname, mitre_id in behaviour_map.items():
        entry: Dict[str, Any] = {"name": bname}
        if mitre_id:
            entry["mitre"] = mitre_id
        result.append(entry)
    return result


def _format_capabilities(cap_map: Dict[str, str]) -> List[Dict[str, Any]]:
    """Convert capability dict → clean list with name + mitre."""
    return [
        {"name": cap_name, "mitre": mitre_id}
        for cap_name, mitre_id in cap_map.items()
    ]


# -----------------------
# Main analyzer
# -----------------------

def analyze_functions(
    binary_path: str,
    strings: Optional[List[str]] = None,
    imports: Optional[List[Any]] = None
) -> Dict[str, Any]:
    """
    Analyze all functions in the binary.

    Each function in results has:
      - function_name
      - calls: list of resolved API names
      - behaviours: list of {name, mitre?} — NO duplicates, mitre only when known
      - capabilities: list of {name, mitre} — higher-level detection
      - mitre_techniques: sorted unique list of MITRE IDs for this function
      - risk_score: 0–100
    """
    if not binary_path:
        return {"error": "invalid binary path"}

    results = []
    global_capabilities: set = set()
    r2 = None

    try:
        r2 = r2pipe.open(binary_path, flags=["-2"])
        r2.cmd("e anal.timeout=180")
        r2.cmd("aaa")

        functions = r2.cmdj("aflj") or []

        # Extract strings once
        if strings is None:
            try:
                strings_j = r2.cmdj("izj") or []
                strings = [
                    s.get("string", "")
                    for s in strings_j
                    if isinstance(s, dict) and s.get("string")
                ]
            except Exception:
                strings = []

        for func in functions:
            if func.get("size", 0) < 8:
                continue

            name = func.get("name", "")
            calls = []

            # Disassemble and extract call targets
            try:
                disasm = r2.cmdj(f"pdfj @ {name}") or {}
                for op in disasm.get("ops", []):
                    if op.get("type", "") not in ("call", "ucall", "rcall", "icall"):
                        continue

                    resolved = None

                    # Try jump target resolution
                    jump_addr = op.get("jump")
                    if jump_addr:
                        try:
                            sym = r2.cmd(f"fd @ {jump_addr}").strip()
                            if sym and sym != str(jump_addr):
                                resolved = sym
                        except Exception:
                            pass

                    # Fallback: parse disasm text
                    if not resolved:
                        text = op.get("disasm", "") or ""
                        parts = text.split(" ", 1)
                        if len(parts) == 2:
                            resolved = parts[1]

                    # Fallback: refs
                    if not resolved:
                        for ref in (op.get("refs") or []):
                            addr = ref.get("addr") if isinstance(ref, dict) else None
                            if addr:
                                try:
                                    sym = r2.cmd(f"fd @ {addr}").strip()
                                    if sym:
                                        resolved = sym
                                        break
                                except Exception:
                                    pass

                    if resolved and resolved not in ("", "call"):
                        calls.append(resolved)

            except Exception:
                pass

            # Deduplicate calls (preserve order)
            seen_c: set = set()
            unique_calls = []
            for c in calls:
                if c not in seen_c:
                    seen_c.add(c)
                    unique_calls.append(c)

            # ── Behaviour detection ──
            behaviour_map = detect_behaviours(unique_calls)

            # ── Normalization (FIXED)
            normalized_behaviour_map = {}

            for bname, mitre in behaviour_map.items():
                canonical = normalize_behavior(bname)
                if canonical:
                    normalized_behaviour_map[canonical] = mitre

            behaviour_map = normalized_behaviour_map

            # ── Capability detection ──
            # Only add capability if it is NOT already a detected behaviour
            cap_map = detect_capabilities(unique_calls)
            extra_caps: Dict[str, str] = {}
            for cap_name, mitre_id in cap_map.items():
                # avoid adding a duplicate behaviour under a different name
                canonical_cap = normalize_behavior(cap_name)

                if canonical_cap and canonical_cap not in behaviour_map:
                    extra_caps[canonical_cap] = mitre_id
                    global_capabilities.add(canonical_cap)

            # ── Fallback if no suspicious behaviour found ──
            if not behaviour_map:
                fallback = resolve_unknown_behaviour(name, unique_calls)
                behaviour_map[fallback] = None  # benign — no MITRE

            # ── Risk score ──
            combined = {**behaviour_map, **extra_caps}
            risk_score = calculate_risk(combined, unique_calls)

            # ── Per-function MITRE techniques (deduplicated) ──
            all_mitre = sorted({
                m for m in list(behaviour_map.values()) + list(extra_caps.values())
                if m
            })

            debug_log(f"Function [{name}]", {
                "behaviours": list(behaviour_map.keys()),
                "capabilities": list(extra_caps.keys()),
                "mitre": all_mitre
            })

            results.append({
                "function_name": name,
                "calls": unique_calls,
                "behaviours": _format_behaviours(behaviour_map),
                "capabilities": _format_capabilities(extra_caps),
                "mitre_techniques": all_mitre,
                "risk_score": risk_score
            })

        # ── Global hidden-api detection ──
        global_hidden = detect_hidden_api_behaviour(strings, imports)

        return {
            "results": results,
            "global_behaviours": [
                {"name": k, "mitre": v}
                for k, v in global_hidden.items()
            ],
            "global_capabilities": sorted(list(global_capabilities))
        }

    except Exception as e:
        debug_log("analyze_functions ERROR", str(e))
        return {
            "results": [],
            "global_behaviours": [],
            "global_capabilities": [],
            "error": str(e)
        }

    finally:
        if r2:
            try:
                r2.quit()
            except Exception:
                pass