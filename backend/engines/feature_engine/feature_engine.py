"""
feature_engine.py

FIXES:
1. extract_features() signature was (functions, imports, strings, behaviour) —
   but the pipeline called it as extract_features(path) with only one argument.
   Signature is preserved (4 args); the caller (analysis.py) now passes correct args.

2. analyze_imports() still emits legacy {\"api\": ..., \"behavior\": ...} format.
   This function is local-only and not consumed by collect_all_behaviours, so it
   is left as-is (internal feature scoring only). No downstream breakage.

3. \"file_encryption\" is not a canonical behavior — it maps to cryptographic_activity
   via normalization.py NORMALIZATION_MAP. No change needed here.
"""
from utils.normalization import normalize_behavior

SUSPICIOUS_APIS = {
    "process_injection": [
        "CreateRemoteThread",
        "WriteProcessMemory",
        "VirtualAllocEx",
        "OpenProcess",
        "NtWriteVirtualMemory",
    ],
    "registry_persistence": [
        "RegSetValueExW",
        "RegCreateKeyExW",
        "RegOpenKeyExW",
    ],
    "network_activity": [
        "InternetOpenW",
        "InternetConnectW",
        "HttpSendRequestW",
        "WSAStartup",
        "socket",
        "connect",
    ],
    "anti_debugging": [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
    ],
    "file_encryption": [
        "CryptEncrypt",
        "CryptAcquireContextW",
    ],
}


def analyze_imports(imports_list):
    """
    Local import-level feature detection.
    Returns legacy {\"api\", \"behavior\"} format — for internal feature use only.
    Not consumed by collect_all_behaviours (which uses import_behaviour_engine instead).
    """
    detected_behaviors = []

    for imp in imports_list:
        if isinstance(imp, dict):
            api_name = imp.get("name", "")
        else:
            api_name = str(imp)

        for category, api_list in SUSPICIOUS_APIS.items():
            if api_name in api_list:
                detected_behaviors.append({"api": api_name, "behavior": category})

    return detected_behaviors


def extract_features(functions, imports, strings, behaviour):
    """
    Extract binary-level feature signals for the scoring engine.

    Args:
        functions: list of function analysis result dicts
        imports:   list of import name strings or dicts
        strings:   list of string value strings or dicts
        behaviour: list of behaviour dicts (standardized: {\"name\", \"source\", \"confidence\"})

    Returns:
        dict of feature flags and counts used by scoring_engine.
    """
    features = {}

    # ── Counts ───────────────────────────────────────────────────────────────
    features["function_count"] = len(functions) if isinstance(functions, list) else 0
    features["import_count"] = len(imports) if isinstance(imports, list) else 0
    features["string_count"] = len(strings) if isinstance(strings, list) else 0

    # ── Behaviour flags ───────────────────────────────────────────────────────
    # FIX: standardized format uses "name" key; fallback to "behavior"/"behaviour"
    behaviour_types = []

    for b in (behaviour or []):
        if isinstance(b, dict):
            raw = b.get("name") or b.get("behavior") or b.get("behaviour")
        else:
            raw = str(b)

        canonical = normalize_behavior(raw)

        if canonical:
            behaviour_types.append(canonical)

    features["anti_debug"] = "anti_debugging" in behaviour_types
    features["registry_persistence"] = "registry_persistence" in behaviour_types

    # ── Suspicious string scan ────────────────────────────────────────────────
    suspicious_keywords = ["http", "cmd.exe", "powershell", "temp", "appdata", "registry"]
    suspicious_found = 0
    seen_strings = set()

    for s in (strings or []):
        if isinstance(s, dict):
            text = str(s.get("string", "")).lower()
        else:
            text = str(s).lower()

        for key in suspicious_keywords:
            if key in text:
                seen_strings.add(text)
                break

    features["suspicious_strings"] = len(seen_strings)

    return features
