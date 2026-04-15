from utils.normalization import extract_behavior_name, normalize_behavior


BEHAVIOUR_WEIGHTS = {
    "process_injection": 40,
    "process_hollowing": 45,
    "credential_dumping": 40,
    "privilege_escalation": 35,
    "payload_download": 30,
    "registry_persistence": 30,
    "command_and_control": 30,
    "keylogging": 30,
    "data_exfiltration": 25,
    "anti_debugging": 25,
    "token_manipulation": 25,
    "dynamic_loading": 20,
    "memory_protection_change": 20,
    "anti_vm": 20,
    "service_creation": 20,
    "network_activity": 15,
    "process_creation": 15,
    "cryptographic_activity": 15,
    "file_deletion": 10,
    "process_enumeration": 10,
    "memory_allocation": 10,
}


# -------------------------------
# SAFE + NORMALIZED BEHAVIOR EXTRACTION
# -------------------------------
def _safe_behavior_name(b):
    try:
        raw = extract_behavior_name(b) if isinstance(b, dict) else str(b)
        return normalize_behavior(raw)
    except Exception:
        return None


# -------------------------------
# FUNCTION RISK
# -------------------------------
def calculate_function_risk(behaviours: list) -> int:

    if not isinstance(behaviours, list):
        return 0

    score = 0
    seen = set()

    for b in behaviours:
        bname = _safe_behavior_name(b)

        if not bname or bname in seen:
            continue

        seen.add(bname)
        score += BEHAVIOUR_WEIGHTS.get(bname, 5)

    return min(score, 100)


# -------------------------------
# IMPORT RISK
# -------------------------------
def calculate_import_risk(import_behaviours: list) -> int:

    if not isinstance(import_behaviours, list):
        return 0

    seen = set()
    score = 0

    for b in import_behaviours:
        bname = _safe_behavior_name(b)

        if not bname or bname in seen:
            continue

        seen.add(bname)
        score += BEHAVIOUR_WEIGHTS.get(bname, 5)

    return min(score, 100)


# -------------------------------
# STATIC + IMPORT RISK
# -------------------------------
def calculate_risk(features: dict, import_behaviours: list = None) -> int:

    if not isinstance(features, dict):
        features = {}

    score = 0

    # Static signals
    if features.get("anti_debug"):
        score += 30

    if features.get("registry_persistence"):
        score += 30

    if isinstance(features.get("suspicious_strings"), int) and features["suspicious_strings"] > 3:
        score += 20

    if isinstance(features.get("import_count"), int) and features["import_count"] > 300:
        score += 10

    if isinstance(features.get("function_count"), int) and features["function_count"] > 500:
        score += 10

    # Import boost
    if import_behaviours:
        import_score = calculate_import_risk(import_behaviours)
        score += int(import_score * 0.4)

    return min(score, 100)


# -------------------------------
# FINAL COMBINED RISK
# -------------------------------
def calculate_combined_risk(
    features: dict,
    function_results: list,
    import_behaviours: list,
    mitre_result: dict = None
) -> dict:

    static_score = calculate_risk(features)
    import_score = calculate_import_risk(import_behaviours or [])

    # -------------------------
    # FUNCTION MAX SCORE
    # -------------------------
    func_max = 0

    if isinstance(function_results, list):
        valid_scores = [
            f.get("risk_score", 0)
            for f in function_results
            if isinstance(f, dict)
        ]
        func_max = max(valid_scores) if valid_scores else 0

    # -------------------------
    # MITRE BONUS (SAFE)
    # -------------------------
    mitre_bonus = 0

    if isinstance(mitre_result, dict):
        mitre_list = (
            mitre_result.get("mitre_techniques")
            or mitre_result.get("final_mitre")
            or []
        )

        if isinstance(mitre_list, list):
            mitre_bonus = min(len(mitre_list) * 2, 20)

    # -------------------------
    # FINAL WEIGHTED SCORE
    # -------------------------
    combined = int(
        static_score * 0.25 +
        import_score * 0.30 +
        func_max * 0.25 +
        mitre_bonus * 0.20
    )

    return {
        "combined_score": min(combined, 100),
        "static_score": static_score,
        "import_score": import_score,
        "function_max_score": func_max,
        "mitre_bonus": mitre_bonus
    }