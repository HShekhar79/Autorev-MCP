from utils.debug import debug_log


# ----------------------------------
# MITRE RISK DB (UNCHANGED)
# ----------------------------------
MITRE_RISK_DB = {
    "T1055": {"score": 9.0, "tactic": "defense-evasion"},
    "T1055.012": {"score": 9.2, "tactic": "defense-evasion"},

    "T1071": {"score": 8.5, "tactic": "command-and-control"},
    "T1071.001": {"score": 8.3, "tactic": "command-and-control"},
    "T1071.002": {"score": 8.0, "tactic": "command-and-control"},
    "T1071.004": {"score": 8.2, "tactic": "command-and-control"},

    "T1003": {"score": 9.5, "tactic": "credential-access"},
    "T1056": {"score": 8.6, "tactic": "credential-access"},
    "T1134": {"score": 8.0, "tactic": "credential-access"},

    "T1041": {"score": 9.0, "tactic": "exfiltration"},
    "T1048": {"score": 8.0, "tactic": "exfiltration"},

    "T1105": {"score": 8.2, "tactic": "command-and-control"},

    "T1547": {"score": 8.0, "tactic": "persistence"},
    "T1547.001": {"score": 8.0, "tactic": "persistence"},
    "T1543": {"score": 8.3, "tactic": "persistence"},
    "T1543.003": {"score": 8.3, "tactic": "persistence"},
    "T1053.005": {"score": 7.8, "tactic": "persistence"},

    "T1112": {"score": 7.2, "tactic": "defense-evasion"},
    "T1012": {"score": 5.5, "tactic": "discovery"},

    "T1068": {"score": 9.0, "tactic": "privilege-escalation"},

    "T1082": {"score": 6.0, "tactic": "discovery"},
    "T1033": {"score": 6.2, "tactic": "discovery"},
    "T1057": {"score": 5.8, "tactic": "discovery"},
    "T1083": {"score": 5.5, "tactic": "discovery"},

    "T1622": {"score": 6.5, "tactic": "defense-evasion"},
    "T1497": {"score": 6.5, "tactic": "defense-evasion"},
    "T1027": {"score": 7.0, "tactic": "defense-evasion"},
    "T1027.002": {"score": 7.2, "tactic": "defense-evasion"},
    "T1620": {"score": 7.5, "tactic": "defense-evasion"},

    "T1059": {"score": 7.5, "tactic": "execution"},
    "T1059.001": {"score": 7.8, "tactic": "execution"},
    "T1059.003": {"score": 7.5, "tactic": "execution"},

    "T1119": {"score": 6.5, "tactic": "collection"},
    "T1560": {"score": 7.0, "tactic": "collection"},

    "T1485": {"score": 9.0, "tactic": "impact"},
    "T1486": {"score": 9.5, "tactic": "impact"},
    "T1529": {"score": 8.5, "tactic": "impact"},
}


# ----------------------------------
# Risk Level
# ----------------------------------
def classify_risk(score):
    if score >= 9:
        return "CRITICAL"
    elif score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "NONE"


# ----------------------------------
# FINAL CVSS ENGINE (FIXED)
# ----------------------------------
def calculate_cvss_score(mitre_ids, capabilities=None):

    debug_log("CVSS INPUT", {"mitre_ids": mitre_ids, "capabilities": capabilities})

    if not mitre_ids and not capabilities:
        return {
            "cvss_score": 0.0,
            "risk_level": "NONE",
            "technique_count": 0,
            "tactic_coverage": [],
            "confidence": 0
        }

    unique_ids = sorted(set(filter(None, mitre_ids)))
    scores = []
    tactics = set()

    # -------------------------
    # MITRE scoring
    # -------------------------
    for tid in unique_ids:
        entry = MITRE_RISK_DB.get(tid)   # ✅ ADD THIS

        if not entry:
            debug_log("CVSS UNKNOWN MITRE", tid)
            continue

        scores.append(entry["score"])
        tactics.add(entry["tactic"])

    # -------------------------
    # BASE SCORE
    # -------------------------
    if scores:
        base = sum(scores) / len(scores)
    else:
        base = min(4.0 + len(unique_ids) * 0.5, 7.0)

    # -------------------------
    # COMPLEXITY
    # -------------------------
    complexity = min(len(unique_ids) * 0.25, 1.5)

    # -------------------------
    # TACTIC DIVERSITY
    # -------------------------
    diversity = min(len(tactics) * 0.2, 1.0)

    # -------------------------
    # CAPABILITY BOOST (NEW 🔥)
    # -------------------------
    capability_bonus = 0

    if capabilities:
        for cap in capabilities:
            cap_lower = cap.lower()

            if cap_lower == "execution":
                capability_bonus += 1.5
            elif cap_lower == "process_injection":
                capability_bonus += 1.5
            elif cap_lower == "command_and_control":
                capability_bonus += 1.0
            elif cap_lower == "credential_access":
                capability_bonus += 1.5

    capability_bonus = min(capability_bonus, 2.5)

    # -------------------------
    # FINAL SCORE
    # -------------------------
    final_score = min(base + complexity + diversity + capability_bonus, 10)
    final_score = round(final_score, 2)

    # -------------------------
    # CONFIDENCE
    # -------------------------
    confidence = min(100, int((len(scores) / max(len(unique_ids), 1)) * 100))

    result = {
        "cvss_score": final_score,
        "risk_level": classify_risk(final_score),
        "technique_count": len(unique_ids),
        "tactic_coverage": sorted(list(tactics)),
        "confidence": confidence
    }

    debug_log("CVSS FINAL RESULT", result)

    return result