"""
capability_mitre_engine.py

Maps high-level capabilities → MITRE ATT&CK techniques.
Target architecture: behaviour → capability → MITRE

Input:
    capabilities: list[str]
    scores: dict[str, float]

Output:
    {
        "mitre_techniques": [...],
        "scores": {"T1071": 2.4, ...},
        "ranked": ["T1071", ...]
    }
"""

from utils.debug import debug_log


CAPABILITY_MITRE_MAP = {
    "execution":            ["T1059", "T1204"],
    "command_and_control":  ["T1071", "T1105"],
    "persistence":          ["T1547", "T1053"],
    "defense_evasion":      ["T1027", "T1055"],
    "credential_access":    ["T1003"],
    "discovery":            ["T1082", "T1057"],
    "collection":           ["T1119"],
    "exfiltration":         ["T1041"],
    "impact":               ["T1485", "T1486"],
    "privilege_escalation": ["T1068", "T1134"],
}


class CapabilityMitreEngine:

    def __init__(self):
        self.mapping = CAPABILITY_MITRE_MAP

    def run(self, capabilities: list, scores: dict) -> dict:
        """
        Map capabilities to MITRE techniques using their scores.

        Args:
            capabilities: list of capability name strings
            scores: dict of {capability_name: float_score}

        Returns:
            {
                "mitre_techniques": list[str],
                "scores": dict[str, float],
                "ranked": list[str]
            }
        """
        if not capabilities:
            return {
                "mitre_techniques": [],
                "scores": {},
                "ranked": []
            }

        technique_scores = {}

        for cap in capabilities:
            if not isinstance(cap, str):
                continue

            cap = cap.lower().strip()

            if cap not in self.mapping:
                debug_log("CapabilityMitreEngine UNKNOWN CAP", cap)
                continue

            score = float(scores.get(cap, 1.0))
            techniques = self.mapping.get(cap, self.mapping.get("execution", []))

            for technique in techniques:
                if technique not in technique_scores:
                    technique_scores[technique] = score
                else:
                    # Keep MAX score — not cumulative sum
                    technique_scores[technique] = max(technique_scores[technique], score)

        # Round scores
        technique_scores = {
            t: round(s, 2)
            for t, s in technique_scores.items()
        }

        # Sort by score DESC, then alphabetically for stable ordering
        ranked = sorted(
            technique_scores.keys(),
            key=lambda t: (-technique_scores[t], t)
        )

        result = {
            "mitre_techniques": sorted(technique_scores.keys()),
            "scores": technique_scores,
            "ranked": ranked
        }

        debug_log("CapabilityMitreEngine OUTPUT", result)

        return result