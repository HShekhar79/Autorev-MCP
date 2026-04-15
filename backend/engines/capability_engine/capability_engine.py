"""
engines/capability_engine/capability_engine.py

Maps detected canonical behavior names -> high-level attack capabilities.

ROOT CAUSE FIX:
    map_behaviours() had a silent fallback:
        if not mapped_caps:
            mapped_caps = ["execution"]   # <- BUG

    This caused ALL unrecognized CAPA names to be incorrectly mapped to
    "execution", even after they were canonicalized. The fallback is removed.
    Unrecognized names are now logged and skipped, not silently reassigned.

    The fix works because capa_engine.py now translates CAPA rule names to
    canonical behavior names (via CAPA_TO_CANONICAL) BEFORE they reach this
    engine, so recognized canonical names pass through the mapping correctly.
"""

from utils.debug import debug_log
from utils.normalization import normalize_behavior, extract_behavior_name
from utils.normalization import CANONICAL_BEHAVIORS


class CapabilityEngine:

    def __init__(self):

        # behavior -> capability mapping (canonical names only as keys)
        self.mapping = {
            "command_execution":            ["execution"],
            "process_creation":             ["execution"],

            "network_communication":        ["command_and_control"],
            "command_and_control":          ["command_and_control"],
            "network_activity":             ["command_and_control"],
            "payload_download":             ["command_and_control"],
            "http_communication":           ["command_and_control"],
            "ftp_communication":            ["command_and_control"],
            "data_exfiltration":            ["command_and_control", "exfiltration"],
            "dns_activity":                 ["command_and_control"],

            "registry_persistence":         ["persistence"],
            "startup_persistence":          ["persistence"],
            "service_creation":             ["persistence"],
            "scheduled_task_creation":      ["persistence"],

            "process_injection":            ["defense_evasion"],
            "process_hollowing":            ["defense_evasion"],
            "dynamic_api_resolution":       ["defense_evasion"],
            "dynamic_loading":              ["defense_evasion"],
            "anti_debugging":               ["defense_evasion"],
            "anti_vm":                      ["defense_evasion"],
            "anti_sandbox":                 ["defense_evasion"],
            "memory_protection_change":     ["defense_evasion"],
            "packing_detection":            ["defense_evasion"],
            "memory_allocation":            ["defense_evasion"],
            "registry_modification":        ["defense_evasion"],
            "random_generation":            ["defense_evasion"],
            "indirect_call_execution":      ["defense_evasion"],

            "process_termination":          ["impact"],
            "file_deletion":                ["impact"],
            "shutdown_system":              ["impact"],
            "reboot_system":                ["impact"],

            "system_discovery":             ["discovery"],
            "system_information_discovery": ["discovery"],
            "process_enumeration":          ["discovery"],
            "module_enumeration":           ["discovery"],
            "user_enumeration":             ["discovery"],
            "directory_enumeration":        ["discovery"],
            "registry_query":               ["discovery"],

            "file_modification":            ["collection"],
            "file_creation":                ["collection"],
            "file_copy":                    ["collection"],
            "file_move":                    ["collection"],
            "keylogging":                   ["collection"],
            "cryptographic_activity":       ["collection"],

            "credential_dumping":           ["credential_access"],
            "token_manipulation":           ["credential_access"],

            "privilege_escalation":         ["privilege_escalation"],

            "unknown_external_activity":    ["execution"],
        }

        self.weights = {
            "execution":            2,
            "command_and_control":  3,
            "persistence":          3,
            "defense_evasion":      2,
            "discovery":            1,
            "collection":           1,
            "exfiltration":         3,
            "credential_access":    3,
            "privilege_escalation": 3,
            "impact":               2,
        }

    # ------------------------------------------------------------------
    # INPUT NORMALISATION
    # ------------------------------------------------------------------
    def _normalise_input(self, behaviours):
        """
        Accept any input shape and return (canonical_name, confidence) pairs.

        Shape 1: dict {"behaviors": [...], "_detail": [...]}
        Shape 2: list of dicts or strings
        """
        result = []

        if isinstance(behaviours, dict):
            names = behaviours.get("behaviors", [])
            detail = behaviours.get("_detail", [])

            detail_map = {
                normalize_behavior(d.get("name", "")): float(d.get("confidence", 0.8))
                for d in detail if isinstance(d, dict) and d.get("name")
            }

            for raw in names:
                canonical = normalize_behavior(raw)
                if canonical:
                    confidence = detail_map.get(canonical, 0.8)
                    result.append((canonical, confidence))

            return result

        if isinstance(behaviours, list):
            for b in behaviours:
                raw_name = extract_behavior_name(b)
                canonical = normalize_behavior(raw_name)

                if not canonical:
                    continue

                # Informational names carry no capability signal
                if canonical in ("internal_function_calls", "no_external_activity"):
                    continue

                confidence = float(b.get("confidence", 0.8)) if isinstance(b, dict) else 0.8
                result.append((canonical, confidence))

            return result

        return []

    # ------------------------------------------------------------------
    # CORE MAPPING
    # ------------------------------------------------------------------
    def map_behaviours(self, behaviours):
        """
        Map canonical behavior names -> capability scores.

        FIX: Removed the silent "execution" fallback for unrecognized names.
        Previously ALL names not in self.mapping got mapped to "execution",
        causing all un-translated CAPA names to add spurious execution scores.
        Now unrecognized names are logged and skipped cleanly.
        """
        capability_scores = {}
        seen = set()

        pairs = self._normalise_input(behaviours)
        debug_log("CapabilityEngine normalized pairs", pairs)

        for name, confidence in pairs:

            if name in seen:
                continue
            seen.add(name)

            mapped_caps = self.mapping.get(name)

            if not mapped_caps:
                # FIX: was mapped_caps = ["execution"] -- silent incorrect fallback removed
                debug_log("[CAP] NO MAPPING (skipped)", name)
                continue

            for cap in mapped_caps:
                weight = self.weights.get(cap, 1)
                score = round(weight * confidence, 2)

                if cap not in capability_scores or score > capability_scores[cap]:
                    capability_scores[cap] = score
                    debug_log("[CAP MAP]", "%s -> %s (%.2f)" % (name, cap, score))

        return capability_scores

    # ------------------------------------------------------------------
    # ENTRY POINT
    # ------------------------------------------------------------------
    def run(self, behaviours):
        """
        Main entry point.

        Args:
            behaviours: dict {"behaviors": [...], "_detail": [...]}
                        or list of behavior dicts/strings

        Returns:
            {
                "capabilities": ["command_and_control", ...],
                "scores": {"command_and_control": 2.7, ...}
            }
        """
        debug_log("CapabilityEngine INPUT type", type(behaviours).__name__)

        scores = self.map_behaviours(behaviours)
        sorted_caps = sorted(scores.items(), key=lambda x: (-x[1], x[0]))

        result = {
            "capabilities": [c for c, _ in sorted_caps],
            "scores": scores,
        }

        debug_log("CapabilityEngine OUTPUT", result)
        return result
