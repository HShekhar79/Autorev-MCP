from utils.normalization import normalize_behavior


def classify_binary_behaviour(function_results: list, extra_behaviours: list = None) -> list:

    if not function_results:
        return []

    behaviours = set()

    # -------------------------
    # Function behaviours
    # -------------------------
    for f in function_results:
        if not isinstance(f, dict):
            continue

        for b in f.get("behaviours", f.get("behaviour", [])):

            if isinstance(b, dict):
                raw = b.get("name") or b.get("behavior") or b.get("behaviour")
            else:
                raw = str(b) if b else None

            canonical = normalize_behavior(raw)

            if canonical:
                behaviours.add(canonical)

    # -------------------------
    # Extra behaviours (imports / capa)
    # -------------------------
    if extra_behaviours:
        for b in extra_behaviours:
            raw = b.get("name") if isinstance(b, dict) else b
            canonical = normalize_behavior(raw)

            if canonical:
                behaviours.add(canonical)

    # -------------------------
    # Classification rules
    # -------------------------
    classification = []

    if "payload_download" in behaviours:
        classification.append("Downloader")

    if "process_injection" in behaviours or "process_hollowing" in behaviours:
        classification.append("Injector")

    if "registry_persistence" in behaviours or "startup_persistence" in behaviours or "service_creation" in behaviours:
        classification.append("Persistence")

    if "anti_debugging" in behaviours or "anti_vm" in behaviours or "anti_sandbox" in behaviours:
        classification.append("Anti-Analysis")

    if "network_activity" in behaviours or "command_and_control" in behaviours:
        classification.append("Network-Enabled")

    if "credential_dumping" in behaviours or "keylogging" in behaviours:
        classification.append("Credential-Stealer")

    if "data_exfiltration" in behaviours:
        classification.append("Exfiltrator")

    if "cryptographic_activity" in behaviours:
        classification.append("Encryptor")

    return classification