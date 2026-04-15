from utils.normalization import extract_behavior_name


def generate_ai_function_name(function: dict) -> str:

    calls = function.get("calls") or []
    behaviours = (
        function.get("behaviors")
        or function.get("behaviours")
        or function.get("behaviour")
        or []
    )

    behaviour_names = []

    for b in behaviours:
        name = extract_behavior_name(b)
        if name:
            behaviour_names.append(name)

    behaviour_set = set(behaviour_names)  # 🔥 optional optimization

    call_text = " ".join(str(c).lower() for c in calls)

    # Behaviour-based
    if "process_injection" in behaviour_set:
        return "inject_remote_process"
    if "process_hollowing" in behaviour_set:
        return "hollow_remote_process"
    if "payload_download" in behaviour_set:
        return "download_payload"
    if "command_and_control" in behaviour_set:
        return "c2_communication"
    if "registry_persistence" in behaviour_set:
        return "establish_registry_persistence"
    if "credential_dumping" in behaviour_set:
        return "dump_credentials"
    if "keylogging" in behaviour_set:
        return "capture_keystrokes"
    if "system_information_discovery" in behaviour_set:
        return "collect_system_information"
    if "cryptographic_activity" in behaviour_set:
        return "encrypt_or_decrypt_data"
    if "privilege_escalation" in behaviour_set:
        return "escalate_privileges"
    if "anti_debugging" in behaviour_set:
        return "evade_debugger"

    # API fallback
    if "createremotethread" in call_text:
        return "inject_remote_thread"
    if "writeprocessmemory" in call_text:
        return "write_into_remote_process"
    if "internetopen" in call_text:
        return "internet_connection"
    if "urldownloadtofile" in call_text:
        return "download_file_from_url"
    if "createfile" in call_text and "writefile" in call_text:
        return "write_file_to_disk"
    if "deletefile" in call_text:
        return "delete_file"
    if "regsetvalue" in call_text:
        return "modify_registry"
    if "createprocess" in call_text:
        return "spawn_new_process"

    return "generic_function"


def rename_functions(function_analysis: list) -> list:

    renamed = []

    for f in function_analysis:
        if not isinstance(f, dict):
            continue

        ai_name = generate_ai_function_name(f)

        renamed.append({
            "function_name": f.get("function_name"),
            "ai_name": ai_name,
            "risk_score": f.get("risk_score"),
            "behaviors": (
                f.get("behaviors")
                or f.get("behaviours")
                or f.get("behaviour", [])
            ),
        })

    return renamed