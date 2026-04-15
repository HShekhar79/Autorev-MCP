from utils.debug import debug_log
from utils.normalization import normalize_behavior, CANONICAL_BEHAVIORS

# =============================================================================
# BEHAVIOUR RULES
# Canonical lowercase API token patterns → canonical behaviour name.
# Keys MUST be members of CANONICAL_BEHAVIORS (validated at module load).
# =============================================================================

BEHAVIOUR_RULES = {

    # -----------------------------
    # NETWORK
    # -----------------------------
    "network_activity": [
        "internetopen", "internetconnect", "socket", "connect",
        "wsastartup", "wsaconnect", "bind", "listen", "accept"
    ],
    "payload_download": [
        "urldownloadtofile", "urlmon", "winhttpopenrequest", "winhttpreaddata",
        "internetreadfile", "urldownloadtocacheentry"
    ],
    "command_and_control": [
        "winhttp", "internetreadfile", "recv", "send",
        "httpopenrequest", "httpsendrequestex", "winhttpsendrequest"
    ],
    "http_communication": [
        "httpopenrequest", "winhttpopenrequest", "httpsendrequestex"
    ],
    "ftp_communication": [
        "ftpputfile", "ftpopenfile", "ftpgetfile"
    ],
    "dns_activity": [
        "dnsquery", "gethostbyname", "getaddrinfo", "dnsquerya"
    ],
    "data_exfiltration": [
        "send", "wsasend", "ftpputfile"
    ],
    "network_communication": [
        "socket", "connect", "recv", "send", "wsaconnect",
        "internetconnect", "winhttpsendrequest", "httpopenrequest"
    ],

    # -----------------------------
    # PROCESS
    # -----------------------------
    "process_creation": [
        "createprocess", "winexec", "shellexecute", "shellexecuteex",
        "createprocessw", "createprocessa"
    ],
    "process_termination": [
        "terminateprocess", "exitprocess"
    ],
    "process_injection": [
        "createremotethread", "createremotethreadex",
        "writeprocessmemory", "ntwritevirtualmemory",
        "openprocess", "ntcreatethreadex", "setthreadcontext",
        "virtualallocex"
    ],
    "process_hollowing": [
        "zwunmapviewofsection", "ntunmapviewofsection"
    ],

    # -----------------------------
    # FILESYSTEM
    # -----------------------------
    "file_creation": [
        "createfile", "createfilea", "createfilew", "writefile"
    ],
    "file_modification": [
        "writefile", "setfileattributes"
    ],
    "file_deletion": [
        "deletefile", "deletefilea", "deletefilew", "ntdeletefile"
    ],
    "file_copy": [
        "copyfile", "copyfileex"
    ],
    "file_move": [
        "movefile", "movefileex"
    ],
    "directory_enumeration": [
        "findfirstfile", "findnextfile",
        "findfirstfilea", "findfirstfilew"
    ],

    # -----------------------------
    # REGISTRY
    # -----------------------------
    "registry_persistence": [
        "regsetvalue", "regsetvalueexa", "regsetvalueexw",
        "regcreatekey", "regcreatekeya", "regcreatekeyex"
    ],
    "registry_modification": [
        "regsetvalue", "regdeletevalue", "regdeletekey"
    ],
    "registry_query": [
        "regqueryvalue", "regqueryvalueex", "regopenkeyex"
    ],

    # -----------------------------
    # PERSISTENCE
    # -----------------------------
    "startup_persistence": [
        "regsetvalue", "startup"
    ],
    "service_creation": [
        "createservice", "createservicea", "createservicew",
        "startservice", "openscmanager"
    ],
    "scheduled_task_creation": [
        "schtasks", "itaskscheduler", "itasktrigger"
    ],

    # -----------------------------
    # ANTI-ANALYSIS
    # -----------------------------
    "anti_debugging": [
        "isdebuggerpresent", "checkremotedebuggerpresent",
        "ntqueryinformationprocess", "outputdebugstring", "debugbreak"
    ],
    "anti_vm": [
        "vmware", "virtualbox", "vboxhook", "vmtoolsd"
    ],
    "anti_sandbox": [
        "sandbox"
    ],

    # -----------------------------
    # CREDENTIALS
    # -----------------------------
    "credential_dumping": [
        "lsass", "minidumpwritedump", "lsaopenpolicy",
        "lsaretrieveprivatedata", "credenumerate",
        "samopendb", "samtypes"
    ],
    "keylogging": [
        "setwindowshook", "setwindowshookexa", "setwindowshookexw",
        "getasynckeystate", "getkeystate"
    ],

    # -----------------------------
    # SYSTEM DISCOVERY
    # -----------------------------
    "system_information_discovery": [
        "getsysteminfo", "getversion", "getcomputername",
        "getusername", "rtlgetversion", "getnativesysteminfo"
    ],
    "system_discovery": [
        "getsysteminfo", "getcomputername", "getusername",
        "getversion", "rtlgetversion"
    ],
    "user_enumeration": [
        "netuserenum", "netusergetinfo"
    ],

    # -----------------------------
    # MONITORING / ENUMERATION
    # -----------------------------
    "process_enumeration": [
        "createtoolhelp32snapshot", "process32first",
        "process32next", "enumprocesses"
    ],
    "module_enumeration": [
        "module32first", "module32next", "enumprocessmodules"
    ],

    # -----------------------------
    # MEMORY
    # -----------------------------
    "memory_allocation": [
        "virtualalloc", "virtualallocex", "heapalloc", "rtlallocateheap"
    ],
    "memory_protection_change": [
        "virtualprotect", "virtualprotectex"
    ],

    # -----------------------------
    # CRYPTO
    # -----------------------------
    "cryptographic_activity": [
        "cryptencrypt", "cryptdecrypt", "cryptacquirecontext",
        "bcryptencrypt", "bcryptdecrypt", "bcryptopenalgorithmprovider"
    ],
    "random_generation": [
        "rand", "cryptgenrandom", "rtlgenrandom", "bcryptgenrandom"
    ],

    # -----------------------------
    # PRIVILEGES
    # -----------------------------
    "privilege_escalation": [
        "adjusttokenprivileges", "lookupprivilegevalue"
    ],
    "token_manipulation": [
        "opentoken", "duplicatetoken", "openprocesstoken",
        "impersonateloggedonuser", "createprocesswithtokenw"
    ],

    # -----------------------------
    # SYSTEM CONTROL
    # -----------------------------
    "shutdown_system": [
        "exitwindowsex"
    ],
    "reboot_system": [
        "reboot", "initiatesystemshutdown"
    ],

    # -----------------------------
    # OBFUSCATION / DYNAMIC LOADING
    # -----------------------------
    "packing_detection": [
        "upx", "packer"
    ],
    "dynamic_loading": [
        "loadlibrary", "loadlibrarya", "loadlibraryw",
        "getprocaddress", "ldrloaddll"
    ],
    "dynamic_api_resolution": [
        "getprocaddress", "loadlibrary", "ldrloaddll"
    ],

    # -----------------------------
    # COMMAND EXECUTION
    # -----------------------------
    "command_execution": [
        "createprocess", "winexec", "shellexecute",
        "system", "cmd", "powershell"
    ],
}


# Validate at import time: every BEHAVIOUR_RULES key must be canonical.
# This catches rule additions that don't update CANONICAL_BEHAVIORS.
_CANONICAL_SET = set(CANONICAL_BEHAVIORS)
_invalid_keys = [k for k in BEHAVIOUR_RULES if k not in _CANONICAL_SET]
if _invalid_keys:
    raise ValueError(
        "behaviour_engine: BEHAVIOUR_RULES contains non-canonical keys: %s\n"
        "Add them to CANONICAL_BEHAVIORS in utils/normalization.py first."
        % _invalid_keys
    )

# =============================================================================
# MAIN FUNCTION (FIXED)
# =============================================================================

# BUILD LOOKUP
PATTERN_LOOKUP = {}

for behaviour, patterns in BEHAVIOUR_RULES.items():
    for p in patterns:
        PATTERN_LOOKUP[p] = behaviour
        
def detect_behaviour_from_calls(calls, source="function_calls", confidence=0.8):

    if not calls:
        return {"behaviors": [], "_detail": []}

    # Normalize calls
    calls_lower = [
        c.strip().lower()
        for c in calls
        if isinstance(c, str) and c.strip()
    ]

    detected_names = set()

    # Fast lookup
    for call in calls_lower:
        behaviour = PATTERN_LOOKUP.get(call)

        if not behaviour:
            continue

        canonical = normalize_behavior(behaviour)

        if not canonical:
            continue

        if canonical not in CANONICAL_BEHAVIORS:
            debug_log("[INVALID CANONICAL]", canonical)
            continue

        detected_names.add(canonical)
        debug_log("[MATCH]", f"{call} → {canonical}")

    # Build output
    detail = [
        {"name": name, "source": source, "confidence": confidence}
        for name in sorted(detected_names)
    ]

    result = {
        "behaviors": sorted(detected_names),
        "_detail": detail,
    }

    debug_log("detect_behaviour_from_calls RESULT", result)

    return result