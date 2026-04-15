"""
import_behaviour_engine.py

Derives behaviours directly from the binary's import table.
This is a reliable fallback when function-level call extraction fails,
and also catches APIs that are dynamically resolved via GetProcAddress.

Works with the output of extract_imports() — list of dicts or strings.

BUG FIXES:
1. analyze_imports_for_behaviour now returns STANDARDIZED format
   {"name": ..., "source": "imports", "confidence": ...}
   Previously returned {"api": ..., "behavior": ...} causing downstream mismatch.
2. Normalization logic fixed: regex now strips both A and W suffixes properly.
3. get_behaviour_summary now reads "name" key (was reading "behavior").
"""

import re
from utils.debug import debug_log


# Canonical API → Behaviour mapping (case-insensitive matching)
IMPORT_BEHAVIOUR_RULES = {
    # ---- NETWORK ----
    "network_activity": [
        "internetopen", "internetconnect", "internetreadfile",
        "winhttpopenrequest", "winhttpsendrequest", "winhttpreaddata",
        "socket", "connect", "wsastartup", "wsaconnect"
    ],
    "network_communication": [
        "socket", "connect", "recv", "send", "wsaconnect",
        "internetconnect", "winhttpsendrequest", "httpopenrequest"
    ],
    "payload_download": [
        "urldownloadtofile", "urldownloadtocacheentry",
        "winhttpreaddata", "internetreadfile"
    ],
    "command_and_control": [
        "httpsendrequestex", "httpopenrequest", "internetconnect",
        "winhttpsendrequest", "recv", "send"
    ],
    "dns_activity": [
        "dnsquery", "gethostbyname", "getaddrinfo", "dnsquerya"
    ],
    "data_exfiltration": [
        "send", "wsasend", "ftpputfile"
    ],
    "ftp_communication": [
        "ftpputfile", "ftpopenfile", "ftpgetfile"
    ],

    # ---- PROCESS ----
    "process_creation": [
        "createprocess", "createprocessw", "createprocessa",
        "winexec", "shellexecute", "shellexecuteex"
    ],
    "process_injection": [
        "createremotethread", "createremotethreadex",
        "writeprocessmemory", "ntwritevirtualmemory",
        "virtualallocex", "openprocess", "ntcreatethreadex",
        "setthreadcontext"
    ],
    "process_hollowing": [
        "zwunmapviewofsection", "ntunmapviewofsection"
    ],
    "process_termination": [
        "terminateprocess", "exitprocess"
    ],

    # ---- FILESYSTEM ----
    "file_creation": [
        "createfile", "createfilea", "createfilew", "writefile"
    ],
    "file_deletion": [
        "deletefile", "deletefilea", "deletefilew",
        "ntdeletefile", "shdeletepath"
    ],
    "file_modification": [
        "writefile", "setfileattributes", "movefile", "copyfile"
    ],
    "file_copy": ["copyfile", "copyfileex"],
    "file_move": ["movefile", "movefileex"],
    "directory_enumeration": [
        "findfirstfile", "findnextfile",
        "findfirstfilea", "findfirstfilew"
    ],

    # ---- REGISTRY ----
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

    # ---- PERSISTENCE ----
    "service_creation": [
        "createservice", "createservicea", "createservicew",
        "startservice", "openscmanager"
    ],
    "scheduled_task_creation": [
        "itaskscheduler", "itasktrigger"
    ],

    # ---- ANTI-ANALYSIS ----
    "anti_debugging": [
        "isdebuggerpresent", "checkremotedebuggerpresent",
        "ntqueryinformationprocess", "outputdebugstring",
        "debugbreak"
    ],
    "anti_vm": [
        "vboxhook", "vmtoolsd", "vmwarebase", "vboxservice"
    ],

    # ---- CREDENTIALS ----
    "credential_dumping": [
        "lsaopenpolicy", "lsaretrieveprivatedata",
        "credenumerate", "minidumpwritedump",
        "samopendb", "samtypes"
    ],
    "keylogging": [
        "setwindowshookexa", "setwindowshookexw",
        "getasynckeystate", "getkeystate"
    ],

    # ---- DISCOVERY ----
    "system_information_discovery": [
        "getsysteminfo", "getcomputername", "getusername",
        "getversion", "rtlgetversion", "getnativesysteminfo"
    ],
    "system_discovery": [
        "getsysteminfo", "getcomputername", "getusername",
        "getversion", "rtlgetversion"
    ],
    "user_enumeration": ["netuserenum", "netusergetinfo"],
    "process_enumeration": [
        "process32first", "process32next",
        "createtoolhelp32snapshot", "enumprocesses"
    ],
    "module_enumeration": [
        "enumprocessmodules", "module32first", "module32next"
    ],

    # ---- MEMORY ----
    "memory_allocation": [
        "virtualalloc", "virtualallocex", "heapalloc", "rtlallocateheap"
    ],
    "memory_protection_change": [
        "virtualprotect", "virtualprotectex"
    ],

    # ---- CRYPTO ----
    "cryptographic_activity": [
        "cryptencrypt", "cryptdecrypt", "cryptacquirecontext",
        "bcryptencrypt", "bcryptdecrypt", "bcryptopenalgorithmprovider"
    ],
    "random_generation": [
        "cryptgenrandom", "rtlgenrandom", "bcryptgenrandom"
    ],

    # ---- PRIVILEGES ----
    "privilege_escalation": [
        "adjusttokenprivileges", "lookupprivilegevalue"
    ],
    "token_manipulation": [
        "openprocesstoken", "duplicatetoken", "impersonateloggedonuser",
        "createprocesswithtokenw"
    ],

    # ---- OBFUSCATION ----
    "dynamic_loading": [
        "loadlibrary", "loadlibrarya", "loadlibraryw",
        "getprocaddress", "ldrloaddll"
    ],
    "dynamic_api_resolution": [
        "getprocaddress", "loadlibrary", "ldrloaddll"
    ],

    # ---- COMMAND EXECUTION ----
    "command_execution": [
        "createprocess", "winexec", "shellexecute",
        "system", "cmd", "powershell"
    ],

    # ---- SYSTEM CONTROL ----
    "shutdown_system": ["exitwindowsex"],
    "reboot_system": ["initiatesystemshutdown"],
}

from utils.normalization import normalize_behavior

# FAST LOOKUP (GLOBAL)
IMPORT_LOOKUP = {}

for behaviour, patterns in IMPORT_BEHAVIOUR_RULES.items():
    for p in patterns:
        IMPORT_LOOKUP[p] = behaviour

def analyze_imports_for_behaviour(imports_list: list) -> list:

    if not imports_list:
        return []

    detected = []
    seen = set()

    for imp in imports_list:

        if isinstance(imp, str):
            api_name = imp
        elif isinstance(imp, dict):
            api_name = imp.get("name", "")
        else:
            continue

        api_name = str(api_name).lower().strip()

        api_norm = re.sub(r"(?<=\w{4})[aw]$", "", api_name)

        # FAST MATCHING
        for pattern, behaviour in IMPORT_LOOKUP.items():

            if pattern in api_norm or pattern in api_name:

                canonical = normalize_behavior(behaviour)

                if not canonical:
                    continue

                if canonical not in seen:
                    seen.add(canonical)

                    detected.append({
                        "name": canonical,
                        "source": "imports",
                        "confidence": 0.9
                    })

                break

    debug_log("analyze_imports_for_behaviour RESULT", detected)

    return detected


def get_behaviour_summary(import_behaviours: list) -> list:
    """
    Return unique behaviour names from import analysis.

    BUG FIX: was reading "behavior" key; now reads "name" key
    to match standardized format.
    """
    # BUG FIX: key was "behavior", now "name"
    return list({b["name"] for b in import_behaviours if "name" in b})