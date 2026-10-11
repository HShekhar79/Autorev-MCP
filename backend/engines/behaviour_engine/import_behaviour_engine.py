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
    # recv/send removed: raw socket I/O is the transport primitive of any networked
    # program; C2 / exfiltration need destination or payload context that an import
    # table cannot provide (see COLLISION DECISIONS below).
    "command_and_control": [
        "httpsendrequestex", "httpopenrequest", "internetconnect",
        "winhttpsendrequest"
    ],
    "dns_activity": [
        "dnsquery", "gethostbyname", "getaddrinfo", "dnsquerya"
    ],
    "data_exfiltration": [
        "wsasend", "ftpputfile"
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
        "ntcreatethreadex", "setthreadcontext"
    ],
    "process_hollowing": [
        "zwunmapviewofsection", "ntunmapviewofsection"
    ],
    "process_termination": [
        "terminateprocess"
    ],

    # ---- FILESYSTEM ----
    # writefile removed: WriteFile writes to an existing handle; creation is shown by
    # CreateFile (file_modification is kept for WriteFile).
    "file_creation": [
        "createfile", "createfilea", "createfilew"
    ],
    "file_deletion": [
        "deletefile", "deletefilea", "deletefilew",
        "ntdeletefile", "shdeletepath"
    ],
    # movefile/copyfile removed: redundant with the specific file_move / file_copy
    # labels (matches the function-level rule set in behaviour_engine.py).
    "file_modification": [
        "writefile", "setfileattributes"
    ],
    "file_copy": ["copyfile", "copyfileex"],
    "file_move": ["movefile", "movefileex"],
    "directory_enumeration": [
        "findfirstfile", "findnextfile",
        "findfirstfilea", "findfirstfilew"
    ],

    # ---- REGISTRY ----
    # regsetvalue* removed: writing a registry value does not by itself show
    # persistence intent (registry_modification is kept for it).
    "registry_persistence": [
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


# =============================================================================
# MATCHING STRATEGY (deterministic, explicit, conservative)
#
# Import-table evidence means "the binary imports this API". It is NOT proof that
# the high-level behaviour was performed.
#
# 1. Names are cleaned (lower-case, radare2 symbol prefixes and "<lib>.dll_" style
#    prefixes removed).
# 2. A cleaned name matches ONLY an explicit spelling in IMPORT_API_INDEX:
#       - a pattern literally listed in IMPORT_BEHAVIOUR_RULES, or
#       - base + "a" / "w" for a base listed in _ANSI_WIDE_BASES (the ANSI and
#         Unicode exports of the SAME Win32 function), or
#       - a spelling listed in _EXPLICIT_ALIASES.
#    Nothing else is generated: no Ex / ExA / ExW forms, no suffixes on any other
#    pattern. There is NO arbitrary substring matching, so SystemTime,
#    ConnectionReset, SocketTimeout, ConnectNamedPipe, CreateFileMapping,
#    ConnectEx, SystemA ... never match.
# 3. Patterns in EXACT_MATCH_ONLY ("system", "cmd") match the whole name only.
# 4. An API listed under several behaviours yields ALL of them (one entry per
#    canonical name). Dictionary insertion order no longer decides anything.
#
# COLLISION DECISIONS (APIs that the rules list under more than one behaviour):
#   Principle: keep every label that DESCRIBES the API's own operation; do not
#   assert attacker-intent labels (command_and_control, data_exfiltration,
#   registry_persistence, process_injection) from generic primitives whose import
#   alone cannot support them. Function/call-level evidence may still assert them.
#
#   KEPT AS MULTI-BEHAVIOUR (all labels explicit and descriptive):
#     connect, socket, wsaconnect, internetconnect, winhttpsendrequest,
#     httpopenrequest, internetreadfile, winhttpreaddata, ftpputfile,
#     createprocess, winexec, shellexecute, getprocaddress, loadlibrary,
#     ldrloaddll, getsysteminfo, getcomputername, getusername, getversion,
#     rtlgetversion
#   TRIMMED (label removed from the rule lists above):
#     send           -> command_and_control, data_exfiltration  (context required)
#     recv           -> command_and_control                     (context required)
#     virtualallocex -> process_injection                       (context required)
#     regsetvalue*   -> registry_persistence                    (context required)
#     writefile      -> file_creation                           (CreateFile shows creation)
#     copyfile       -> file_modification                       (redundant with file_copy)
#     movefile       -> file_modification                       (redundant with file_move)
# =============================================================================

# LEGACY single-behaviour view (last-write-wins). NOT used by the matcher; kept only
# so existing imports/tests of IMPORT_LOOKUP keep working. Do not use it to decide
# which behaviours an API produces -- use IMPORT_PATTERN_BEHAVIOURS instead.
IMPORT_LOOKUP = {}

for behaviour, patterns in IMPORT_BEHAVIOUR_RULES.items():
    for p in patterns:
        IMPORT_LOOKUP[p] = behaviour

# Patterns that must match the whole API name only (no A/W/Ex variants).
EXACT_MATCH_ONLY = frozenset({"system", "cmd"})

# pattern -> tuple of ALL behaviours the rules assign to it (no information loss)
_pattern_buckets: dict = {}
for _behaviour, _patterns in IMPORT_BEHAVIOUR_RULES.items():
    for _p in _patterns:
        _bucket = _pattern_buckets.setdefault(_p, [])
        if _behaviour not in _bucket:
            _bucket.append(_behaviour)
IMPORT_PATTERN_BEHAVIOURS = {p: tuple(b) for p, b in _pattern_buckets.items()}

# Win32 functions that ship separate ANSI ("A") and Unicode ("W") exports. Only these
# bases receive "a"/"w" spellings (CreateFileA, RegQueryValueExW, ...). Each base must
# itself be a rule pattern (checked at import time). Distinct functions that merely
# look similar (ConnectEx, GetVersionEx, LoadLibraryEx, WriteFileEx, ...) are NOT
# derived and match only if the rules list them literally.
_ANSI_WIDE_BASES = (
    "internetopen", "internetconnect", "urldownloadtofile", "urldownloadtocacheentry",
    "httpopenrequest", "httpsendrequestex", "ftpputfile", "ftpopenfile", "ftpgetfile",
    "createprocess", "shellexecute", "shellexecuteex",
    "createfile", "deletefile", "setfileattributes", "copyfile", "copyfileex",
    "movefile", "movefileex", "findfirstfile", "findnextfile",
    "regsetvalue", "regcreatekey", "regcreatekeyex", "regdeletevalue", "regdeletekey",
    "regqueryvalue", "regqueryvalueex", "regopenkeyex",
    "createservice", "startservice", "openscmanager", "outputdebugstring",
    "credenumerate", "getcomputername", "getusername", "lookupprivilegevalue",
    "cryptacquirecontext", "initiatesystemshutdown", "loadlibrary",
)

# Explicit spellings that are not simply base + "a"/"w". Each maps to an existing
# rule pattern, so no new taxonomy is introduced.
_EXPLICIT_ALIASES = {
    # RegSetValueExA/W were listed literally in the original rules.
    "regsetvalueexa": "regsetvalue",
    "regsetvalueexw": "regsetvalue",
    # Real export spellings of APIs whose bare name is a rule pattern.
    "dnsquery_a": "dnsquery",
    "dnsquery_w": "dnsquery",
    "dnsquery_utf8": "dnsquery",
    "getaddrinfow": "getaddrinfo",
    "process32firstw": "process32first",
    "process32nextw": "process32next",
    "module32firstw": "module32first",
    "module32nextw": "module32next",
}


def _build_import_index() -> dict:
    index: dict = {}

    def add(spelling, behaviours):
        bucket = index.setdefault(spelling, [])
        for b in behaviours:
            if b not in bucket:
                bucket.append(b)

    for pattern, behaviours in IMPORT_PATTERN_BEHAVIOURS.items():
        add(pattern, behaviours)

    for base in _ANSI_WIDE_BASES:
        if base not in IMPORT_PATTERN_BEHAVIOURS or base in EXACT_MATCH_ONLY:
            raise ValueError("_ANSI_WIDE_BASES entry is not a rule pattern: %s" % base)
        for suffix in ("a", "w"):
            add(base + suffix, IMPORT_PATTERN_BEHAVIOURS[base])

    for alias, pattern in _EXPLICIT_ALIASES.items():
        if pattern not in IMPORT_PATTERN_BEHAVIOURS:
            raise ValueError("_EXPLICIT_ALIASES target is not a rule pattern: %s" % pattern)
        add(alias, IMPORT_PATTERN_BEHAVIOURS[pattern])

    return {k: tuple(v) for k, v in index.items()}


# cleaned API spelling -> tuple of behaviours (authoritative lookup for the matcher)
IMPORT_API_INDEX = _build_import_index()

_R2_PREFIXES = ("sym.imp.", "sym.", "imp.", "reloc.", "ptr.")
_LIB_PREFIX_RE = re.compile(r"^[a-z0-9_\-]+\.dll[_!.]")


def _clean_api_name(raw) -> str:
    """Lower-case and strip radare2 symbol prefixes and '<lib>.dll_' prefixes."""
    name = str(raw).lower().strip()

    stripped = True
    while stripped:
        stripped = False
        for prefix in _R2_PREFIXES:
            if name.startswith(prefix):
                name = name[len(prefix):]
                stripped = True

    return _LIB_PREFIX_RE.sub("", name).strip()


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

        api_name = _clean_api_name(api_name)

        # EXPLICIT MATCHING: every behaviour assigned to this API spelling is kept
        for behaviour in IMPORT_API_INDEX.get(api_name, ()):

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
