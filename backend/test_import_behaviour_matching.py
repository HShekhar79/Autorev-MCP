"""Regression: deterministic, explicit import-behaviour matching.

Run from backend/:  python -m pytest -q test_import_behaviour_matching.py
Uses the real project modules (no stubs, mocks, or monkeypatching).

Import evidence means "the binary imports this API", not "the behaviour was
performed". Collision decisions are documented in import_behaviour_engine.py.
"""
from engines.behaviour_engine.import_behaviour_engine import (
    EXACT_MATCH_ONLY,
    IMPORT_API_INDEX,
    IMPORT_BEHAVIOUR_RULES,
    IMPORT_PATTERN_BEHAVIOURS,
    analyze_imports_for_behaviour,
)
from utils.normalization import CANONICAL_BEHAVIORS


def _names(*apis):
    return [b["name"] for b in analyze_imports_for_behaviour(list(apis))]


def _set(api):
    return set(_names(api))


# ---------------------------------------------------------------- short patterns
def test_exact_short_patterns_are_command_execution():
    for api in ["system", "System", "cmd", "CMD"]:
        assert "command_execution" in _set(api), api


def test_system_substrings_are_not_command_execution():
    for api in ["SystemTime", "GetSystemTime", "SystemFunction032", "ZwSystemDebugControl"]:
        assert "command_execution" not in _set(api), api


# ----------------------------------------------------------------------- process
def test_process_import_semantics_preserved():
    assert "process_injection" not in _set("OpenProcess")
    assert "process_injection" not in _set("VirtualAllocEx")
    assert "memory_allocation" in _set("VirtualAllocEx")
    assert "process_injection" in _set("WriteProcessMemory")
    assert "process_injection" in _set("NtWriteVirtualMemory")
    assert "process_injection" in _set("CreateRemoteThread")
    assert "process_injection" in _set("CreateRemoteThreadEx")
    assert "process_injection" in _set("NtCreateThreadEx")
    assert "process_injection" in _set("SetThreadContext")
    assert "process_termination" not in _set("ExitProcess")
    assert "process_termination" in _set("TerminateProcess")


def test_openprocesstoken_is_token_manipulation_only():
    assert _set("OpenProcessToken") == {"token_manipulation"}


# ------------------------------------------------------- collisions: kept as multi
def test_multi_behaviour_apis_keep_all_explicit_labels():
    expected = {
        "GetProcAddress": {"dynamic_loading", "dynamic_api_resolution"},
        "LoadLibrary": {"dynamic_loading", "dynamic_api_resolution"},
        "LdrLoadDll": {"dynamic_loading", "dynamic_api_resolution"},
        "CreateProcess": {"process_creation", "command_execution"},
        "WinExec": {"process_creation", "command_execution"},
        "ShellExecute": {"process_creation", "command_execution"},
        "GetSystemInfo": {"system_information_discovery", "system_discovery"},
        "GetComputerName": {"system_information_discovery", "system_discovery"},
        "GetUserName": {"system_information_discovery", "system_discovery"},
        "GetVersion": {"system_information_discovery", "system_discovery"},
        "RtlGetVersion": {"system_information_discovery", "system_discovery"},
        "InternetConnect": {"network_activity", "network_communication", "command_and_control"},
        "WinHttpSendRequest": {"network_activity", "network_communication", "command_and_control"},
        "HttpOpenRequest": {"network_communication", "command_and_control"},
        "InternetReadFile": {"network_activity", "payload_download"},
        "WinHttpReadData": {"network_activity", "payload_download"},
        "FtpPutFile": {"ftp_communication", "data_exfiltration"},
        "Socket": {"network_activity", "network_communication"},
        "Connect": {"network_activity", "network_communication"},
        "WSAConnect": {"network_activity", "network_communication"},
    }
    for api, want in expected.items():
        assert _set(api) == want, (api, _set(api))


# ----------------------------------------- collisions: trimmed (context required)
def test_trimmed_collision_labels_are_not_asserted_from_imports():
    assert _set("Send") == {"network_communication"}
    assert _set("Recv") == {"network_communication"}
    assert "data_exfiltration" not in _set("Send")
    assert "command_and_control" not in _set("Recv")
    assert _set("RegSetValue") == {"registry_modification"}
    assert _set("RegSetValueExA") == {"registry_modification"}
    assert _set("WriteFile") == {"file_modification"}
    assert _set("CopyFile") == {"file_copy"}
    assert _set("MoveFile") == {"file_move"}
    assert _set("VirtualAllocEx") == {"memory_allocation"}


def test_specific_apis_still_assert_their_own_labels():
    assert "registry_persistence" in _set("RegCreateKeyExA")
    assert "file_creation" in _set("CreateFileW")
    assert "data_exfiltration" in _set("WSASend")
    assert "anti_debugging" in _set("IsDebuggerPresent")
    assert "process_enumeration" in _set("CreateToolhelp32Snapshot")


# ------------------------------------------------------------ substring safety
def test_unrelated_names_do_not_match_by_substring():
    for api in [
        "ConnectionReset", "SocketTimeout", "ConnectNamedPipe",
        "SystemTime", "GetSystemTime", "SystemFunction032", "ZwSystemDebugControl",
        "CreateFileMappingA", "SendMessageW", "SendInput", "closesocket",
        "StartServiceCtrlDispatcherA",
    ]:
        assert _names(api) == [], (api, _names(api))


# ------------------------------------------------------- explicit API variants
# Review artifact: every spelling the index may contain beyond the literal rule
# patterns. If the production lists change, this list must be changed on purpose.
ACCEPTED_EXTRA_SPELLINGS = frozenset({
    "copyfilea", "copyfileexa", "copyfileexw", "copyfilew", "credenumeratea",
    "credenumeratew", "cryptacquirecontexta", "cryptacquirecontextw", "dnsquery_a",
    "dnsquery_utf8", "dnsquery_w", "findnextfilea", "findnextfilew", "ftpgetfilea",
    "ftpgetfilew", "ftpopenfilea", "ftpopenfilew", "ftpputfilea", "ftpputfilew",
    "getaddrinfow", "getcomputernamea", "getcomputernamew", "getusernamea",
    "getusernamew", "httpopenrequesta", "httpopenrequestw", "httpsendrequestexa",
    "httpsendrequestexw", "initiatesystemshutdowna", "initiatesystemshutdownw",
    "internetconnecta", "internetconnectw", "internetopena", "internetopenw",
    "lookupprivilegevaluea", "lookupprivilegevaluew", "module32firstw", "module32nextw",
    "movefilea", "movefileexa", "movefileexw", "movefilew", "openscmanagera",
    "openscmanagerw", "outputdebugstringa", "outputdebugstringw", "process32firstw",
    "process32nextw", "regcreatekeyexa", "regcreatekeyexw", "regcreatekeyw",
    "regdeletekeya", "regdeletekeyw", "regdeletevaluea", "regdeletevaluew",
    "regopenkeyexa", "regopenkeyexw", "regqueryvaluea", "regqueryvalueexa",
    "regqueryvalueexw", "regqueryvaluew", "regsetvaluea", "regsetvalueexa",
    "regsetvalueexw", "regsetvaluew", "setfileattributesa", "setfileattributesw",
    "shellexecutea", "shellexecuteexa", "shellexecuteexw", "shellexecutew",
    "startservicea", "startservicew", "urldownloadtocacheentrya",
    "urldownloadtocacheentryw", "urldownloadtofilea", "urldownloadtofilew",
})


def test_index_contains_only_rule_patterns_and_reviewed_extras():
    allowed = set(IMPORT_PATTERN_BEHAVIOURS) | ACCEPTED_EXTRA_SPELLINGS
    assert set(IMPORT_API_INDEX) == allowed
    assert not (set(IMPORT_API_INDEX) & {"connectex", "systema", "systemex", "senda"})


def test_explicit_ansi_wide_variants_resolve_to_base_behaviours():
    assert _set("CreateFileA") == _set("CreateFileW") == _set("CreateFile")
    assert _set("LoadLibraryA") == _set("LoadLibraryW") == _set("LoadLibrary")
    assert _set("RegSetValueExA") == _set("RegSetValueExW") == {"registry_modification"}
    assert _set("RegSetValueA") == _set("RegSetValueW") == {"registry_modification"}
    assert _set("ShellExecuteEx") == {"process_creation"}
    assert _set("ShellExecuteExA") == _set("ShellExecuteExW") == {"process_creation"}
    assert _set("ShellExecuteA") == _set("ShellExecuteW") == {"process_creation", "command_execution"}
    assert _set("CreateProcessA") == _set("CreateProcessW") == {"process_creation", "command_execution"}
    assert "command_and_control" in _set("InternetConnectA")
    assert "command_and_control" in _set("HttpSendRequestExA")
    assert "registry_query" in _set("RegQueryValueExA")
    assert "system_discovery" in _set("GetUserNameW")
    assert "process_enumeration" in _set("Process32FirstW")
    assert "dns_activity" in _set("GetAddrInfoW")
    assert "dns_activity" in _set("DnsQuery_A")


def test_invented_variants_are_not_generated():
    # The earlier global suffix logic accepted every one of these.
    for api in [
        "ConnectEx", "ConnectW", "SocketA", "SocketW", "SendA", "SendEx", "RecvA",
        "SystemEx", "SystemA", "SystemW", "CmdA", "CMDEx", "PowershellA",
        "GetVersionExA", "GetVersionExW", "LoadLibraryExW", "LoadLibraryExA",
        "GetComputerNameExA", "GetUserNameExA", "WriteFileEx", "CreateFileExA",
        "GetProcAddressA", "IsDebuggerPresentW", "TerminateProcessA",
        "VirtualAllocExA", "CreateRemoteThreadW", "WriteProcessMemoryA",
        "WSAConnectA", "WinExecA", "CreateToolhelp32SnapshotA",
    ]:
        assert _names(api) == [], (api, _names(api))


def test_related_but_unlisted_functions_are_not_matched():
    for api in [
        "CreateProcessAsUserW", "CreateProcessWithLogonW", "CreateProcessInternalW",
        "recvfrom", "sendto", "WSARecv", "MoveFileWithProgressW",
        "InternetReadFileExA", "WinHttpConnect", "FindFirstFileExW",
    ]:
        assert _names(api) == [], (api, _names(api))


def test_exact_only_patterns_have_no_variants():
    for pattern in EXACT_MATCH_ONLY:
        assert _names(pattern) == ["command_execution"]
        for suffix in ["a", "w", "ex", "exa", "exw"]:
            assert _names(pattern + suffix) == [], pattern + suffix


def test_symbol_prefixes_are_stripped():
    assert "process_creation" in _set("sym.imp.KERNEL32.dll_CreateProcessA")
    assert "file_creation" in _set("sym.imp.CreateFileW")
    assert "process_injection" in _set("imp.WriteProcessMemory")


# ------------------------------------------------------------- output contract
def test_output_schema_unchanged_and_deduplicated():
    result = analyze_imports_for_behaviour(["CreateProcessA", "CreateProcessW", "WinExec"])
    names = [b["name"] for b in result]
    assert len(names) == len(set(names))
    for b in result:
        assert set(b) == {"name", "source", "confidence"}
        assert b["source"] == "imports"
        assert b["confidence"] == 0.9


def test_dict_and_str_inputs_and_empty_inputs():
    assert analyze_imports_for_behaviour([]) == []
    assert analyze_imports_for_behaviour(None) == []
    assert _set("GetProcAddress") == {
        b["name"] for b in analyze_imports_for_behaviour([{"name": "GetProcAddress"}])
    }
    assert analyze_imports_for_behaviour([42, None]) == []


def test_output_is_deterministic():
    apis = ["Socket", "CreateProcessA", "RegSetValueExA", "GetProcAddress"]
    assert analyze_imports_for_behaviour(apis) == analyze_imports_for_behaviour(apis)


# -------------------------------------------------- no last-write-wins information loss
def test_every_rule_pattern_yields_all_of_its_behaviours():
    # A spelling may additionally pick up behaviours of its API family
    # (e.g. CreateProcessW also belongs to the CreateProcess family), so the
    # invariant is "never fewer", not "exactly".
    for pattern, behaviours in IMPORT_PATTERN_BEHAVIOURS.items():
        assert set(behaviours) <= set(_names(pattern)), pattern


def test_rule_keys_are_canonical_behaviours():
    for behaviour in IMPORT_BEHAVIOUR_RULES:
        assert behaviour in CANONICAL_BEHAVIORS, behaviour


def test_index_has_no_arbitrary_substring_entries():
    for spelling in IMPORT_API_INDEX:
        assert spelling not in {"systemtime", "connectionreset", "sockettimeout"}
