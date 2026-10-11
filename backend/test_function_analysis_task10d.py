"""
test_function_analysis_task10d.py

Task 10D focused regression tests: broad evidence collection, strict evidence
attribution for process_injection.

  VirtualAlloc / VirtualAllocEx / OpenProcess alone  -> NOT process_injection
  WriteProcessMemory / CreateRemoteThread(Ex)        -> process_injection evidence
  strong combinations (incl. variants)               -> process_injection
  strings / import names alone                       -> NOT process_injection

Pure-function tests plus analyze_functions() integration with a faked
extractor (no radare2 binary).  Task 10/10B/10C tests are untouched.
"""
from unittest.mock import MagicMock, patch

import pytest

from engines.function_analysis_engine import function_analysis_engine as fae
from engines.function_analysis_engine.function_analysis_engine import (
    analyze_functions,
    detect_behaviours,
    detect_capabilities,
    detect_hidden_api_behaviour,
)


# ---------------------------------------------------------------- behaviours
def test_A_virtualalloc_is_memory_allocation_not_injection():
    for name in ("VirtualAlloc", "VirtualAllocA", "VirtualAllocW", "sym.imp.VirtualAlloc"):
        b = detect_behaviours([name])
        assert "memory_allocation" in b, name
        assert "process_injection" not in b, name


def test_B_virtualallocex_alone_is_not_injection():
    for name in ("VirtualAllocEx", "VirtualAllocExA", "sym.imp.VirtualAllocEx"):
        b = detect_behaviours([name])
        assert "memory_allocation" in b, name
        assert "process_injection" not in b, name


def test_C_virtualprotect_maps_to_memory_protection_change():
    for name in ("VirtualProtect", "VirtualProtectEx"):
        b = detect_behaviours([name])
        assert "memory_protection_change" in b, name
        assert "process_injection" not in b, name


@pytest.mark.parametrize("api", ["WriteProcessMemory", "NtWriteVirtualMemory", "WriteVirtualMemory"])
def test_D_remote_write_is_injection_evidence(api):
    assert "process_injection" in detect_behaviours([api])


@pytest.mark.parametrize("api", ["CreateRemoteThread", "CreateRemoteThreadEx"])
def test_E_remote_thread_is_injection_evidence(api):
    assert "process_injection" in detect_behaviours([api])


def test_F_classic_combination_is_injection():
    calls = ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
    b = detect_behaviours(calls)
    assert "process_injection" in b and b["process_injection"] == "T1055"
    assert "process_injection" in detect_capabilities(calls)


def test_F2_variant_without_wpm_or_crt_is_still_detected():
    # VirtualAllocEx + NtCreateThreadEx / SetThreadContext / QueueUserAPC
    for exec_api in ("NtCreateThreadEx", "SetThreadContext", "QueueUserAPC", "RtlCreateUserThread"):
        calls = ["OpenProcess", "VirtualAllocEx", exec_api]
        assert "process_injection" in detect_behaviours(calls), exec_api
        assert "process_injection" in detect_capabilities(calls), exec_api


def test_openprocess_and_weak_pairs_are_not_injection():
    for calls in (
        ["OpenProcess"],
        ["OpenProcessToken"],                       # used to substring-match "openprocess"
        ["OpenProcess", "VirtualAllocEx"],          # no write/thread/exec transfer
        ["VirtualAlloc", "CreateThreadEx"],         # local alloc + thread is not injection
        ["VirtualAllocEx", "CreateThread"],
        ["NtCreateThreadEx"],
        ["SetThreadContext"],
    ):
        assert "process_injection" not in detect_behaviours(calls), calls
        assert "process_injection" not in detect_capabilities(calls), calls


def test_openprocesstoken_still_token_manipulation():
    assert "token_manipulation" in detect_behaviours(["OpenProcessToken"])


# -------------------------------------------------------------- capabilities
def test_capability_virtualalloc_is_not_process_injection():
    caps = detect_capabilities(["VirtualAlloc"])
    assert "process_injection" not in caps
    assert "memory_manipulation" in caps          # existing capability retained


def test_capability_virtualallocex_alone_is_not_process_injection():
    assert "process_injection" not in detect_capabilities(["VirtualAllocEx"])


def test_capability_single_primitives_are_process_injection():
    assert "process_injection" in detect_capabilities(["WriteProcessMemory"])
    assert "process_injection" in detect_capabilities(["CreateRemoteThread"])


def test_other_capabilities_unchanged():
    caps = detect_capabilities(["CreateFileW", "LoadLibraryA", "system", "RegSetValue"])
    assert {"file_write", "dynamic_api_resolution", "command_execution", "registry_write"} <= set(caps)


# ------------------------------------------------------- strings / imports
def test_G_string_only_virtualalloc_is_not_injection():
    assert "process_injection" not in detect_hidden_api_behaviour(["VirtualAlloc"], [])
    assert "process_injection" not in detect_hidden_api_behaviour(["call VirtualAllocEx here"], None)


def test_H_string_only_injection_apis_do_not_create_injection():
    strings = ["WriteProcessMemory", "CreateRemoteThread", "VirtualAlloc", "VirtualAllocEx"]
    assert "process_injection" not in detect_hidden_api_behaviour(strings, [])
    imports = [{"name": "WriteProcessMemory"}, {"name": "CreateRemoteThread"},
               {"name": "VirtualAllocEx"}, {"name": "OpenProcess"}]
    assert "process_injection" not in detect_hidden_api_behaviour(strings, imports)
    assert "process_injection" not in detect_hidden_api_behaviour([], imports)


def test_hidden_api_command_execution_and_dynamic_resolution_preserved():
    found = detect_hidden_api_behaviour(["cmd.exe /c dir", "LoadLibraryA"], [])
    assert "command_execution" in found and "dynamic_api_resolution" in found
    # imports of LoadLibrary/GetProcAddress + API-name strings -> dynamic resolution
    found = detect_hidden_api_behaviour(["WriteProcessMemory"], [{"name": "GetProcAddress"}])
    assert "dynamic_api_resolution" in found and "process_injection" not in found


# ----------------------------------- analyze_functions (faked extractor)
def _run(functions, calls_by_offset, strings=None, imports=None):
    fake = MagicMock()
    fake.r2 = MagicMock()
    fake.get_functions.return_value = functions
    fake.get_calls_for_address.side_effect = lambda off: calls_by_offset.get(off, [])
    with patch.object(fae, "RadareExtractor", return_value=fake):
        return analyze_functions("fake.bin", strings=strings if strings is not None else [],
                                 imports=imports)


def _names(fn_result):
    return {b["name"] for b in fn_result["behaviours"]}


def test_pipeline_per_function_attribution_of_injection():
    functions = [
        {"name": "sym.alloc_only", "addr": 0x1000, "size": 32},
        {"name": "sym.inject", "addr": 0x2000, "size": 32},
    ]
    res = _run(functions, {
        0x1000: ["sym.imp.VirtualAlloc"],
        0x2000: ["sym.imp.OpenProcess", "sym.imp.VirtualAllocEx",
                 "sym.imp.WriteProcessMemory", "sym.imp.CreateRemoteThread"],
    })
    by = {r["function_name"]: r for r in res["results"]}
    assert "process_injection" not in _names(by["sym.alloc_only"])
    assert "memory_allocation" in _names(by["sym.alloc_only"])
    assert "process_injection" not in {c["name"] for c in by["sym.alloc_only"]["capabilities"]}
    assert "process_injection" in _names(by["sym.inject"])
    assert res["global_behaviours"] == []


def test_pipeline_string_only_injection_not_global_behaviour():
    res = _run([], {}, strings=["WriteProcessMemory", "CreateRemoteThread", "VirtualAlloc"])
    assert all(g["name"] != "process_injection" for g in res["global_behaviours"])
