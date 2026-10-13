"""
utils/normalization.py

Centralized behavior name normalization for the malware analysis pipeline.

Normalization pipeline (applied in order):
    1. Lowercase + strip whitespace
    2. Replace hyphens and spaces → underscores
    3. Apply explicit NORMALIZATION_MAP (aliases, raw API tokens, British spelling)
    4. Apply fuzzy matching via difflib (cutoff=0.80) — typo correction only
    5. Fallback to cleaned input if nothing matches

Convention: all canonical names are snake_case American English.
            "behavior" not "behaviour", "file_creation" not "filecreation".

Usage:
    from utils.normalization import normalize_behavior, CANONICAL_BEHAVIORS

    name = normalize_behavior("registry_persistance")   # → "registry_persistence"
    name = normalize_behavior("cmd_exec")               # → "command_execution"
    name = normalize_behavior("anti_debug")             # → "anti_debugging"
"""

import copy
import difflib
import hashlib
import logging
import math
import os
from typing import Any, Optional
from utils.debug import debug_log

log = logging.getLogger("arise.normalization")


# =============================================================================
# CANONICAL BEHAVIOR NAMES
# Single source of truth. Every engine validates against this list.
# =============================================================================

CANONICAL_BEHAVIORS: list[str] = [
    # Network
    "network_activity",
    "payload_download",
    "command_and_control",
    "http_communication",
    "ftp_communication",
    "dns_activity",
    "data_exfiltration",
    "network_communication",

    # Process
    "process_creation",
    "process_termination",
    "process_injection",
    "process_hollowing",

    # Filesystem
    "file_creation",
    "file_modification",
    "file_deletion",
    "file_copy",
    "file_move",
    "directory_enumeration",

    # Registry
    "registry_persistence",
    "registry_modification",
    "registry_query",

    # Persistence
    "startup_persistence",
    "service_creation",
    "scheduled_task_creation",

    # Anti-Analysis
    "anti_debugging",
    "anti_vm",
    "anti_sandbox",

    # Credentials
    "credential_dumping",
    "keylogging",

    # Discovery
    "system_information_discovery",
    "system_discovery",
    "user_enumeration",
    "process_enumeration",
    "module_enumeration",

    # Memory
    "memory_allocation",
    "memory_protection_change",

    # Crypto
    "cryptographic_activity",
    "random_generation",

    # Privileges
    "privilege_escalation",
    "token_manipulation",

    # System Control
    "shutdown_system",
    "reboot_system",

    # Obfuscation / Loading
    "packing_detection",
    "dynamic_loading",
    "dynamic_api_resolution",

    # Execution
    "command_execution",

    # Informational (no capability mapping, but valid pipeline names)
    "indirect_call_execution",
    "unknown_external_activity",
    "internal_function_calls",
    "no_external_activity",
]

# Fast lookup set for O(1) membership tests
_CANONICAL_SET: set[str] = set(CANONICAL_BEHAVIORS)


# =============================================================================
# NORMALIZATION MAP
# Explicit alias → canonical name mappings.
# Applied BEFORE fuzzy matching so short/ambiguous aliases are handled precisely.
#
# Covers:
#   - British spellings        (behaviour → behavior*)
#   - Raw Windows API tokens   (CreateFile → file_creation)
#   - Short aliases            (cmd_exec → command_execution)
#   - feature_engine orphans   (file_encryption → cryptographic_activity)
#   - Informational names      (internal_function_calls → internal_function_calls)
#
# * The pipeline key is "name", not "behavior" — this map normalizes the VALUE,
#   not the dict key. The dict key inconsistency is fixed in each engine directly.
# =============================================================================

NORMALIZATION_MAP: dict[str, str] = {
    # ── British → American spelling ─────────────────────────────────────────
    "anti_behaviour":               "anti_debugging",

    # ── Short aliases / legacy names ────────────────────────────────────────
    "cmd_exec":                     "command_execution",
    "exec":                         "command_execution",
    "shell":                        "command_execution",
    "indirect_call":                "indirect_call_execution",
    "indirect_calls":               "indirect_call_execution",
    "file_encrypt":                 "cryptographic_activity",
    "file_encryption":              "cryptographic_activity",  # feature_engine orphan
    "data_encryption":              "cryptographic_activity",
    "startup_execution":            "startup_persistence",
    "data_collection":              "file_creation",           # collection category alias
    "obfuscation":                  "dynamic_api_resolution",

    # ── Raw Windows API token → canonical behaviour ──────────────────────────
    # These appear when raw import names leak into the behaviour name field.
    # The NORMALIZATION_MAP in mitre_engine previously handled a subset of these;
    # they are now unified here so all engines benefit.
    "socket":                       "network_communication",
    "connect":                      "network_communication",
    "recv":                         "network_communication",
    "send":                         "data_exfiltration",
    "wsastartup":                   "network_activity",
    "wsaconnect":                   "network_communication",
    "internetopen":                 "network_activity",
    "internetconnect":              "network_activity",
    "internetreadfile":             "payload_download",
    "urldownloadtofile":            "payload_download",
    "httpopenrequest":              "http_communication",
    "httpsendrequestex":            "http_communication",
    "winhttpopenrequest":           "http_communication",
    "winhttpsendrequest":           "command_and_control",
    "dnsquery":                     "dns_activity",
    "dnsquerya":                    "dns_activity",
    "gethostbyname":                "dns_activity",
    "getaddrinfo":                  "dns_activity",
    "ftpputfile":                   "ftp_communication",
    "ftpgetfile":                   "ftp_communication",
    "ftpopenfile":                  "ftp_communication",
    "createprocess":                "process_creation",
    "createprocessa":               "process_creation",
    "createprocessw":               "process_creation",
    "winexec":                      "process_creation",
    "shellexecute":                 "process_creation",
    "shellexecuteex":               "process_creation",
    "terminateprocess":             "process_termination",
    "exitprocess":                  "process_termination",
    "createremotethread":           "process_injection",
    "writeprocessmemory":           "process_injection",
    "openprocess":                  "process_injection",
    "virtualallocex":               "process_injection",
    "zwunmapviewofsection":         "process_hollowing",
    "ntunmapviewofsection":         "process_hollowing",
    "createfile":                   "file_creation",
    "createfilea":                  "file_creation",
    "createfilew":                  "file_creation",
    "writefile":                    "file_modification",
    "setfileattributes":            "file_modification",
    "deletefile":                   "file_deletion",
    "deletefilea":                  "file_deletion",
    "deletefilew":                  "file_deletion",
    "copyfile":                     "file_copy",
    "copyfileex":                   "file_copy",
    "movefile":                     "file_move",
    "movefileex":                   "file_move",
    "findfirstfile":                "directory_enumeration",
    "findnextfile":                 "directory_enumeration",
    "regsetvalue":                  "registry_persistence",
    "regsetvalueexa":               "registry_persistence",
    "regsetvalueexw":               "registry_persistence",
    "regcreatekey":                 "registry_persistence",
    "regcreatekeya":                "registry_persistence",
    "regcreatekeyex":               "registry_persistence",
    "regdeletevalue":               "registry_modification",
    "regdeletekey":                 "registry_modification",
    "regqueryvalue":                "registry_query",
    "regqueryvalueex":              "registry_query",
    "regopenkeyex":                 "registry_query",
    "createservice":                "service_creation",
    "createservicea":               "service_creation",
    "createservicew":               "service_creation",
    "startservice":                 "service_creation",
    "openscmanager":                "service_creation",
    "isdebuggerpresent":            "anti_debugging",
    "checkremotedebuggerpresent":   "anti_debugging",
    "ntqueryinformationprocess":    "anti_debugging",
    "outputdebugstring":            "anti_debugging",
    "debugbreak":                   "anti_debugging",
    "minidumpwritedump":            "credential_dumping",
    "lsaopenpolicy":                "credential_dumping",
    "lsaretrieveprivatedata":       "credential_dumping",
    "credenumerate":                "credential_dumping",
    "setwindowshook":               "keylogging",
    "setwindowshookexa":            "keylogging",
    "setwindowshookexw":            "keylogging",
    "getasynckeystate":             "keylogging",
    "getkeystate":                  "keylogging",
    "getsysteminfo":                "system_discovery",
    "getnativesysteminfo":          "system_information_discovery",
    "getversion":                   "system_information_discovery",
    "rtlgetversion":                "system_discovery",
    "getcomputername":              "system_discovery",
    "getusername":                  "system_discovery",
    "netuserenum":                  "user_enumeration",
    "netusergetinfo":               "user_enumeration",
    "createtoolhelp32snapshot":     "process_enumeration",
    "process32first":               "process_enumeration",
    "process32next":                "process_enumeration",
    "enumprocesses":                "process_enumeration",
    "module32first":                "module_enumeration",
    "module32next":                 "module_enumeration",
    "enumprocessmodules":           "module_enumeration",
    "virtualalloc":                 "memory_allocation",
    "heapalloc":                    "memory_allocation",
    "rtlallocateheap":              "memory_allocation",
    "virtualprotect":               "memory_protection_change",
    "virtualprotectex":             "memory_protection_change",
    "cryptencrypt":                 "cryptographic_activity",
    "cryptdecrypt":                 "cryptographic_activity",
    "cryptacquirecontext":          "cryptographic_activity",
    "bcryptencrypt":                "cryptographic_activity",
    "bcryptdecrypt":                "cryptographic_activity",
    "bcryptopenalgorithmprovider":  "cryptographic_activity",
    "cryptgenrandom":               "random_generation",
    "rtlgenrandom":                 "random_generation",
    "bcryptgenrandom":              "random_generation",
    "adjusttokenprivileges":        "privilege_escalation",
    "lookupprivilegevalue":         "privilege_escalation",
    "openprocesstoken":             "token_manipulation",
    "duplicatetoken":               "token_manipulation",
    "impersonateloggedonuser":      "token_manipulation",
    "createprocesswithtokenw":      "token_manipulation",
    "exitwindowsex":                "shutdown_system",
    "initiatesystemshutdown":       "reboot_system",
    "loadlibrary":                  "dynamic_loading",
    "loadlibrarya":                 "dynamic_loading",
    "loadlibraryw":                 "dynamic_loading",
    "ldrloaddll":                   "dynamic_loading",
    "getprocaddress":               "dynamic_api_resolution",
    "system":                       "command_execution",
    "cmd":                          "command_execution",
    "powershell":                   "command_execution",
}


# =============================================================================
# CORE NORMALIZATION FUNCTION
# =============================================================================

def normalize_behavior(name: str) -> str | None:

    if not name or not isinstance(name, str):
        return None

    original = name
    cleaned = name.lower().strip()
    cleaned = cleaned.replace("-", "_").replace(" ", "_")

    if cleaned in _CANONICAL_SET:
        return cleaned

    if cleaned in NORMALIZATION_MAP:
        result = NORMALIZATION_MAP[cleaned]
        debug_log("[NORMALIZED] explicit map", "%r → %r" % (original, result))
        return result

    # 🔥 FIX: avoid fuzzy on short strings
    if len(cleaned) > 5:
        matches = difflib.get_close_matches(cleaned, CANONICAL_BEHAVIORS, n=1, cutoff=0.80)
        if matches:
            result = matches[0]
            debug_log("[NORMALIZED] fuzzy match", "%r → %r" % (original, result))
            return result

    debug_log("[NORMALIZED] fallback", "%r → %r" % (original, cleaned))
    return cleaned


def normalize_behavior_list(names: list[str], source: str = "unknown") -> list[dict]:
    """
    Normalize a list of raw behavior name strings into standardized dicts.

    Returns:
        list of {"name": str, "source": str, "confidence": float}
        Duplicates (post-normalization) are deduplicated, keeping first occurrence.
    """
    seen: set[str] = set()
    result: list[dict] = []

    for raw in names:
        canonical = normalize_behavior(raw)
        if not canonical or canonical in seen:
            continue
        seen.add(canonical)
        result.append({
            "name": canonical,
            "source": source,
            "confidence": 0.8,
        })

    return result


def extract_behavior_name(b) -> str | None:
    """
    Safely extract the behavior name from any of the supported input shapes:
        - str                      → used directly
        - dict with "name" key     → preferred
        - dict with "behavior" key → legacy American spelling
        - dict with "behaviour" key→ legacy British spelling

    Returns the normalized canonical name, or None if extraction fails.
    """
    if isinstance(b, str):
        raw = b
    elif isinstance(b, dict):
        raw = (
            b.get("name")
            or b.get("behavior")
            or b.get("behaviour")
            or ""
        )
    else:
        return None

    return normalize_behavior(raw) if raw else None


# =============================================================================
# RESULT NORMALIZATION
# Canonical schema normalization for analysis results across Celery and API routes.
# =============================================================================

def compute_hashes(file_path: str) -> dict:
    hashes = {"md5": "N/A", "sha1": "N/A", "sha256": "N/A"}
    try:
        md5    = hashlib.md5()
        sha1   = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        hashes = {
            "md5":    md5.hexdigest(),
            "sha1":   sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
    except Exception as e:
        log.warning(f"Hash computation failed: {e}")
    return hashes


def detect_file_type(file_path: str) -> str:
    MAGIC = [
        (b"MZ",                "PE Executable (EXE/DLL)"),
        (b"\x7fELF",           "ELF Binary"),
        (b"\xca\xfe\xba\xbe",  "Mach-O Fat Binary"),
        (b"\xcf\xfa\xed\xfe",  "Mach-O 64-bit"),
        (b"\xce\xfa\xed\xfe",  "Mach-O 32-bit"),
        (b"PK\x03\x04",        "ZIP/APK/DOCX/XLSX Archive"),
        (b"Rar!\x1a\x07",      "RAR Archive"),
        (b"7z\xbc\xaf\x27\x1c","7-Zip Archive"),
        (b"%PDF",               "PDF Document"),
        (b"\xd0\xcf\x11\xe0",  "OLE2 (DOC/XLS/PPT/MSI)"),
    ]
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
        for magic, label in MAGIC:
            if header[:len(magic)] == magic:
                return label
        ext = os.path.splitext(file_path)[1].lower()
        ext_map = {
            ".py": "Python Script",  ".js": "JavaScript",
            ".ps1": "PowerShell Script", ".bat": "Batch Script",
            ".sh": "Shell Script",   ".vbs": "VBScript",
            ".txt": "Text File",     ".csv": "CSV File",
            ".json": "JSON File",    ".xml": "XML File",
        }
        return ext_map.get(ext, "Unknown")
    except Exception:
        return "Unknown"


def _resolve_mitre(raw: dict) -> list:
    mitre = raw.get("mitre")
    if isinstance(mitre, list) and mitre:
        return _dedup(mitre)
    fm = raw.get("final_mitre")
    if isinstance(fm, dict):
        candidates = fm.get("mitre_techniques") or fm.get("final_mitre") or []
        if candidates:
            return _dedup(candidates)
    elif isinstance(fm, list) and fm:
        return _dedup(fm)
    mr = raw.get("mitre_results") or raw.get("mitre_result", {})
    if isinstance(mr, dict):
        candidates = mr.get("techniques") or mr.get("mitre") or mr.get("mitre_techniques") or []
        if candidates:
            return _dedup(candidates)
    return []


def _resolve_verdict(raw: dict) -> dict:
    verdict_raw = raw.get("verdict")
    if verdict_raw is None:
        verdict_raw = raw.get("arise_verdict", {})

    if isinstance(verdict_raw, dict) and "verdict" in verdict_raw \
            and isinstance(verdict_raw["verdict"], dict):
        inner = dict(verdict_raw["verdict"])
        for k, v in verdict_raw.items():
            if k != "verdict" and k not in inner:
                inner[k] = v
        verdict = inner
    elif isinstance(verdict_raw, dict):
        verdict = dict(verdict_raw)
    else:
        verdict = {}

    verdict.setdefault("verdict",            "UNKNOWN")
    verdict.setdefault("label",              verdict.get("verdict", "UNKNOWN"))
    verdict.setdefault("confidence",         0)
    verdict.setdefault("confidence_pct",     verdict.get("confidence", 0))
    verdict.setdefault("confidence_label",   "Low")
    verdict.setdefault("category",           "")
    verdict.setdefault("summary",            raw.get("summary", ""))
    verdict.setdefault("reasoning",          verdict.get("summary", ""))
    verdict.setdefault("recommended_actions",[])
    return verdict


def _resolve_behaviours(raw: dict) -> list:
    b = raw.get("behaviours")
    if isinstance(b, list):
        return b
    if isinstance(b, dict):
        return b.get("behaviors") or b.get("behaviours") or []
    b_alt = raw.get("behaviors")
    if isinstance(b_alt, list):
        return b_alt
    if isinstance(b_alt, dict):
        return b_alt.get("behaviors") or b_alt.get("behaviours") or []
    return []


def _dedup(lst: list) -> list:
    seen: set = set()
    out = []
    for item in lst:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _coerce_list(val) -> list:
    if isinstance(val, list): return val
    if val is None:           return []
    return [val]


def _coerce_cvss_score(value: Any) -> Optional[float]:
    """
    Safely parse and validate a CVSS score as a finite float in [0.0, 10.0].

    Returns:
        float score in [0.0, 10.0] if valid, or None if malformed/untrustworthy:
        - Booleans (True/False) -> None (rejected; not treated as 1.0/0.0)
        - Non-finite (NaN, +Inf, -Inf) -> None (rejected)
        - Numeric strings (e.g. "7.5", "  8.2 ") -> parsed float
        - Non-numeric strings or unparseable types -> None (rejected)
        - Out-of-range (< 0.0 or > 10.0) -> None (rejected; not trustworthy)
        - Large integer overflow (e.g. 10**400) -> None (rejected)
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        val = float(value)
    except (ValueError, TypeError, OverflowError):
        return None

    if not math.isfinite(val):
        return None

    if val < 0.0 or val > 10.0:
        return None

    return val


def normalise_result(
    raw: dict,
    elapsed: float = 0.0,
    original_name: str = "",
    hashes: dict = None,
    file_type: str = "Unknown",
) -> dict:
    """Canonical result schema normalizer for analysis results."""
    if not isinstance(raw, dict):
        raw = {}
    meta = raw.get("analysis_meta", {}) if isinstance(raw.get("analysis_meta"), dict) else {}

    existing_detail = raw.get("cvss_detail")
    cvss_raw = raw.get("cvss")
    cvss_score_raw = raw.get("cvss_score")
    cvss_results_raw = raw.get("cvss_results")

    if isinstance(existing_detail, dict):
        candidate_dict = existing_detail
    elif isinstance(cvss_raw, dict):
        candidate_dict = cvss_raw
    elif isinstance(cvss_results_raw, dict):
        candidate_dict = cvss_results_raw
    else:
        candidate_dict = None

    if candidate_dict is not None:
        cvss_detail = copy.deepcopy(candidate_dict)
        raw_val = cvss_detail.get("cvss_score")
        if raw_val is None or isinstance(raw_val, bool):
            candidate_fallback = cvss_score_raw if (cvss_score_raw is not None and not isinstance(cvss_score_raw, bool)) else cvss_raw
            if candidate_fallback is not None and not isinstance(candidate_fallback, bool):
                raw_val = candidate_fallback

        parsed_val = _coerce_cvss_score(raw_val)
        if parsed_val is not None:
            cvss_val = parsed_val
            cvss_detail["cvss_score"] = cvss_val

            expected_risk = (
                "CRITICAL" if cvss_val >= 9.0 else
                "HIGH" if cvss_val >= 7.0 else
                "MEDIUM" if cvss_val >= 4.0 else
                "LOW" if cvss_val > 0.0 else
                "NONE"
            )
            if "risk_level" not in cvss_detail or not cvss_detail["risk_level"]:
                cvss_detail["risk_level"] = expected_risk
            elif str(cvss_detail["risk_level"]).upper() != expected_risk:
                log.warning(
                    f"normalise_result: preserved cvss risk_level '{cvss_detail['risk_level']}' "
                    f"which differs from standard '{expected_risk}' for score {cvss_val}"
                )
        else:
            log.warning(
                f"normalise_result: invalid or out-of-range cvss score {raw_val!r}; falling back to 0.0 NONE"
            )
            cvss_val = 0.0
            cvss_detail["cvss_score"] = 0.0
            cvss_detail["risk_level"] = "NONE"
            if "cvss_risk_level" in cvss_detail:
                cvss_detail["cvss_risk_level"] = "NONE"
    else:
        raw_scalar = cvss_raw if cvss_raw is not None else cvss_score_raw
        if isinstance(raw_scalar, bool) and cvss_score_raw is not None and not isinstance(cvss_score_raw, bool):
            raw_scalar = cvss_score_raw

        parsed_val = _coerce_cvss_score(raw_scalar)
        if parsed_val is not None:
            cvss_val = parsed_val
            cvss_detail = {
                "cvss_score": cvss_val,
                "risk_level": (
                    "CRITICAL" if cvss_val >= 9.0 else
                    "HIGH" if cvss_val >= 7.0 else
                    "MEDIUM" if cvss_val >= 4.0 else
                    "LOW" if cvss_val > 0.0 else
                    "NONE"
                ),
            }
        else:
            if raw_scalar is not None:
                log.warning(
                    f"normalise_result: invalid or out-of-range cvss score {raw_scalar!r}; falling back to 0.0 NONE"
                )
            cvss_val = 0.0
            cvss_detail = {"cvss_score": 0.0, "risk_level": "NONE"}

    mitre        = _resolve_mitre(raw)
    verdict      = _resolve_verdict(raw)
    behaviours   = _resolve_behaviours(raw)
    capabilities = _coerce_list(raw.get("capabilities", []))

    for field, val in [("capabilities", capabilities), ("mitre", mitre), ("behaviours", behaviours)]:
        if not val:
            log.warning(f"normalise_result: EMPTY field '{field}'")

    risk_score_raw = raw.get("risk_score")
    if risk_score_raw is None:
        risk_obj = raw.get("risk")
        if isinstance(risk_obj, dict):
            risk_score_raw = risk_obj.get("combined_score", 0)
        else:
            risk_score_raw = 0
    try:
        risk_score = float(risk_score_raw or 0)
    except (ValueError, TypeError):
        risk_score = 0.0

    existing_hashes = raw.get("hashes")
    effective_hashes = hashes or existing_hashes or {"md5": "N/A", "sha1": "N/A", "sha256": "N/A"}
    effective_file_type = file_type if file_type != "Unknown" else raw.get("file_type", "Unknown")
    resolved_filename = original_name or meta.get("filename") or "analysis"

    analysis_meta = {
        "ghidra_available":   meta.get("ghidra_available", False),
        "radare2_available":  meta.get("radare2_available", False),
        "extraction_engine":  meta.get("extraction_engine", "radare2"),
        "capa_enabled":       meta.get("capa_enabled", False),
        "capa_mitre_count":   meta.get("capa_mitre_count", 0),
        "extraction_elapsed": meta.get("extraction_elapsed"),
        "total_elapsed":      elapsed or meta.get("total_elapsed", 0.0),
        "filename":           resolved_filename,
    }
    for k, v in meta.items():
        if k not in analysis_meta:
            analysis_meta[k] = v

    return {
        "functions":     _coerce_list(raw.get("functions", [])),
        "imports":       _coerce_list(raw.get("imports", [])),
        "strings":       _coerce_list(raw.get("strings", [])),
        "calls":         _coerce_list(raw.get("calls", [])),
        "behaviours":    behaviours,
        "capabilities":  capabilities,
        "mitre":         mitre,
        "risk_score":    risk_score,
        "cvss":          cvss_val,
        "cvss_detail":   cvss_detail,
        "verdict":       verdict,
        "summary":       raw.get("summary", verdict.get("summary", "")),
        "hashes":        effective_hashes,
        "file_type":     effective_file_type,
        "analysis_meta": analysis_meta,
    }
