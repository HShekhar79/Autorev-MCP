"""
backend/engines/file_type_router/file_type_router.py

Static analysis router. Detects file type from magic bytes + extension,
dispatches to the correct analysis engine, returns a normalised dict
compatible with the unified_extractor output schema.

SUPPORTED WITH FULL STATIC ANALYSIS:
  PE / DLL / SYS / EXE  -> Radare2 + CAPA (via unified_extractor)
  ELF / .so             -> Radare2 (via unified_extractor)
  APK                   -> ZIP unpack + manifest + DEX string extraction
  MSI                   -> OLE2 stream enumeration + string extraction
  PDF                   -> pdfplumber text + raw JS/action indicator scan
  DOCX/XLSX/PPTX        -> oletools VBA macro + XML content extraction
  DOC/XLS/PPT           -> oletools VBA macro (OLE2 binary format)
  RTF                   -> oletools RTF object extraction
  PS1/BAT/VBS           -> pattern-based behaviour analysis
  PY/SH/JS/PHP          -> pattern + string analysis
  ZIP/RAR/7Z            -> safe recursive listing + entry scanning
  PNG/JPG/GIF           -> metadata + embedded payload detection
  TXT/CSV/JSON/XML      -> IOC + string + credential pattern extraction

Install: pip install oletools pdfplumber python-magic
"""

import os, re, struct, hashlib, zipfile, gzip, json, math, string, logging
from pathlib import Path

log = logging.getLogger("arise.file_type_router")

# ---------------------------------------------------------------------------
# MAGIC BYTES
# ---------------------------------------------------------------------------

MAGIC_MAP = [
    (b"MZ",               "pe"),
    (b"\x7fELF",          "elf"),
    (b"\xca\xfe\xba\xbe", "macho"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"PK\x03\x04",       "zip_based"),
    (b"PK\x05\x06",       "zip_based"),
    (b"Rar!\x1a\x07",     "rar"),
    (b"7z\xbc\xaf\x27\x1c","sevenzip"),
    (b"\x1f\x8b",         "gzip"),
    (b"BZh",              "bzip2"),
    (b"%PDF",             "pdf"),
    (b"\xd0\xcf\x11\xe0", "ole2"),
    (b"{\\rtf",           "rtf"),
    (b"\x89PNG\r\n\x1a\n","png"),
    (b"\xff\xd8\xff",     "jpg"),
    (b"GIF8",             "gif"),
]

ZIP_SUBTYPES = {
    ".apk":"apk", ".aar":"apk", ".jar":"jar",
    ".docx":"docx", ".docm":"docx",
    ".xlsx":"xlsx", ".xlsm":"xlsx",
    ".pptx":"pptx", ".pptm":"pptx",
    ".odt":"opendoc", ".ods":"opendoc",
}

OLE2_SUBTYPES = {
    ".doc":"doc", ".dot":"doc",
    ".xls":"xls", ".xlt":"xls",
    ".ppt":"ppt", ".pot":"ppt",
    ".msi":"msi", ".msp":"msi",
    ".msg":"msg",
}

SCRIPT_EXTENSIONS = {
    ".ps1":"powershell", ".bat":"batch", ".cmd":"batch",
    ".vbs":"vbscript",   ".vbe":"vbscript",
    ".js":"javascript",  ".jse":"javascript",
    ".py":"python",      ".rb":"ruby",
    ".sh":"shell",       ".bash":"shell", ".zsh":"shell",
    ".php":"php",        ".pl":"perl",
}

TEXT_EXTENSIONS = {
    ".txt",".csv",".log",".json",".xml",
    ".yaml",".yml",".ini",".cfg",".conf",
    ".html",".htm",".md",".rst",".toml",
}

_PRINTABLE = set(string.printable)

_HIGH_SIGNAL = [
    re.compile(r"https?://\S{6,}", re.I),
    re.compile(r"HKEY_\w+", re.I),
    re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
    re.compile(r"%[A-Z]{3,}%"),
    re.compile(r"cmd\.exe|powershell|wscript|cscript|mshta", re.I),
    re.compile(r"[A-Za-z0-9+/]{30,}={0,2}$"),
    re.compile(r"\\\\[A-Za-z0-9_\-]{2,}\\"),
    re.compile(r"\b(?:eval|exec|system|shell_exec|popen)\b", re.I),
]

DANGEROUS_EXTENSIONS = {
    ".exe",".dll",".scr",".bat",".cmd",".vbs",".vbe",
    ".js",".jse",".ps1",".psm1",".hta",".msi",
    ".lnk",".jar",".apk",".elf",".sh",
}


# ---------------------------------------------------------------------------
# SHARED HELPERS
# ---------------------------------------------------------------------------

def _entropy(data: bytes) -> float:
    if not data: return 0.0
    freq: dict = {}
    for b in data: freq[b] = freq.get(b, 0) + 1
    l = len(data)
    return -sum((v/l)*math.log2(v/l) for v in freq.values())


def _strings_from_bytes(data: bytes, min_len=6, max_count=1000) -> list:
    results, cur = [], []
    for b in data:
        c = chr(b)
        if c in _PRINTABLE and c not in "\r\n\t":
            cur.append(c)
        else:
            if len(cur) >= min_len:
                results.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        results.append("".join(cur))

    def score(s):
        return sum(10 for p in _HIGH_SIGNAL if p.search(s)) + min(len(s)//10, 5)

    results = list(dict.fromkeys(results))
    results.sort(key=score, reverse=True)
    return results[:max_count]


def _iocs(strings: list) -> list:
    seen, out = set(), []
    for s in strings:
        if s not in seen and any(p.search(s) for p in _HIGH_SIGNAL):
            seen.add(s); out.append(s)
    return out


def _hashes(file_path: str) -> dict:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
    except Exception:
        pass
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def _empty(file_path: str, reason: str) -> dict:
    return {
        "functions":[], "imports":[], "strings":[], "calls":[],
        "behaviours":[], "capabilities":[], "mitre":[],
        "_meta":{"file_type":"unknown","subtype":"unknown","reason":reason,
                 "extraction_engine":"none","radare2_available":False,"ghidra_available":False,
                 "filename":os.path.basename(file_path)},
        "hashes": _hashes(file_path),
    }


def _dedup(lst: list) -> list:
    return list(dict.fromkeys(x for x in lst if x))


# ---------------------------------------------------------------------------
# TYPE DETECTION
# ---------------------------------------------------------------------------

def detect_file_type(file_path: str) -> tuple:
    ext = Path(file_path).suffix.lower()
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
    except Exception:
        return "unknown", "unreadable"

    for magic, group in MAGIC_MAP:
        if header[:len(magic)] == magic:
            if group == "zip_based":
                return "zip_based", ZIP_SUBTYPES.get(ext, "zip")
            if group == "ole2":
                return "ole2", OLE2_SUBTYPES.get(ext, "ole2_generic")
            return group, group

    if ext in SCRIPT_EXTENSIONS:
        return "script", SCRIPT_EXTENSIONS[ext]
    if ext in TEXT_EXTENSIONS:
        return "text", ext.lstrip(".")
    if ext == ".rar":
        return "rar", "rar"

    # Try UTF-8 plaintext fallback
    try:
        header.decode("utf-8")
        return "text", "plaintext"
    except Exception:
        pass

    return "unknown", ext.lstrip(".") or "binary"


# ---------------------------------------------------------------------------
# ENGINE: OFFICE OPENXML (DOCX/XLSX/PPTX)
# ---------------------------------------------------------------------------

def _analyse_office_openxml(file_path: str, subtype: str) -> dict:
    strings, calls, behaviours, capabilities, macros = [], [], [], [], []

    try:
        from oletools.olevba import VBA_Parser
        vp = VBA_Parser(file_path)
        if vp.detect_vba_macros():
            for (_, _, vba_fn, vba_code) in vp.extract_macros():
                if vba_code:
                    macros.append(vba_fn)
                    for line in vba_code.split("\n"):
                        line = line.strip()
                        if len(line) > 6:
                            strings.append(line[:200])
            for (typ, kw, _) in vp.analyze_macros():
                if typ == "AutoExec":
                    behaviours.append("autoexec_macro")
                    behaviours.append("command_execution")
                    calls.append(kw)
                    capabilities.append("macro_autoexec")
                elif typ == "Suspicious":
                    calls.append(kw)
                elif typ == "IOC":
                    strings.append(kw)
                elif typ in ("Hex String","Base64 String","Dridex String"):
                    behaviours.append("obfuscated_content")
            if macros:
                capabilities.append("macro_present")
        vp.close()
    except Exception as e:
        log.warning(f"[OPENXML VBA] {e}")

    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            for entry in zf.namelist():
                if entry.endswith(".xml") or entry.endswith(".rels"):
                    try:
                        text = zf.read(entry).decode("utf-8", errors="replace")
                        urls = re.findall(r"https?://[^\s\"<>]+", text)
                        strings.extend(urls[:20])
                        ext_refs = re.findall(r'Target="(https?://[^"]+)"', text)
                        for ref in ext_refs:
                            strings.append(f"EXTERNAL_REF: {ref}")
                            behaviours.append("network_activity")
                    except Exception:
                        pass
    except Exception as e:
        log.warning(f"[OPENXML ZIP] {e}")

    strings = _dedup(strings)[:500]
    return {
        "functions": macros, "imports": [],
        "strings": strings, "calls": _dedup(calls),
        "behaviours": _dedup(behaviours), "capabilities": _dedup(capabilities),
        "mitre": [],
        "_meta": {"file_type": subtype.upper(), "subtype": subtype,
                  "extraction_engine": "oletools+zipparse",
                  "macro_count": len(macros), "ioc_count": len(_iocs(strings)),
                  "radare2_available": False, "ghidra_available": False},
        "hashes": _hashes(file_path),
    }


# ---------------------------------------------------------------------------
# ENGINE: OLE2 BINARY (DOC/XLS/PPT/MSI)
# ---------------------------------------------------------------------------

def _analyse_ole2(file_path: str, subtype: str) -> dict:
    strings, calls, behaviours, capabilities, macros = [], [], [], [], []

    try:
        from oletools.olevba import VBA_Parser
        vp = VBA_Parser(file_path)
        if vp.detect_vba_macros():
            capabilities.append("macro_present")
            for (_, _, vba_fn, vba_code) in vp.extract_macros():
                if vba_code:
                    macros.append(vba_fn)
                    for line in vba_code.split("\n"):
                        line = line.strip()
                        if len(line) > 6:
                            strings.append(line[:200])
            for (typ, kw, _) in vp.analyze_macros():
                if typ == "AutoExec":
                    behaviours.append("autoexec_macro")
                    behaviours.append("command_execution")
                    calls.append(kw); capabilities.append("macro_autoexec")
                elif typ == "Suspicious": calls.append(kw)
                elif typ == "IOC": strings.append(kw)
                elif typ in ("Hex String","Base64 String","Dridex String"):
                    behaviours.append("obfuscated_content")
        vp.close()
    except Exception as e:
        log.warning(f"[OLE2 VBA] {e}")

    if subtype == "msi":
        try:
            import olefile
            if olefile.isOleFile(file_path):
                ole = olefile.OleFileIO(file_path)
                for entry in ole.listdir():
                    name = "/".join(entry)
                    strings.append(f"OLE_STREAM: {name}")
                    try:
                        data = ole.openstream(entry).read()
                        strings.extend(_strings_from_bytes(data, min_len=8)[:20])
                    except Exception:
                        pass
                ole.close()
                capabilities.append("msi_installer")
        except Exception as e:
            log.warning(f"[MSI OLE] {e}")

    try:
        with open(file_path, "rb") as f:
            raw = f.read(2 * 1024 * 1024)
        strings.extend(_strings_from_bytes(raw, min_len=8))
    except Exception:
        pass

    strings = _dedup(strings)[:500]
    return {
        "functions": macros, "imports": [],
        "strings": strings, "calls": _dedup(calls),
        "behaviours": _dedup(behaviours), "capabilities": _dedup(capabilities),
        "mitre": [],
        "_meta": {"file_type": subtype.upper(), "subtype": subtype,
                  "extraction_engine": "oletools",
                  "macro_count": len(macros),
                  "radare2_available": False, "ghidra_available": False},
        "hashes": _hashes(file_path),
    }


# ---------------------------------------------------------------------------
# ENGINE: RTF
# ---------------------------------------------------------------------------

def _analyse_rtf(file_path: str) -> dict:
    strings, behaviours, capabilities, calls = [], [], [], []

    try:
        from oletools.rtfobj import RtfObjParser
        with open(file_path, "rb") as f:
            data = f.read()
        parser = RtfObjParser(data)
        parser.parse()
        for obj in parser.objects:
            if obj.is_ole:
                capabilities.append("embedded_ole_object")
                behaviours.append("dynamic_loading")
            if obj.is_package:
                capabilities.append("embedded_package")
                behaviours.append("payload_download")
            if hasattr(obj, "filename") and obj.filename:
                strings.append(f"EMBEDDED_FILE: {obj.filename}")
            if hasattr(obj, "src_path") and obj.src_path:
                strings.append(f"SOURCE_PATH: {obj.src_path}")
    except Exception as e:
        log.warning(f"[RTF] {e}")

    try:
        with open(file_path, "rb") as f:
            raw = f.read(1024 * 1024)
        strings.extend(_strings_from_bytes(raw, min_len=8))
    except Exception:
        pass

    strings = _dedup(strings)[:500]
    return {
        "functions":[], "imports":[],
        "strings": strings, "calls": _dedup(calls),
        "behaviours": _dedup(behaviours), "capabilities": _dedup(capabilities),
        "mitre":[],
        "_meta":{"file_type":"RTF","subtype":"rtf",
                 "extraction_engine":"oletools-rtf",
                 "radare2_available":False,"ghidra_available":False},
        "hashes": _hashes(file_path),
    }


# ---------------------------------------------------------------------------
# ENGINE: PDF
# ---------------------------------------------------------------------------

_PDF_JS = [
    re.compile(r"\beval\b", re.I),
    re.compile(r"app\.launchURL", re.I),
    re.compile(r"this\.exportDataObject", re.I),
    re.compile(r"String\.fromCharCode", re.I),
    re.compile(r"unescape\s*\(", re.I),
    re.compile(r"/OpenAction", re.I),
    re.compile(r"/JS\s", re.I),
    re.compile(r"/JavaScript\s", re.I),
    re.compile(r"/Launch\b", re.I),
    re.compile(r"/SubmitForm\b", re.I),
    re.compile(r"/EmbeddedFile\b", re.I),
    re.compile(r"/RichMedia\b", re.I),
]


def _analyse_pdf(file_path: str) -> dict:
    strings, calls, behaviours, capabilities, metadata = [], [], [], [], {}

    try:
        import pdfplumber
        with pdfplumber.open(file_path) as pdf:
            metadata = pdf.metadata or {}
            for page in pdf.pages[:30]:
                try:
                    text = page.extract_text()
                    if text:
                        for line in text.split("\n"):
                            line = line.strip()
                            if len(line) >= 8:
                                strings.append(line[:300])
                except Exception:
                    pass
    except Exception as e:
        log.warning(f"[PDF pdfplumber] {e}")

    try:
        with open(file_path, "rb") as f:
            raw = f.read(4 * 1024 * 1024)
        raw_text = raw.decode("latin-1", errors="replace")

        for pat in _PDF_JS:
            if pat.search(raw_text):
                token = pat.pattern.strip(r"\b\s/")
                calls.append(token)
                if "JS" in token or "JavaScript" in token or "eval" in token:
                    behaviours.append("javascript_execution")
                    capabilities.append("embedded_javascript")
                if "Launch" in token:
                    behaviours.append("command_execution")
                    capabilities.append("launch_action")
                if "EmbeddedFile" in token:
                    capabilities.append("embedded_file")
                    behaviours.append("payload_download")
                if "SubmitForm" in token:
                    behaviours.append("data_exfiltration")

        for url in re.findall(rb"https?://[^\s\x00-\x1f\"<>]{6,}", raw)[:50]:
            try: strings.append(url.decode("latin-1"))
            except Exception: pass

        strings.extend(_strings_from_bytes(raw, min_len=8))
    except Exception as e:
        log.warning(f"[PDF raw] {e}")

    for k, v in metadata.items():
        if v and isinstance(v, str) and len(v) > 2:
            strings.append(f"PDF_META_{k}: {v}")

    strings = _dedup(strings)[:500]
    return {
        "functions":[], "imports":[],
        "strings": strings, "calls": _dedup(calls),
        "behaviours": _dedup(behaviours), "capabilities": _dedup(capabilities),
        "mitre":[],
        "_meta":{"file_type":"PDF","subtype":"pdf",
                 "extraction_engine":"pdfplumber+raw_scan",
                 "ioc_count":len(_iocs(strings)), "metadata":metadata,
                 "radare2_available":False,"ghidra_available":False},
        "hashes": _hashes(file_path),
    }


# ---------------------------------------------------------------------------
# ENGINE: SCRIPTS (PS1/BAT/VBS/PY/SH/JS/PHP)
# ---------------------------------------------------------------------------

_SCRIPT_RULES = [
    (r"DownloadString|DownloadFile|WebClient|Invoke-WebRequest|wget |curl |urllib|requests\.get|Net\.WebClient",
     "payload_download", "network_communication"),
    (r"Invoke-Expression|IEX|\beval\b|\bexec\b|os\.system|subprocess\.run|subprocess\.Popen|shell_exec|popen\(",
     "command_execution", "command_execution"),
    (r"FromBase64String|base64\.b64decode|-[Ee]nc\b|[Aa]tob\(|btoa\(|String\.fromCharCode",
     "obfuscated_content", "dynamic_loading"),
    (r"HKLM|HKCU|reg\s+add|RegWrite|New-ItemProperty|winreg",
     "registry_persistence", "registry_persistence"),
    (r"schtasks|crontab|\.bashrc|\.profile|autostart|startup",
     "startup_persistence", "startup_persistence"),
    (r"sc\s+create|New-Service|ServiceController",
     "service_creation", "service_creation"),
    (r"Get-Process|tasklist|\bps\b\s+-|proc/",
     "process_enumeration", "process_enumeration"),
    (r"Get-ChildItem|os\.listdir|os\.walk|find\s+/|dir\s+[A-Za-z]",
     "directory_enumeration", "directory_enumeration"),
    (r"whoami|GetUserName|getlogin",
     "system_discovery", "system_discovery"),
    (r"requests\.post|Invoke-WebRequest.*POST|curl.*-d\b|smtplib|ftp\.upload",
     "data_exfiltration", "data_exfiltration"),
    (r"IsDebuggerPresent|CheckRemoteDebugger|\bSleep\(\s*[5-9]\d{3}",
     "anti_debugging", "anti_debugging"),
    (r"VirtualBox|VMware|VBOX|Sandboxie|Wireshark",
     "anti_vm", "anti_vm"),
    (r"socket\.|connect\(|bind\(|listen\(|accept\(",
     "network_communication", "network_communication"),
    (r"CryptEncrypt|Cipher\.|AES\.|RSA\.|hashlib\.",
     "cryptographic_activity", "cryptographic_activity"),
    (r"CreateObject|WScript\.Shell|\.Run\b|ShellExecute|Shell\(",
     "command_execution", "process_creation"),
    (r"ActiveXObject|WScript\.|cscript|wscript",
     "command_execution", "process_creation"),
    (r"powershell\s+-[Ee]nc|powershell\s+-nop|powershell\s+-[Ww]",
     "command_execution", "command_execution"),
    (r"cmd\s*/[cCkK]|cmd\.exe|command\.com",
     "command_execution", "command_execution"),
    (r"net\s+user|net\s+localgroup|whoami|ipconfig|systeminfo",
     "system_discovery", "system_discovery"),
    (r"taskkill|tasklist|sc\s+stop|net\s+stop",
     "process_termination", "process_termination"),
    (r"vssadmin|wmic\s+shadowcopy|bcdedit|wbadmin",
     "file_deletion", "file_deletion"),
]


def _analyse_script(file_path: str, script_type: str) -> dict:
    behaviours: set = set()
    capabilities: set = set()
    strings, calls, imports_list = [], [], []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        return _empty(file_path, f"script_read_failed: {e}")

    for line in content.split("\n"):
        line = line.strip()
        if len(line) >= 6:
            strings.append(line[:300])

    quoted = re.findall(r'"([^"]{6,200})"', content) + re.findall(r"'([^']{6,200})'", content)
    strings.extend(quoted[:200])

    for (pattern, beh, cap) in _SCRIPT_RULES:
        if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
            behaviours.add(beh); capabilities.add(cap)
            m = re.search(pattern, content, re.IGNORECASE)
            if m: calls.append(m.group(0)[:60])

    urls = re.findall(r"https?://[^\s\"'<>]{6,}", content)
    ips  = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", content)
    strings.extend(urls[:30]); strings.extend(ips[:20])
    if urls or ips: behaviours.add("network_activity")

    imports_list = re.findall(r"^(?:import|require|#include)\s+([\w./\"']+)", content, re.MULTILINE)[:30]

    ent = _entropy(content.encode("utf-8", errors="replace"))
    if ent > 5.5:
        behaviours.add("obfuscated_content"); capabilities.add("dynamic_loading")

    strings = _dedup(strings)[:500]
    return {
        "functions":[], "imports": _dedup(imports_list),
        "strings": strings, "calls": _dedup(calls),
        "behaviours": list(behaviours), "capabilities": list(capabilities),
        "mitre":[],
        "_meta":{"file_type":script_type.upper(),"subtype":script_type,
                 "extraction_engine":"pattern_analysis",
                 "entropy":round(ent,2),"line_count":content.count("\n"),
                 "radare2_available":False,"ghidra_available":False},
        "hashes": _hashes(file_path),
    }


# ---------------------------------------------------------------------------
# ENGINE: APK
# ---------------------------------------------------------------------------

_APK_PERMS = {
    "android.permission.INTERNET":               ("network_communication","network_activity"),
    "android.permission.SEND_SMS":               ("data_exfiltration","sms_abuse"),
    "android.permission.READ_CONTACTS":          ("data_exfiltration","contact_access"),
    "android.permission.READ_CALL_LOG":          ("data_exfiltration","call_log_access"),
    "android.permission.RECORD_AUDIO":           ("keylogging","audio_capture"),
    "android.permission.CAMERA":                 ("keylogging","camera_access"),
    "android.permission.ACCESS_FINE_LOCATION":   ("data_exfiltration","location_tracking"),
    "android.permission.READ_SMS":               ("data_exfiltration","sms_read"),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("startup_persistence","startup_persistence"),
    "android.permission.INSTALL_PACKAGES":       ("payload_download","package_install"),
    "android.permission.BIND_DEVICE_ADMIN":      ("privilege_escalation","device_admin"),
}


def _analyse_apk(file_path: str) -> dict:
    strings, permissions, activities, calls = [], [], [], []
    behaviours: set = set()
    capabilities: set = set()
    dex_count = 0

    try:
        with zipfile.ZipFile(file_path, "r") as apk:
            entries = apk.namelist()

            if "AndroidManifest.xml" in entries:
                try:
                    manifest = apk.read("AndroidManifest.xml").decode("latin-1", errors="replace")
                    for perm in re.findall(r"android\.permission\.\w+", manifest):
                        permissions.append(perm)
                        if perm in _APK_PERMS:
                            b, c = _APK_PERMS[perm]
                            behaviours.add(b); capabilities.add(c)
                    pkg = re.findall(r'package="([^"]+)"', manifest)
                    if pkg: strings.append(f"PACKAGE: {pkg[0]}")
                    activities.extend(re.findall(r'android:name="([^"]*Activity[^"]*)"', manifest)[:20])
                    if re.search(r'android:debuggable="true"', manifest):
                        strings.append("FLAG: debuggable=true")
                    if re.search(r'android:allowBackup="true"', manifest):
                        strings.append("FLAG: allowBackup=true")
                except Exception as e:
                    log.warning(f"[APK manifest] {e}")

            dex_files = [e for e in entries if e.endswith(".dex")]
            dex_count = len(dex_files)
            for dex_name in dex_files[:3]:
                try:
                    dex = apk.read(dex_name)
                    strings.extend(_strings_from_bytes(dex, min_len=8)[:200])
                    t = dex.decode("latin-1", errors="replace")
                    if re.search(r"Runtime\.exec|ProcessBuilder", t):
                        behaviours.add("command_execution"); calls.append("Runtime.exec")
                    if re.search(r"HttpURLConnection|OkHttpClient", t):
                        behaviours.add("network_communication"); capabilities.add("http_communication")
                    if re.search(r"DexClassLoader|PathClassLoader", t):
                        behaviours.add("dynamic_loading"); capabilities.add("dynamic_loading")
                    if re.search(r"[Cc]ipher|AES|RSA|encrypt", t):
                        behaviours.add("cryptographic_activity"); capabilities.add("cryptographic_activity")
                except Exception as e:
                    log.warning(f"[APK DEX] {e}")

            for entry in entries:
                if (entry.startswith("assets/") or entry.startswith("lib/")) and len(entry) > 8:
                    try:
                        data = apk.read(entry)
                        if len(data) < 512*1024:
                            strings.extend(_strings_from_bytes(data, min_len=10)[:30])
                    except Exception:
                        pass

    except zipfile.BadZipFile:
        return _empty(file_path, "invalid_apk_zip")
    except Exception as e:
        return _empty(file_path, f"apk_exception: {e}")

    strings = _dedup(strings)[:500]
    return {
        "functions": activities, "imports": permissions,
        "strings": strings, "calls": _dedup(calls),
        "behaviours": list(behaviours), "capabilities": list(capabilities),
        "mitre":[],
        "_meta":{"file_type":"APK","subtype":"apk",
                 "extraction_engine":"apk_static",
                 "permission_count":len(permissions),"dex_files":dex_count,
                 "radare2_available":False,"ghidra_available":False},
        "hashes": _hashes(file_path),
    }


# ---------------------------------------------------------------------------
# ENGINE: ARCHIVES (ZIP / RAR / 7Z / GZ)
# ---------------------------------------------------------------------------

def _analyse_archive(file_path: str, subtype: str) -> dict:
    strings, dangerous_found, behaviours, capabilities = [], [], [], []
    entry_count = 0
    total_uncompressed = 0

    if subtype in ("zip","jar","opendoc") or subtype in ZIP_SUBTYPES.values():
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                for info in zf.infolist():
                    entry_count += 1
                    total_uncompressed += info.file_size
                    ext = Path(info.filename).suffix.lower()
                    strings.append(f"ENTRY: {info.filename} ({info.file_size} bytes)")
                    if ext in DANGEROUS_EXTENSIONS:
                        dangerous_found.append(info.filename)
                    if ".." in info.filename or info.filename.startswith("/"):
                        behaviours.append("path_traversal_attempt")
                        capabilities.append("evasion")
                        strings.append(f"ZIPSLIP: {info.filename}")
                    if info.file_size < 64*1024:
                        try:
                            data = zf.read(info.filename)
                            strings.extend(_strings_from_bytes(data, min_len=8)[:10])
                        except Exception:
                            pass
        except Exception as e:
            log.warning(f"[ZIP] {e}")

    elif subtype in ("rar","sevenzip"):
        try:
            with open(file_path, "rb") as f:
                raw = f.read(2*1024*1024)
            strings = _strings_from_bytes(raw, min_len=8)
        except Exception:
            pass

    elif subtype in ("gzip","bzip2"):
        try:
            with gzip.open(file_path, "rb") as f:
                data = f.read(1024*1024)
            strings = _strings_from_bytes(data, min_len=8)
        except Exception:
            pass

    compressed_size = os.path.getsize(file_path)
    if compressed_size > 0 and total_uncompressed > 0:
        ratio = total_uncompressed / compressed_size
        if ratio > 100 or total_uncompressed > 500*1024*1024:
            behaviours.append("zip_bomb_detected")
            capabilities.append("anti_sandbox")
            strings.append(f"ZIP_BOMB: ratio={ratio:.0f}x uncompressed={total_uncompressed//1024//1024}MB")

    if dangerous_found:
        behaviours.append("payload_download")
        capabilities.append("embedded_executable")
        strings.append(f"DANGEROUS_FILES: {', '.join(dangerous_found[:10])}")

    strings = _dedup(strings)[:500]
    return {
        "functions":[], "imports": dangerous_found[:50],
        "strings": strings, "calls":[],
        "behaviours": _dedup(behaviours), "capabilities": _dedup(capabilities),
        "mitre":[],
        "_meta":{"file_type":subtype.upper(),"subtype":subtype,
                 "extraction_engine":"archive_static",
                 "entry_count":entry_count,"total_uncompressed":total_uncompressed,
                 "dangerous_files":len(dangerous_found),
                 "radare2_available":False,"ghidra_available":False},
        "hashes": _hashes(file_path),
    }


# ---------------------------------------------------------------------------
# ENGINE: IMAGES (PNG / JPG / GIF)
# ---------------------------------------------------------------------------

def _analyse_image(file_path: str, subtype: str) -> dict:
    strings, behaviours, capabilities = [], [], []

    try:
        with open(file_path, "rb") as f:
            raw = f.read()

        strings = _strings_from_bytes(raw, min_len=8)

        if subtype == "png":
            i = 8
            while i < len(raw) - 8:
                try:
                    chunk_len  = struct.unpack(">I", raw[i:i+4])[0]
                    chunk_type = raw[i+4:i+8].decode("ascii", errors="replace")
                    chunk_data = raw[i+8:i+8+chunk_len]
                    if chunk_type in ("tEXt","iTXt","zTXt"):
                        strings.append(f"PNG_META_{chunk_type}: {chunk_data.decode('latin-1',errors='replace')[:200]}")
                    if b"steghide" in chunk_data or b"outguess" in chunk_data:
                        capabilities.append("steganography_indicator")
                        behaviours.append("obfuscated_content")
                    i += 12 + chunk_len
                except Exception:
                    break

        if subtype == "jpg":
            exif_pos = raw.find(b"Exif")
            if exif_pos != -1:
                for s in _strings_from_bytes(raw[exif_pos:exif_pos+512], min_len=4):
                    strings.append(f"EXIF: {s}")

        if b"PK\x03\x04" in raw:
            capabilities.append("embedded_archive")
            behaviours.append("payload_download")
            strings.append("POLYGLOT: embedded ZIP found in image")
        if b"MZ" in raw[100:]:
            capabilities.append("embedded_executable")
            behaviours.append("payload_download")
            strings.append("POLYGLOT: embedded PE found in image")

        ent = _entropy(raw)
        if ent > 7.5:
            capabilities.append("high_entropy_content")
            strings.append(f"HIGH_ENTROPY: {ent:.2f} bits/byte")

    except Exception as e:
        log.warning(f"[IMAGE] {e}")

    strings = _dedup(strings)[:300]
    return {
        "functions":[], "imports":[],
        "strings": strings, "calls":[],
        "behaviours": _dedup(behaviours), "capabilities": _dedup(capabilities),
        "mitre":[],
        "_meta":{"file_type":subtype.upper(),"subtype":subtype,
                 "extraction_engine":"image_static",
                 "radare2_available":False,"ghidra_available":False},
        "hashes": _hashes(file_path),
    }


# ---------------------------------------------------------------------------
# ENGINE: TEXT / DATA
# ---------------------------------------------------------------------------

def _analyse_text(file_path: str, subtype: str) -> dict:
    strings, behaviours, capabilities = [], [], []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(2*1024*1024)

        for line in content.split("\n"):
            line = line.strip()
            if len(line) >= 6:
                strings.append(line[:300])

        urls = re.findall(r"https?://\S+", content)
        ips  = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", content)
        strings.extend(urls[:30]); strings.extend(ips[:20])
        if urls or ips: behaviours.append("network_activity")

        if subtype == "json":
            try:
                data = json.loads(content)
                sensitive = re.compile(r"password|secret|token|api.?key|auth|credential|private.?key", re.I)
                def scan(obj, d=0):
                    if d > 5: return
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            if sensitive.search(str(k)):
                                strings.append(f"SENSITIVE_KEY: {k}")
                                behaviours.append("credential_exposure")
                                capabilities.append("credential_dumping")
                            scan(v, d+1)
                    elif isinstance(obj, list):
                        for item in obj[:20]: scan(item, d+1)
                scan(data)
            except Exception:
                pass

    except Exception as e:
        log.warning(f"[TEXT] {e}")

    strings = _dedup(strings)[:500]
    return {
        "functions":[], "imports":[],
        "strings": strings, "calls":[],
        "behaviours": _dedup(behaviours), "capabilities": _dedup(capabilities),
        "mitre":[],
        "_meta":{"file_type":subtype.upper(),"subtype":subtype,
                 "extraction_engine":"text_static",
                 "radare2_available":False,"ghidra_available":False},
        "hashes": _hashes(file_path),
    }


# ---------------------------------------------------------------------------
# MAIN DISPATCH
# ---------------------------------------------------------------------------

def route_and_extract(file_path: str) -> dict:
    """
    Detect file type and dispatch to the correct static analysis engine.
    Returns a dict compatible with unified_extractor output schema.
    PE/ELF/MachO: returns {"_route_to_radare": True} so unified_extractor
    handles them with Radare2 + Ghidra + CAPA.
    """
    if not os.path.isfile(file_path):
        return _empty(file_path, "file_not_found")

    type_group, subtype = detect_file_type(file_path)
    log.info(f"[ROUTER] {os.path.basename(file_path)} type={type_group} sub={subtype}")

    try:
        if type_group in ("pe", "elf", "macho"):
            return {"_route_to_radare": True, "file_type": type_group.upper(), "subtype": subtype}

        if type_group == "zip_based":
            if subtype == "apk" or subtype == "jar":
                return _analyse_apk(file_path)
            elif subtype in ("zip", "opendoc"):
                return _analyse_archive(file_path, subtype)
            else:
                return _analyse_office_openxml(file_path, subtype)

        if type_group == "ole2":
            return _analyse_ole2(file_path, subtype)

        if type_group == "rtf":
            return _analyse_rtf(file_path)

        if type_group == "pdf":
            return _analyse_pdf(file_path)

        if type_group == "script":
            return _analyse_script(file_path, subtype)

        if type_group in ("rar", "sevenzip", "gzip", "bzip2"):
            return _analyse_archive(file_path, type_group)

        if type_group in ("png", "jpg", "gif"):
            return _analyse_image(file_path, type_group)

        if type_group == "text":
            return _analyse_text(file_path, subtype)

        # Unknown: raw string extraction
        try:
            with open(file_path, "rb") as f:
                raw = f.read(4*1024*1024)
            return {
                "functions":[], "imports":[],
                "strings": _strings_from_bytes(raw),
                "calls":[], "behaviours":[], "capabilities":[], "mitre":[],
                "_meta":{"file_type":"UNKNOWN","subtype":subtype,
                         "extraction_engine":"raw_strings",
                         "radare2_available":False,"ghidra_available":False},
                "hashes": _hashes(file_path),
            }
        except Exception as e:
            return _empty(file_path, f"raw_extraction_failed: {e}")

    except Exception as e:
        log.error(f"[ROUTER] Engine exception for {file_path}: {e}")
        return _empty(file_path, f"engine_exception: {e}")
