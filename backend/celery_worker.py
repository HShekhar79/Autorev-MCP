from dotenv import load_dotenv
import os as _os

# Load .env from backend/ directory with EXPLICIT path
# Celery spawns child workers with different CWD — load_dotenv() without
# a path fails silently in child processes. We find backend/.env explicitly.
_THIS_FILE    = _os.path.abspath(__file__)
_BACKEND_DIR  = _os.path.dirname(_THIS_FILE)
_ENV_FILE     = _os.path.join(_BACKEND_DIR, '.env')
if _os.path.isfile(_ENV_FILE):
    load_dotenv(_ENV_FILE, override=True)

import os
import sys
import time
import hashlib
import logging
import traceback

# ---------------------------------------------------------------------------
# PATH RESOLUTION
# ---------------------------------------------------------------------------

_PROJECT_ROOT = os.path.dirname(_BACKEND_DIR)

for _path in (_BACKEND_DIR, _PROJECT_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

# ---------------------------------------------------------------------------
# CELERY APP
# ---------------------------------------------------------------------------

from celery import Celery

REDIS_URL = os.getenv("ARISE_REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "arise_worker",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    result_expires=3600,
    task_track_started=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)

# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("arise.worker")

# Log .env status at startup
log.info(f".env path: {_ENV_FILE}")
log.info(f".env loaded: {os.path.isfile(_ENV_FILE)}")
log.info(f"ARISE_CAPA_PATH: {os.getenv('ARISE_CAPA_PATH', 'NOT SET')}")
log.info(f"ARISE_CAPA_RULES: {os.getenv('ARISE_CAPA_RULES', 'NOT SET')}")

# ---------------------------------------------------------------------------
# PIPELINE IMPORT
# ---------------------------------------------------------------------------

try:
    from analysis import run_analysis_pipeline as _run_pipeline
    _PIPELINE_OK = True
    log.info("Pipeline import: OK")
except Exception as _exc:
    _run_pipeline = None
    _PIPELINE_OK  = False
    log.error(f"Pipeline import FAILED: {_exc}")


# ---------------------------------------------------------------------------
# TASK
# ---------------------------------------------------------------------------

@celery_app.task(
    bind=True,
    name="arise.run_analysis",
    max_retries=2,
    soft_time_limit=300,
    time_limit=360,
)
def run_analysis_task(self, file_path: str, original_name: str = "") -> dict:
    log.info(f"[{self.request.id}] START: {file_path} ({original_name})")
    t0 = time.time()

    def _progress(stage: str, pct: int = 0):
        self.update_state(
            state="PROGRESS",
            meta={"stage": stage, "pct": pct, "elapsed": round(time.time() - t0, 1)},
        )
        log.info(f"[{self.request.id}] STAGE={stage} pct={pct}")

    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Upload not found on worker: {file_path}")

    if not _PIPELINE_OK or _run_pipeline is None:
        raise RuntimeError("Analysis pipeline not available on worker")

    try:
        result = _run_pipeline(file_path, progress_cb=_progress)

        if not isinstance(result, dict):
            raise ValueError(f"Pipeline returned unexpected type: {type(result)}")

        # Diagnostic logging
        log.info(f"[{self.request.id}] Pipeline keys: {list(result.keys())}")
        for field in ["behaviours", "capabilities", "mitre", "functions", "imports", "strings", "calls"]:
            val = result.get(field, [])
            count = len(val) if isinstance(val, list) else "?"
            if isinstance(val, list) and count == 0:
                log.warning(f"[{self.request.id}] EMPTY: {field}")
            else:
                log.info(f"[{self.request.id}] {field}: {count}")

        log.info(f"[{self.request.id}] risk_score: {result.get('risk_score')}")
        log.info(f"[{self.request.id}] cvss_score: {result.get('cvss_score')}")
        v = result.get("verdict", {})
        log.info(f"[{self.request.id}] verdict: {v.get('verdict') if isinstance(v, dict) else v}")

        # Compute hashes before deleting the file
        hashes   = _compute_hashes(file_path)
        file_type = _detect_file_type(file_path)

        _cleanup_upload(file_path)
        elapsed = round(time.time() - t0, 2)
        log.info(f"[{self.request.id}] DONE in {elapsed}s")

        return _normalise_result(result, elapsed, original_name, hashes, file_type)

    except Exception as exc:
        log.error(f"[{self.request.id}] FAILED: {exc}")
        log.debug(traceback.format_exc())
        _cleanup_upload(file_path)
        raise


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def _cleanup_upload(file_path: str):
    try:
        if os.path.isfile(file_path):
            os.remove(file_path)
            log.info(f"Cleaned up: {file_path}")
    except Exception as exc:
        log.warning(f"Cleanup failed for {file_path}: {exc}")


def _compute_hashes(file_path: str) -> dict:
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


def _detect_file_type(file_path: str) -> str:
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
    verdict_raw = raw.get("verdict", {})
    if isinstance(verdict_raw, dict) and "verdict" in verdict_raw \
            and isinstance(verdict_raw["verdict"], dict):
        inner = dict(verdict_raw["verdict"])
        for k, v in verdict_raw.items():
            if k != "verdict" and k not in inner:
                inner[k] = v
        verdict = inner
    elif isinstance(verdict_raw, dict):
        verdict = verdict_raw
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


def _normalise_result(
    raw: dict,
    elapsed: float,
    original_name: str,
    hashes: dict = None,
    file_type: str = "Unknown",
) -> dict:
    meta = raw.get("analysis_meta", {})

    cvss_raw = raw.get("cvss", raw.get("cvss_score", 0))
    if isinstance(cvss_raw, dict):
        cvss_val    = float(cvss_raw.get("cvss_score", 0) or 0)
        cvss_detail = cvss_raw
    elif isinstance(cvss_raw, (int, float)):
        cvss_val    = float(cvss_raw)
        cvss_detail = {
            "cvss_score": cvss_val,
            "risk_level": "HIGH" if cvss_val >= 7 else "MEDIUM" if cvss_val >= 4 else "LOW",
        }
    else:
        cvss_val    = 0.0
        cvss_detail = {"cvss_score": 0.0, "risk_level": "NONE"}

    mitre        = _resolve_mitre(raw)
    verdict      = _resolve_verdict(raw)
    behaviours   = _resolve_behaviours(raw)
    capabilities = _coerce_list(raw.get("capabilities", []))

    for field, val in [("capabilities", capabilities), ("mitre", mitre), ("behaviours", behaviours)]:
        if not val:
            log.warning(f"_normalise_result: EMPTY field '{field}'")

    return {
        "functions":     _coerce_list(raw.get("functions", [])),
        "imports":       _coerce_list(raw.get("imports", [])),
        "strings":       _coerce_list(raw.get("strings", [])),
        "calls":         _coerce_list(raw.get("calls", [])),
        "behaviours":    behaviours,
        "capabilities":  capabilities,
        "mitre":         mitre,
        "risk_score":    float(raw.get("risk_score", 0)),
        "cvss":          cvss_val,
        "cvss_detail":   cvss_detail,
        "verdict":       verdict,
        "summary":       raw.get("summary", verdict.get("summary", "")),
        "hashes":        hashes or {"md5": "N/A", "sha1": "N/A", "sha256": "N/A"},
        "file_type":     file_type,
        "analysis_meta": {
            "ghidra_available":   meta.get("ghidra_available", False),
            "radare2_available":  meta.get("radare2_available", True),
            "extraction_engine":  meta.get("extraction_engine", "radare2"),
            "capa_enabled":       meta.get("capa_enabled", False),
            "capa_mitre_count":   meta.get("capa_mitre_count", 0),
            "extraction_elapsed": meta.get("extraction_elapsed"),
            "total_elapsed":      elapsed,
            "filename":           original_name,
        },
    }
