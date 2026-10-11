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
    from services.analysis_pipeline import (
        run_analysis_pipeline as _run_pipeline,
        to_legacy_result as _to_legacy_result,
    )
    _PIPELINE_OK = True
    log.info("Pipeline import: OK")
except Exception as _exc:
    _run_pipeline = None
    _to_legacy_result = None
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
        result = _to_legacy_result(_run_pipeline(file_path, progress_cb=_progress))

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


from utils.normalization import (
    compute_hashes as _compute_hashes,
    detect_file_type as _detect_file_type,
    normalise_result as _normalise_result,
    normalise_result,
    compute_hashes,
    detect_file_type,
)
