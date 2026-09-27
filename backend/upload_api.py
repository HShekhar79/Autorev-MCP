import os
import uuid
import time
import logging
from pathlib import Path
from typing import Optional, Any

from fastapi import FastAPI, File, UploadFile, HTTPException, Request, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import create_tables, get_db, AnalysisDB, UserDB
from auth.routes import router as auth_router
from auth.dependencies import get_current_user, check_upload_limit
from auth.utils import get_upload_limit
import json
from datetime import datetime

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from celery.result import AsyncResult

from celery_worker import celery_app, run_analysis_task

# ── Report router ────────────────────────────────────────────────────────────
try:
    from api.routes.report import router as report_router
    _REPORT_ROUTER_OK = True
except Exception as _re:
    _REPORT_ROUTER_OK = False
    logging.getLogger("arise.api").warning(f"Report router unavailable: {_re}")

# ── Rate limiting ─────────────────────────────────────────────────────────────
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])
    _RATE_OK = True
except ImportError:
    limiter = None
    _RATE_OK = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("arise.api")

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

UPLOAD_DIR = Path(os.getenv("ARISE_UPLOAD_DIR", "/tmp/arise_uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_MB   = int(os.getenv("ARISE_MAX_FILE_MB", "256"))
MAX_FILE_SIZE = MAX_FILE_MB * 1024 * 1024

_RAW_ORIGINS = os.getenv(
    "ARISE_CORS_ORIGINS",
    "http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000"
)
ALLOWED_ORIGINS = [o.strip() for o in _RAW_ORIGINS.split(",") if o.strip()]

# Magic byte signatures for file type detection
MAGIC_SIGNATURES = [
    (b"MZ",               "PE Executable"),
    (b"\x7fELF",          "ELF Binary"),
    (b"\xca\xfe\xba\xbe", "Mach-O Fat Binary"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit"),
    (b"PK\x03\x04",       "ZIP/APK/DOCX Archive"),
    (b"Rar!\x1a\x07",     "RAR Archive"),
    (b"7z\xbc\xaf\x27\x1c","7-Zip Archive"),
    (b"%PDF",              "PDF Document"),
    (b"\xd0\xcf\x11\xe0", "OLE2 Document"),
]

TEXT_EXTENSIONS = {
    ".js", ".vbs", ".bat", ".ps1", ".py", ".sh", ".php", ".rb",
    ".txt", ".csv", ".json", ".xml", ".log",
}

# ---------------------------------------------------------------------------
# MIDDLEWARES
# ---------------------------------------------------------------------------

class _BodySizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and int(cl) > MAX_FILE_SIZE:
            return JSONResponse(
                status_code=413,
                content={"error": f"Request body exceeds {MAX_FILE_MB} MB limit"},
            )
        return await call_next(request)


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

# ---------------------------------------------------------------------------
# APP
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AutoRev MCP — A.R.I.S.E. Engine",
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)
create_tables()
app.include_router(auth_router)


if _RATE_OK and limiter:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(_SecurityHeadersMiddleware)
app.add_middleware(_BodySizeLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
    max_age=600,
)

if _REPORT_ROUTER_OK:
    app.include_router(report_router)

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def _detect_magic(header: bytes) -> str:
    for magic, label in MAGIC_SIGNATURES:
        if header[:len(magic)] == magic:
            return label
    return "unknown"


def _safe_display_name(filename: str) -> str:
    import re
    if not filename:
        return "upload"
    name = filename.replace("\x00", "").replace("/", "_").replace("\\", "_")
    name = re.sub(r"[^\x20-\x7E]", "_", name)
    return name[:200].strip() or "upload"


def _task_response(task_id: str, status: str, stage: str = "",
                   result=None, error: str = "") -> dict:
    payload: dict = {"task_id": task_id, "status": status}
    if stage:
        payload["stage"] = stage
    if result is not None:
        payload["result"] = result
    if error:
        payload["error"] = error
    return payload


def _validate_result_fields(result: dict, task_id: str):
    mandatory = ["functions", "imports", "strings", "calls",
                 "capabilities", "mitre", "risk_score", "cvss", "verdict",
                 "behaviours", "hashes", "file_type"]
    for field in mandatory:
        val = result.get(field)
        if isinstance(val, list) and len(val) == 0:
            log.warning(f"[{task_id}] EMPTY FIELD: '{field}'")
        elif val is None:
            log.warning(f"[{task_id}] MISSING FIELD: '{field}'")


# ---------------------------------------------------------------------------
# CHAT MODELS
# ---------------------------------------------------------------------------

class ChatSummaryRequest(BaseModel):
    analysis: dict[str, Any]
    question: str = ""


class ChatMitreRequest(BaseModel):
    techniques: list[str]
    question: str = ""


# ---------------------------------------------------------------------------
# CHAT HELPERS
# ---------------------------------------------------------------------------

def _build_summary_text(analysis: dict, question: str) -> str:
    verdict = analysis.get("verdict", {})
    label      = verdict.get("label", verdict.get("verdict", "UNKNOWN"))
    confidence = verdict.get("confidence", verdict.get("confidence_pct", 0))
    category   = verdict.get("category", "")
    summary    = verdict.get("summary", "")
    risk       = analysis.get("risk_score", 0)
    cvss       = analysis.get("cvss", 0)
    cvss_val   = cvss if isinstance(cvss, (int, float)) else cvss.get("cvss_score", 0) if isinstance(cvss, dict) else 0
    caps       = analysis.get("capabilities", [])
    mitre      = analysis.get("mitre", [])
    behaviours = analysis.get("behaviours", [])
    imports    = analysis.get("imports", [])[:8]
    strings    = analysis.get("strings", [])[:6]
    hashes     = analysis.get("hashes", {})
    file_type  = analysis.get("file_type", "Unknown")
    meta       = analysis.get("analysis_meta", {})
    filename   = meta.get("filename", "unknown")
    engine     = meta.get("extraction_engine", "radare2")

    lines = [
        "ARISE MALWARE ANALYSIS SUMMARY",
        "─" * 42,
        f"File        : {filename}",
        f"Type        : {file_type}",
        f"Engine      : {engine.upper()}",
        f"MD5         : {hashes.get('md5', 'N/A')}",
        f"SHA-256     : {hashes.get('sha256', 'N/A')}",
        "",
        f"VERDICT     : {label}",
        f"Confidence  : {confidence}%",
        f"Category    : {category or 'N/A'}",
        f"Risk Score  : {risk:.1f} / 100",
        f"CVSS Score  : {cvss_val:.1f} / 10.0",
        "",
        f"SUMMARY",
        f"  {summary or 'No summary available.'}",
        "",
        f"BEHAVIOURS DETECTED ({len(behaviours)})",
    ]
    for b in behaviours:
        lines.append(f"  • {b.replace('_', ' ').title()}")

    lines += ["", f"CAPABILITIES ({len(caps)})"]
    for c in caps:
        lines.append(f"  • {c.replace('_', ' ').title()}")

    lines += ["", f"MITRE ATT&CK ({len(mitre)})"]
    for t in mitre:
        lines.append(f"  • {t}")

    lines += ["", "KEY IMPORTS"]
    for imp in imports:
        lines.append(f"  • {imp}")

    lines += ["", "NOTABLE STRINGS"]
    for s in strings:
        lines.append(f"  • {s}")

    if question:
        lines += [
            "",
            f"RE: '{question}'",
            f"  Based on the analysis, this binary exhibits {label.lower()} behavior "
            f"with {confidence}% confidence. Primary indicators: "
            f"{', '.join(behaviours[:3]) if behaviours else 'none detected'}.",
        ]
    return "\n".join(lines)


def _build_mitre_text(techniques: list[str], question: str) -> str:
    TECHNIQUE_MAP = {
        "T1055":  ("Process Injection",               "Defense Evasion / Priv Esc", "Injects code into another process address space."),
        "T1071":  ("Application Layer Protocol",       "Command and Control",         "Uses HTTP/DNS/SMTP for C2 blending into normal traffic."),
        "T1547":  ("Boot or Logon Autostart",          "Persistence",                 "Configures system to auto-execute code at boot."),
        "T1059":  ("Command and Scripting Interpreter","Execution",                   "Abuses cmd.exe, PowerShell, bash for malicious commands."),
        "T1134":  ("Access Token Manipulation",        "Defense Evasion / Priv Esc", "Manipulates Windows tokens to gain elevated privileges."),
        "T1082":  ("System Information Discovery",     "Discovery",                   "Gathers OS/hardware info to fingerprint victim environment."),
        "T1083":  ("File and Directory Discovery",     "Discovery",                   "Enumerates files to locate targets for exfiltration."),
        "T1057":  ("Process Discovery",                "Discovery",                   "Lists running processes to find security tools or targets."),
        "T1105":  ("Ingress Tool Transfer",            "Command and Control",         "Downloads tools from external system to compromised host."),
        "T1027":  ("Obfuscated Files",                 "Defense Evasion",             "Encrypts or encodes payloads to evade detection."),
        "T1562":  ("Impair Defenses",                  "Defense Evasion",             "Disables or tampers with security software."),
        "T1003":  ("OS Credential Dumping",            "Credential Access",           "Dumps credentials from OS memory (LSASS, SAM, NTDS)."),
        "T1056":  ("Input Capture / Keylogging",       "Collection",                  "Captures keystrokes to harvest credentials."),
        "T1041":  ("Exfiltration Over C2 Channel",     "Exfiltration",               "Exfiltrates data using the existing C2 channel."),
        "T1486":  ("Data Encrypted for Impact",        "Impact",                      "Encrypts victim data — ransomware technique."),
        "T1485":  ("Data Destruction",                 "Impact",                      "Permanently destroys data on victim systems."),
        "T1055.012": ("Process Hollowing",             "Defense Evasion",             "Replaces legitimate process memory with malicious code."),
    }
    lines = [
        "MITRE ATT&CK TECHNIQUE ANALYSIS",
        "─" * 42,
        f"Techniques identified: {len(techniques)}",
        "",
    ]
    unknown = []
    for tid in techniques:
        if tid in TECHNIQUE_MAP:
            name, tactic, desc = TECHNIQUE_MAP[tid]
            lines += [f"◉ {tid} — {name}", f"  Tactic: {tactic}", f"  {desc}", ""]
        else:
            unknown.append(tid)
    if unknown:
        lines += [f"Additional (see attack.mitre.org): {', '.join(unknown)}", ""]
    if question:
        lines += [f"RE: '{question}'", f"  Review the techniques above for context on this query."]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# ENDPOINTS
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    checks: dict = {"api": "ok"}
    try:
        import redis as _redis
        r = _redis.Redis.from_url(REDIS_URL, socket_connect_timeout=1)
        r.ping()
        checks["redis"] = "ok"
    except Exception as exc:
        checks["redis"] = f"unavailable ({exc})"
    overall = "healthy" if all(v == "ok" for v in checks.values()) else "degraded"
    return {"status": overall, "checks": checks, "timestamp": time.time()}


@app.post("/upload-analyze")
async def upload_analyze(request: Request, file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    display_name = _safe_display_name(file.filename)
    ext = Path(display_name).suffix.lower()

    # UUID-only storage path — original filename never touches filesystem
    job_id     = str(uuid.uuid4())
    store_name = f"{job_id}.bin"
    file_path  = UPLOAD_DIR / store_name

    # Streaming write with size enforcement
    bytes_written = 0
    header_bytes  = b""
    try:
        with open(file_path, "wb") as buf:
            while True:
                chunk = await file.read(65536)
                if not chunk:
                    break
                bytes_written += len(chunk)
                if bytes_written > MAX_FILE_SIZE:
                    buf.close()
                    try:
                        file_path.unlink()
                    except Exception:
                        pass
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds maximum size ({MAX_FILE_MB} MB)",
                    )
                if len(header_bytes) < 16:
                    header_bytes += chunk[:16]
                buf.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:
        try:
            file_path.unlink()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"Upload write failed: {exc}")

    if bytes_written == 0:
        try:
            file_path.unlink()
        except Exception:
            pass
        raise HTTPException(status_code=400, detail="Empty file rejected")

    magic_label = _detect_magic(header_bytes)
    if magic_label == "unknown" and ext not in TEXT_EXTENSIONS:
        log.warning(f"[{job_id}] Unknown file type: ext={ext!r} header={header_bytes[:8].hex()!r}")

    log.info(f"[{job_id}] Accepted: {display_name!r} ({bytes_written} bytes) type={magic_label}")

    task = run_analysis_task.delay(str(file_path), display_name)
    log.info(f"[{job_id}] Enqueued task {task.id}")

    return JSONResponse(
        status_code=202,
        content=_task_response(task_id=task.id, status="pending", stage="queued"),
    )


@app.get("/task-status/{task_id}")
def task_status(task_id: str):
    try:
        result: AsyncResult = AsyncResult(task_id, app=celery_app)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid task id: {exc}")

    state = result.state

    if state == "PENDING":
        return _task_response(task_id=task_id, status="pending", stage="queued")

    if state == "PROGRESS":
        meta = result.info or {}
        return _task_response(
            task_id=task_id, status="processing",
            stage=meta.get("stage", ""), result={"pct": meta.get("pct", 0)}
        )

    if state == "SUCCESS":
        raw_result = result.result
        if isinstance(raw_result, dict):
            _validate_result_fields(raw_result, task_id)
            log.info(
                f"[{task_id}] SUCCESS — "
                f"caps={len(raw_result.get('capabilities',[]))} "
                f"mitre={len(raw_result.get('mitre',[]))} "
                f"risk={raw_result.get('risk_score')} "
                f"cvss={raw_result.get('cvss')}"
            )
        return _task_response(task_id=task_id, status="completed", result=raw_result)

    if state == "FAILURE":
        err = str(result.info) if result.info else "Unknown error"
        return _task_response(task_id=task_id, status="failed", error=err)

    return _task_response(task_id=task_id, status=state.lower())


@app.post("/chat-summary")
async def chat_summary(req: ChatSummaryRequest):
    try:
        text = _build_summary_text(req.analysis, req.question)
        return {"response": text, "source": "builtin"}
    except Exception as exc:
        log.error(f"chat-summary error: {exc}")
        return {"response": "Analysis summary unavailable.", "source": "error", "warning": str(exc)}


@app.post("/chat-mitre")
async def chat_mitre(req: ChatMitreRequest):
    if not req.techniques:
        return {"response": "No MITRE techniques detected in this binary.", "source": "builtin"}
    try:
        text = _build_mitre_text(req.techniques, req.question)
        return {"response": text, "source": "builtin"}
    except Exception as exc:
        log.error(f"chat-mitre error: {exc}")
        return {"response": "MITRE explanation unavailable.", "source": "error", "warning": str(exc)}


@app.delete("/task/{task_id}")
def revoke_task(task_id: str):
    try:
        celery_app.control.revoke(task_id, terminate=True)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return {"task_id": task_id, "status": "revoked"}


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("upload_api:app", host="0.0.0.0", port=8000, reload=True)
