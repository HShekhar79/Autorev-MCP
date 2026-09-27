"""
api/routes/upload.py

Authenticated file upload endpoint.

Storage convention:
    job_id     = full uuid4() string (never truncated)
    stored as  = <job_id>.bin under UPLOAD_DIR
The client-supplied filename is stored as metadata only (JobRecord.filename)
and is NEVER used to build a filesystem path.
"""

import hashlib
import os
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user
from core.job_manager import create_job
from database import get_db
from models import User

# ✅ cache invalidation for api/routes/analysis.py's full_pipeline() cache
from api.routes.analysis import _invalidate_cache

router = APIRouter()

# Matches core/cleanup_manager.py's independently-derived UPLOAD_DIR exactly:
# backend/api/routes/upload.py -> parent.parent.parent == backend/
_BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
UPLOAD_DIR = (_BACKEND_DIR / "storage" / "uploads").resolve()
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ARISE_MAX_FILE_MB = int(os.environ.get("ARISE_MAX_FILE_MB", "256"))
MAX_FILE_SIZE = ARISE_MAX_FILE_MB * 1024 * 1024

_CHUNK_SIZE = 1024 * 1024  # 1 MiB streaming chunks

_MAGIC = [
    (b"MZ", "PE Executable (EXE/DLL)"),
    (b"\x7fELF", "ELF Binary"),
    (b"\xca\xfe\xba\xbe", "Mach-O Fat Binary"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit"),
    (b"PK\x03\x04", "ZIP/APK/DOCX/XLSX Archive"),
    (b"Rar!\x1a\x07", "RAR Archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive"),
    (b"%PDF", "PDF Document"),
    (b"\xd0\xcf\x11\xe0", "OLE2 (DOC/XLS/PPT/MSI)"),
]


def _safe_delete(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass


def _compute_sha256(path: Path) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            sha256.update(block)
    return sha256.hexdigest()


def _detect_file_type(path: Path) -> str:
    try:
        with open(path, "rb") as f:
            header = f.read(16)
    except OSError:
        return "Unknown"
    for magic, label in _MAGIC:
        if header[: len(magic)] == magic:
            return label
    return "Unknown"


@router.post("/upload")
async def upload_binary(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    raw_name = file.filename or ""

    # Filename validation happens BEFORE any file is written to disk.
    if not raw_name:
        raise HTTPException(status_code=400, detail="Invalid filename: filename is required")

    if "\x00" in raw_name:
        raise HTTPException(status_code=400, detail="Invalid filename: null bytes not allowed")

    # Display-name only — never used as, or to build, a filesystem path.
    display_name = os.path.basename(raw_name)

    # Bug fix: a filename that is only path separators (e.g. "/", "///")
    # collapses to an empty string under os.path.basename() on POSIX.
    # Reject explicitly with 400 rather than storing empty metadata or
    # risking an unhandled downstream failure.
    if not display_name:
        raise HTTPException(status_code=400, detail="Invalid filename: no usable filename after sanitization")

    job_id = str(uuid.uuid4())
    store_name = f"{job_id}.bin"
    file_path = (UPLOAD_DIR / store_name).resolve()

    # Defense-in-depth: the computed path must remain inside UPLOAD_DIR.
    try:
        file_path.relative_to(UPLOAD_DIR)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid upload target path")

    bytes_written = 0
    try:
        with open(file_path, "wb") as buffer:
            while True:
                chunk = await file.read(_CHUNK_SIZE)
                if not chunk:
                    break
                bytes_written += len(chunk)
                if bytes_written > MAX_FILE_SIZE:
                    buffer.close()
                    _safe_delete(file_path)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds maximum allowed size of {ARISE_MAX_FILE_MB} MB",
                    )
                buffer.write(chunk)
    except HTTPException:
        raise
    except OSError as exc:
        _safe_delete(file_path)
        raise HTTPException(status_code=500, detail="Failed to store uploaded file") from exc

    if bytes_written == 0:
        _safe_delete(file_path)
        raise HTTPException(status_code=400, detail="Empty file rejected")

    sha256_hash = _compute_sha256(file_path)
    file_type = _detect_file_type(file_path)

    _invalidate_cache(str(file_path))

    created = create_job(
        job_id=job_id,
        filename=display_name,
        file_path=str(file_path),
        user_id=current_user.id,
    )
    if not created:
        _safe_delete(file_path)
        raise HTTPException(status_code=500, detail="Job creation failed")

    return {
        "job_id": job_id,
        "filename": display_name,
        "file_path": str(file_path),
        "sha256": sha256_hash,
        "file_size": bytes_written,
        "file_type": file_type,
        "status": "uploaded",
    }
