import os
import hashlib
import uuid

from fastapi import APIRouter, UploadFile, File
from core.job_manager import create_job

# ✅ ADD THIS IMPORT
from api.routes.analysis import _invalidate_cache

router = APIRouter()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_DIR = os.path.abspath(
    os.path.join(BASE_DIR, "..", "storage", "uploads")
)

os.makedirs(UPLOAD_DIR, exist_ok=True)


def calculate_sha256(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)

    return sha256.hexdigest()


@router.post("/upload")
async def upload_binary(file: UploadFile = File(...)):

    try:
        job_id = str(uuid.uuid4())[:8]

        if not file.filename:
            return {"error": "invalid file"}

        safe_name = os.path.basename(file.filename)
        filename = f"{job_id}_{safe_name}"

        file_path = os.path.join(UPLOAD_DIR, filename)

        # ✅ STREAM WRITE (SAFE)
        with open(file_path, "wb") as buffer:
            while True:
                chunk = await file.read(4096)
                if not chunk:
                    break
                buffer.write(chunk)

        if os.path.getsize(file_path) == 0:
            return {"error": "empty file"}

        sha256_hash = calculate_sha256(file_path)

        # ✅ CACHE INVALIDATION (IMPORTANT 🔥)
        _invalidate_cache(file_path)

        # ✅ JOB CREATE
        if not create_job(job_id, filename):
            return {"error": "job creation failed"}

        return {
            "job_id": job_id,
            "filename": filename,
            "sha256": sha256_hash,
            "status": "uploaded"
        }

    except Exception as e:
        return {"error": str(e)}