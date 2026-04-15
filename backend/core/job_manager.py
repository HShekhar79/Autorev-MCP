import threading
from datetime import datetime, timezone
import copy

jobs = {}
lock = threading.Lock()

VALID_STATUSES = {"uploaded", "processing", "completed", "failed"}


# -------------------------------
# CREATE JOB
# -------------------------------
def create_job(job_id, filename):

    if not job_id or not filename:
        return False

    now = datetime.now(timezone.utc).isoformat()

    with lock:
        if job_id in jobs:
            return False

        jobs[job_id] = {
            "job_id": job_id,
            "filename": filename,
            "status": "uploaded",
            "created_at": now,
            "updated_at": now
        }

    return True


# -------------------------------
# UPDATE JOB
# -------------------------------
def update_job(job_id, status):

    if status not in VALID_STATUSES:
        return False

    now = datetime.now(timezone.utc).isoformat()

    with lock:

        if job_id not in jobs:
            return False

        jobs[job_id]["status"] = status
        jobs[job_id]["updated_at"] = now

        return True


# -------------------------------
# GET SINGLE JOB
# -------------------------------
def get_job(job_id):

    with lock:
        job = jobs.get(job_id)

        if not job:
            return None  # or {"error": "job not found"} if you want strict API response

        return copy.deepcopy(job)


# -------------------------------
# LIST ALL JOBS
# -------------------------------
def list_jobs():

    with lock:
        return [copy.deepcopy(job) for job in jobs.values()]