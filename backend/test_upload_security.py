"""
test_upload_security.py

Regression coverage for the ACTIVE production upload endpoint:
    main.py -> api.routes.upload.router -> POST /upload

Tests main:app directly via FastAPI's TestClient (no live uvicorn server
required, no production code modified). Uses the project's real database
and real authentication flow (/auth/register, /auth/login) exactly as the
existing test_job_ownership.py / test_pe_api.py do over HTTP — only the
transport differs (in-process TestClient vs. live-server urllib).

IMPORTANT — RUN THIS FILE IN ISOLATION:
upload.py computes MAX_FILE_SIZE from ARISE_MAX_FILE_MB at module import
time. This file sets that env var to a small value BEFORE importing main,
so the oversized-upload test can run against a small (fast) payload rather
than allocating hundreds of MB. This only works if this test module is the
first to import `main` in the process — if another test module in the same
pytest session imports `main` first, the env var change has no effect on
the already-computed MAX_FILE_SIZE (a property of module-level config
evaluation, not a defect in upload.py). Run with:

    pytest -q test_upload_security.py

not as part of a combined multi-file pytest session, unless that session
is also launched fresh with ARISE_MAX_FILE_MB pre-set in the environment.
"""

import os

# Must be set BEFORE `import main` — see module docstring above.
os.environ.setdefault("ARISE_MAX_FILE_MB", "1")

import re
import uuid
import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from main import app
from api.routes.upload import UPLOAD_DIR, MAX_FILE_SIZE
from core.job_manager import get_job, expire_job


client = TestClient(app)

_UUID_BIN_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.bin$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Multipart body construction — matches the raw-boundary style already used
# in test_pe_api.py / test_job_ownership.py, and is required (rather than
# TestClient's `files=` shortcut) so a literal null byte can be embedded in
# the filename for the null-byte-rejection test.
# ---------------------------------------------------------------------------

def _build_multipart(filename: str, content: bytes,
                      content_type: str = "application/octet-stream") -> tuple[bytes, str]:
    boundary = "----AutoRevUploadSecurityBoundary"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n"
        "\r\n"
    ).encode("utf-8") + content + f"\r\n--{boundary}--\r\n".encode("utf-8")
    return body, f"multipart/form-data; boundary={boundary}"


def _post_upload(body: bytes, content_type: str, token: str | None):
    headers = {"Content-Type": content_type}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return client.post("/upload", content=body, headers=headers)


def _count_upload_dir_files() -> int:
    if not UPLOAD_DIR.exists():
        return 0
    return sum(1 for _ in UPLOAD_DIR.iterdir())


# ---------------------------------------------------------------------------
# Auth fixture — real register/login flow, unique user per test run to
# avoid 409 collisions across repeated runs.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def auth_token():
    unique = uuid.uuid4().hex[:12]
    email = f"upload.security.{unique}@example.com"
    username = f"upload_sec_{unique}"
    password = "UploadSecurity-Test-123!"

    register_resp = client.post("/auth/register", json={
        "email": email,
        "username": username,
        "password": password,
        "full_name": "Upload Security Test",
    })
    assert register_resp.status_code in (200, 201), register_resp.text

    login_resp = client.post("/auth/login", json={
        "email": email,
        "password": password,
    })
    assert login_resp.status_code == 200, login_resp.text
    return login_resp.json()["access_token"]


@pytest.fixture(scope="module")
def auth_user_id(auth_token):
    me_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {auth_token}"})
    assert me_resp.status_code == 200, me_resp.text
    return me_resp.json()["id"]


# Track (job_id, file_path) created by tests so they can be cleaned up.
_created_jobs: list[tuple[str, str]] = []


@pytest.fixture(autouse=True, scope="module")
def _cleanup_created_jobs():
    yield
    for job_id, file_path in _created_jobs:
        try:
            p = Path(file_path)
            if p.exists():
                p.unlink()
        except Exception:
            pass
        try:
            expire_job(job_id)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 1. Unauthenticated upload rejected
# ---------------------------------------------------------------------------

def test_unauthenticated_upload_rejected():
    """
    Validates: api/routes/upload.py's `current_user: User = Depends(get_current_user)`
    dependency, and auth/dependencies.py's authentication_required() (401 with
    WWW-Authenticate: Bearer) when no credentials are supplied at all.
    """
    body, content_type = _build_multipart("noauth.bin", b"some bytes")
    resp = _post_upload(body, content_type, token=None)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 2. Empty file rejected
# ---------------------------------------------------------------------------

def test_empty_file_rejected(auth_token):
    """
    Validates: upload.py's post-write `if bytes_written == 0:` branch,
    returning 400 "Empty file rejected", and that _safe_delete() removes
    the zero-byte file it had already created before rejecting.
    """
    before = _count_upload_dir_files()
    body, content_type = _build_multipart("empty.bin", b"")
    resp = _post_upload(body, content_type, token=auth_token)
    assert resp.status_code == 400
    assert "empty" in resp.json().get("detail", "").lower()
    after = _count_upload_dir_files()
    assert after == before, "empty-file rejection must not leave a stored file"


# ---------------------------------------------------------------------------
# 3. Oversized upload rejected (413)
# ---------------------------------------------------------------------------

def test_oversized_upload_rejected(auth_token):
    """
    Validates: upload.py's streaming `if bytes_written > MAX_FILE_SIZE:`
    check inside the write loop, returning 413 with the configured
    ARISE_MAX_FILE_MB in the detail message, and that the partially-written
    file is deleted via _safe_delete() rather than left on disk.

    Uses ARISE_MAX_FILE_MB=1 (set at the top of this module before `main`
    was imported) so this test sends ~2 MB instead of 256+ MB.
    """
    before = _count_upload_dir_files()
    oversized_content = b"A" * (MAX_FILE_SIZE + (1024 * 1024))
    body, content_type = _build_multipart("big.bin", oversized_content)
    resp = _post_upload(body, content_type, token=auth_token)
    assert resp.status_code == 413
    assert "exceeds maximum" in resp.json().get("detail", "").lower()
    after = _count_upload_dir_files()
    assert after == before, "oversized rejection must not leave a stored file"


# ---------------------------------------------------------------------------
# 4. Null-byte filename rejected
# ---------------------------------------------------------------------------

def test_null_byte_filename_rejected(auth_token):
    """
    Validates: upload.py's `if "\\x00" in raw_name:` check, which runs
    BEFORE any file is written to disk, returning 400 "Invalid filename:
    null bytes not allowed".
    """
    before = _count_upload_dir_files()
    body, content_type = _build_multipart("evil\x00.exe", b"some bytes")
    resp = _post_upload(body, content_type, token=auth_token)
    assert resp.status_code == 400
    assert "null bytes" in resp.json().get("detail", "").lower()
    after = _count_upload_dir_files()
    assert after == before, "null-byte rejection occurs before any file is written"


# ---------------------------------------------------------------------------
# 5. Path traversal filename cannot become the filesystem path
# ---------------------------------------------------------------------------

def test_path_traversal_filename_is_not_used_as_storage_path(auth_token):
    """
    Validates: upload.py never uses the client filename as a filesystem
    path at all — storage path is always `{uuid4}.bin` under UPLOAD_DIR
    (the `store_name = f"{job_id}.bin"` line), plus the defense-in-depth
    `file_path.relative_to(UPLOAD_DIR)` containment check.
    """
    body, content_type = _build_multipart("../../evil.exe", b"MZ" + b"\x90" * 32)
    resp = _post_upload(body, content_type, token=auth_token)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    _created_jobs.append((data["job_id"], data["file_path"]))

    stored_path = Path(data["file_path"]).resolve()
    try:
        stored_path.relative_to(UPLOAD_DIR)
    except ValueError:
        pytest.fail(f"stored path escaped UPLOAD_DIR: {stored_path}")

    assert _UUID_BIN_RE.match(stored_path.name), (
        f"stored filename is not UUID4-based: {stored_path.name}"
    )
    assert "evil" not in stored_path.name
    assert ".." not in stored_path.name


# ---------------------------------------------------------------------------
# 6/7/8/9. Valid upload accepted, response contract, sha256, UUID naming
# ---------------------------------------------------------------------------

def test_valid_small_binary_accepted_with_full_response_contract(auth_token):
    """
    Validates:
    - A valid small binary (PE magic bytes) is accepted with HTTP 200.
    - Response contains job_id, filename, file_path, sha256, file_size,
      file_type, status (the exact dict literal returned at the end of
      upload_binary()).
    - sha256 returned matches the actual uploaded bytes
      (_compute_sha256() reads back the written file and hashes it).
    - Stored filename is UUID4-based (`{job_id}.bin`) and contains no
      trace of the client-supplied display filename.
    """
    content = b"MZ" + b"\x90" * 64 + b"AUTOREV_UPLOAD_SECURITY_TEST_PAYLOAD"
    expected_sha256 = hashlib.sha256(content).hexdigest()

    body, content_type = _build_multipart("legitimate_sample.exe", content)
    resp = _post_upload(body, content_type, token=auth_token)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    _created_jobs.append((data["job_id"], data["file_path"]))

    for key in ("job_id", "filename", "file_path", "sha256", "file_size", "file_type", "status"):
        assert key in data, f"missing expected response key: {key}"

    assert data["status"] == "uploaded"
    assert data["file_size"] == len(content)
    assert data["sha256"] == expected_sha256

    stored_name = Path(data["file_path"]).name
    assert _UUID_BIN_RE.match(stored_name), f"not UUID4-based: {stored_name}"
    assert "legitimate_sample" not in stored_name
    assert stored_name.startswith(data["job_id"])


# ---------------------------------------------------------------------------
# 10. Job associated with the authenticated user
# ---------------------------------------------------------------------------

def test_uploaded_job_is_associated_with_authenticated_user(auth_token, auth_user_id):
    """
    Validates: upload.py's `create_job(..., user_id=current_user.id)` call —
    checked against the real job repository via core.job_manager.get_job(),
    the same public API the rest of the application uses for ownership.
    """
    content = b"MZ" + b"\x90" * 16
    body, content_type = _build_multipart("ownership_check.bin", content)
    resp = _post_upload(body, content_type, token=auth_token)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    _created_jobs.append((data["job_id"], data["file_path"]))

    job = get_job(data["job_id"])
    assert job is not None
    assert job["user_id"] == auth_user_id
    assert job["file_path"] == data["file_path"]
    assert job["filename"] == data["filename"]
    assert job["status"] == "uploaded"