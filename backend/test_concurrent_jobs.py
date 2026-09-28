"""
test_concurrent_jobs.py

Regression test for concurrent job creation, updates, and result storage.

This test exercises the existing thread-safe InMemoryJobRepository
through the public job_manager API.

Run with:
    python test_concurrent_jobs.py
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

from core import job_manager


# =============================================================================
# Configuration
# =============================================================================

JOB_COUNT = 50
USER_IDS = [1, 2, 3, 4, 5]


# =============================================================================
# Helpers
# =============================================================================

def create_and_complete_job(index: int) -> dict:
    """
    Create one job, update it to processing, then store its result.

    Each worker operates on its own job ID.
    """

    job_id = job_manager.generate_job_id()

    user_id = USER_IDS[index % len(USER_IDS)]

    filename = f"concurrent_test_{index}.exe"
    file_path = f"storage/uploads/{job_id}.exe"

    created = job_manager.create_job(
        job_id=job_id,
        filename=filename,
        file_path=file_path,
        user_id=user_id,
    )

    if not created:
        raise AssertionError(
            f"Failed to create job {job_id}"
        )

    processing = job_manager.update_job(
        job_id,
        "processing",
    )

    if not processing:
        raise AssertionError(
            f"Failed to update job {job_id} to processing"
        )

    result = {
        "test": "concurrent_jobs",
        "index": index,
        "job_id": job_id,
        "user_id": user_id,
    }

    completed = job_manager.set_result(
        job_id,
        result,
    )

    if not completed:
        raise AssertionError(
            f"Failed to complete job {job_id}"
        )

    return {
        "job_id": job_id,
        "user_id": user_id,
        "filename": filename,
        "result": result,
    }


# =============================================================================
# Main regression
# =============================================================================

def test_concurrent_jobs():
    print("\n" + "=" * 80)
    print("REGRESSION: CONCURRENT JOBS")
    print("=" * 80)

    print(f"Jobs to create: {JOB_COUNT}")
    print(f"Worker threads: {JOB_COUNT}")

    created_jobs = []

    # -------------------------------------------------------------------------
    # Concurrent creation + processing + completion
    # -------------------------------------------------------------------------

    with ThreadPoolExecutor(
        max_workers=JOB_COUNT
    ) as executor:

        futures = [
            executor.submit(
                create_and_complete_job,
                index,
            )
            for index in range(JOB_COUNT)
        ]

        for future in as_completed(futures):
            created_jobs.append(
                future.result()
            )

    # -------------------------------------------------------------------------
    # Validate number of completed worker operations
    # -------------------------------------------------------------------------

    assert len(created_jobs) == JOB_COUNT, (
        f"Expected {JOB_COUNT} completed workers, "
        f"got {len(created_jobs)}"
    )

    print(
        f"PASS: {len(created_jobs)} concurrent jobs processed"
    )

    # -------------------------------------------------------------------------
    # Validate UUID/job uniqueness
    # -------------------------------------------------------------------------

    job_ids = [
        job["job_id"]
        for job in created_jobs
    ]

    assert len(job_ids) == len(set(job_ids)), (
        "Duplicate job IDs detected"
    )

    print(
        f"PASS: {len(set(job_ids))} unique job IDs"
    )

    # -------------------------------------------------------------------------
    # Validate every job through repository reads
    # -------------------------------------------------------------------------

    for expected in created_jobs:

        job_id = expected["job_id"]

        job = job_manager.get_job(job_id)

        assert job is not None, (
            f"Job disappeared: {job_id}"
        )

        assert job["job_id"] == job_id

        assert job["user_id"] == expected["user_id"]

        assert job["filename"] == expected["filename"]

        assert job["file_path"] == (
            f"storage/uploads/{job_id}.exe"
        )

        assert job["status"] == "completed"

        assert job["result"] == expected["result"]

    print(
        "PASS: All jobs retained correct ownership, "
        "metadata, status, and result"
    )

    # -------------------------------------------------------------------------
    # Validate repository contains all jobs
    # -------------------------------------------------------------------------

    all_jobs = job_manager.list_jobs()

    all_job_ids = {
        job["job_id"]
        for job in all_jobs
    }

    missing_jobs = set(job_ids) - all_job_ids

    assert not missing_jobs, (
        f"Jobs missing from repository: {missing_jobs}"
    )

    print(
        f"PASS: All {JOB_COUNT} jobs present in repository"
    )

    # -------------------------------------------------------------------------
    # Validate user ownership distribution
    # -------------------------------------------------------------------------

    expected_by_user = {}

    for job in created_jobs:
        user_id = job["user_id"]
        expected_by_user[user_id] = (
            expected_by_user.get(user_id, 0) + 1
        )

    actual_by_user = {}

    for job in created_jobs:
        user_id = job["user_id"]
        actual_by_user[user_id] = (
            actual_by_user.get(user_id, 0) + 1
        )

    assert actual_by_user == expected_by_user

    print(
        f"PASS: User ownership distribution preserved: "
        f"{actual_by_user}"
    )

    print("\n" + "=" * 80)
    print("CONCURRENT JOBS REGRESSION: PASS")
    print("=" * 80)

    return True


# =============================================================================
# Entry point
# =============================================================================

if __name__ == "__main__":
    try:
        test_concurrent_jobs()

    except Exception as exc:
        print("\n" + "=" * 80)
        print("CONCURRENT JOBS REGRESSION: FAIL")
        print("=" * 80)
        print(f"Error: {exc}")

        import traceback

        traceback.print_exc()

        raise SystemExit(1)

    raise SystemExit(0)