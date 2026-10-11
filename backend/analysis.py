"""
analysis.py — legacy compatibility wrapper.

There is no analysis algorithm here. run_analysis_pipeline() delegates to the
single authoritative pipeline in services/analysis_pipeline.py and adds the
legacy fields (functions, calls, mitre, risk_score, cvss, verdict, ...) that
existing callers expect. Exceptions (incl. PipelineExtractionFailedError)
propagate unchanged.
"""

from services.analysis_pipeline import (
    PipelineExtractionFailedError,
    run_analysis_pipeline as _shared_pipeline,
    to_legacy_result,
)


def run_analysis_pipeline(file_path: str, progress_cb=None) -> dict:
    return to_legacy_result(_shared_pipeline(file_path, progress_cb=progress_cb))