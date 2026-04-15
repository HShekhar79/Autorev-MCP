"""
engines/similarity_engine/similarity_engine.py

Malware family similarity detection via behaviour overlap.

STATUS: KEEP — future integration. Wire into /report or a dedicated
        /similarity/{job_id} endpoint once malware_families.json is populated.

STRUCTURAL FIX:
    Original was stored at: engines/similarity_engine.py/similarity_engine.py
    (a FILE named "similarity_engine.py" was treated as a DIRECTORY — packaging bug).
    Correct location: engines/similarity_engine/similarity_engine.py
    Add an __init__.py alongside this file.

NO LOGIC BUGS found. Code is clean.
"""

import json
import os
import logging
from typing import Dict, List, Any, Tuple
from utils.normalization import normalize_behavior

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "malware_families.json")


def load_family_profiles() -> Dict[str, Any]:
    """Load malware family behaviour profiles from JSON database."""
    try:
        if not os.path.exists(DB_PATH):
            logger.warning("Malware family database not found at: %s", DB_PATH)
            return {}

        with open(DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            logger.error("Invalid malware family database format.")
            return {}

        return data

    except Exception as e:
        logger.error("Failed to load malware family profiles: %s", e)
        return {}

def calculate_similarity(sample_behaviours, family_behaviours):

    if not sample_behaviours or not family_behaviours:
        return 0.0, []

    sample_set = {
        normalize_behavior(b)
        for b in sample_behaviours
        if normalize_behavior(b)
    }

    family_set = {
        normalize_behavior(b)
        for b in family_behaviours
        if normalize_behavior(b)
    }

    matched = list(sample_set.intersection(family_set))

    score = len(matched) / len(family_set) if family_set else 0.0

    return score, matched


def detect_similar_family(sample_behaviours: List[str]) -> Dict[str, Any]:
    """
    Identify the most similar known malware family.

    Args:
        sample_behaviours: list of canonical behaviour name strings

    Returns:
        {family, similarity, matched_behaviours, sample_behaviour_count}
    """
    try:
        families = load_family_profiles()

        if not families:
            return {
                "family": None,
                "similarity": 0.0,
                "matched_behaviours": [],
                "sample_behaviour_count": len(sample_behaviours),
            }

        best_family = None
        best_score = 0.0
        best_matches: List[str] = []

        for family, profile in families.items():
            family_behaviours = profile.get("behaviours", [])
            score, matches = calculate_similarity(sample_behaviours, family_behaviours)

            if score > best_score:
                best_score = score
                best_family = family
                best_matches = matches

        return {
            "family": best_family,
            "similarity": round(best_score, 2),
            "matched_behaviours": best_matches,
            "sample_behaviour_count": len(sample_behaviours),
        }

    except Exception as e:
        logger.error("Similarity detection failed: %s", e)
        return {"error": str(e)}
