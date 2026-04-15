"""
config/capa_config.py

CAPA integration configuration.

This file centralizes all CAPA-related configuration settings.
Override values via environment variables or modify defaults here.
"""

import os


# =============================================================================
# CAPA EXECUTABLE
# =============================================================================

# CAPA executable name (auto-detected in PATH)
CAPA_EXECUTABLE_NAME = "capa"

# Manual override path (optional)
# Set to None for auto-detection
CAPA_EXECUTABLE_PATH = os.environ.get("CAPA_EXECUTABLE_PATH", None)


# =============================================================================
# CAPA RULES
# =============================================================================

# Default CAPA rules directory
# Override with CAPA_RULES_PATH environment variable
DEFAULT_RULES_PATH = "./capa-rules"

# Get rules path from environment or use default
CAPA_RULES_PATH = os.environ.get("CAPA_RULES_PATH", DEFAULT_RULES_PATH)

# Alternative rules paths to check (in order)
ALTERNATIVE_RULES_PATHS = [
    "/opt/capa-rules",
    "/usr/local/share/capa-rules",
    os.path.expanduser("~/.capa/rules")
]


# =============================================================================
# EXECUTION SETTINGS
# =============================================================================

# CAPA execution timeout (seconds)
# Increase for very large binaries
CAPA_TIMEOUT = int(os.environ.get("CAPA_TIMEOUT", "120"))

# CAPA command-line arguments
# Add custom args here (e.g., ["-v"] for verbose)
CAPA_EXTRA_ARGS = os.environ.get("CAPA_EXTRA_ARGS", "").split() if os.environ.get("CAPA_EXTRA_ARGS") else []


# =============================================================================
# INTEGRATION SETTINGS
# =============================================================================

# Enable CAPA integration
# Set to False to completely disable CAPA (for testing)
CAPA_ENABLED = os.environ.get("CAPA_ENABLED", "true").lower() in ("true", "1", "yes")

# Confidence score for CAPA detections (0.0 - 1.0)
# CAPA is rule-based, so high confidence is appropriate
CAPA_CONFIDENCE = float(os.environ.get("CAPA_CONFIDENCE", "0.9"))

# Merge function-level CAPA capabilities into function results
MERGE_FUNCTION_CAPABILITIES = True

# Weight capability MITRE higher than behavior MITRE in fusion
WEIGHT_CAPABILITY_MITRE = True

# Capability MITRE weight multiplier
CAPABILITY_MITRE_WEIGHT = 1.5


# =============================================================================
# ERROR HANDLING
# =============================================================================

# Behavior when CAPA executable not found
# Options: "skip", "degraded", "error"
CAPA_NOT_FOUND_MODE = os.environ.get("CAPA_NOT_FOUND_MODE", "degraded")

# Behavior when CAPA rules not found
# Options: "skip", "degraded", "error"
RULES_NOT_FOUND_MODE = os.environ.get("RULES_NOT_FOUND_MODE", "degraded")

# Behavior when CAPA execution fails
# Options: "skip", "error"
EXECUTION_FAILED_MODE = os.environ.get("EXECUTION_FAILED_MODE", "skip")


# =============================================================================
# DEDUPLICATION SETTINGS
# =============================================================================

# Deduplication strategy for capabilities
# Options: "max_confidence", "first", "merge"
DEDUP_STRATEGY = os.environ.get("DEDUP_STRATEGY", "max_confidence")

# When multiple sources detect same capability, how to combine confidence:
# - "max": Use maximum confidence (default, prevents inflation)
# - "average": Use average confidence
# - "weighted": Use weighted average based on source priority
CONFIDENCE_MERGE_MODE = os.environ.get("CONFIDENCE_MERGE_MODE", "max")

# Source priority (higher = more trusted)
SOURCE_PRIORITY = {
    "capa": 3,        # CAPA is rule-based, highest trust
    "behavior": 2,    # Behavior detection is reliable
    "function": 1,    # Function-level heuristics less certain
    "unknown": 0
}


# =============================================================================
# MITRE FUSION SETTINGS
# =============================================================================

# MITRE score merge strategy
# Options: "max", "sum", "average"
# "max" recommended to prevent score inflation
MITRE_SCORE_MERGE = os.environ.get("MITRE_SCORE_MERGE", "max")

# Base MITRE score for behavior detections
BEHAVIOR_MITRE_BASE_SCORE = 1.5

# Base MITRE score for capability detections (when weight_capabilities=False)
CAPABILITY_MITRE_BASE_SCORE = 2.0


# =============================================================================
# VALIDATION SETTINGS
# =============================================================================

# Enable global capability consistency validation
VALIDATE_GLOBAL_CAPABILITIES = os.environ.get("VALIDATE_GLOBAL_CAPABILITIES", "true").lower() in ("true", "1", "yes")

# Enable MITRE deduplication validation
VALIDATE_MITRE_DEDUPLICATION = os.environ.get("VALIDATE_MITRE_DEDUPLICATION", "true").lower() in ("true", "1", "yes")

# Raise error on validation failure (vs. logging warning)
STRICT_VALIDATION = os.environ.get("STRICT_VALIDATION", "false").lower() in ("true", "1", "yes")


# =============================================================================
# LOGGING & DEBUG
# =============================================================================

# Enable CAPA debug logging
CAPA_DEBUG = os.environ.get("CAPA_DEBUG", "false").lower() in ("true", "1", "yes")

# Log CAPA command before execution
LOG_CAPA_COMMAND = os.environ.get("LOG_CAPA_COMMAND", "true").lower() in ("true", "1", "yes")

# Log CAPA output (JSON)
LOG_CAPA_OUTPUT = os.environ.get("LOG_CAPA_OUTPUT", "false").lower() in ("true", "1", "yes")


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_config_summary() -> dict:
    """
    Get current configuration summary.
    
    Returns:
        dict with all config values
    """
    return {
        "capa_enabled": CAPA_ENABLED,
        "capa_rules_path": CAPA_RULES_PATH,
        "capa_timeout": CAPA_TIMEOUT,
        "capa_confidence": CAPA_CONFIDENCE,
        "merge_function_capabilities": MERGE_FUNCTION_CAPABILITIES,
        "weight_capability_mitre": WEIGHT_CAPABILITY_MITRE,
        "dedup_strategy": DEDUP_STRATEGY,
        "confidence_merge_mode": CONFIDENCE_MERGE_MODE,
        "mitre_score_merge": MITRE_SCORE_MERGE,
        "validate_global_capabilities": VALIDATE_GLOBAL_CAPABILITIES,
        "validate_mitre_deduplication": VALIDATE_MITRE_DEDUPLICATION
    }


def validate_config() -> tuple[bool, list[str]]:
    """
    Validate configuration settings.
    
    Returns:
        (valid, errors) tuple
    """
    errors = []
    
    # Check confidence range
    if not 0.0 <= CAPA_CONFIDENCE <= 1.0:
        errors.append(f"CAPA_CONFIDENCE must be 0.0-1.0, got {CAPA_CONFIDENCE}")
    
    # Check timeout
    if CAPA_TIMEOUT <= 0:
        errors.append(f"CAPA_TIMEOUT must be positive, got {CAPA_TIMEOUT}")
    
    # Check dedup strategy
    valid_dedup = ["max_confidence", "first", "merge"]
    if DEDUP_STRATEGY not in valid_dedup:
        errors.append(f"DEDUP_STRATEGY must be one of {valid_dedup}, got {DEDUP_STRATEGY}")
    
    # Check MITRE merge strategy
    valid_merge = ["max", "sum", "average"]
    if MITRE_SCORE_MERGE not in valid_merge:
        errors.append(f"MITRE_SCORE_MERGE must be one of {valid_merge}, got {MITRE_SCORE_MERGE}")
    
    return len(errors) == 0, errors


# Validate on import
_valid, _errors = validate_config()
if not _valid:
    import warnings
    warnings.warn(f"CAPA config validation failed: {_errors}")
