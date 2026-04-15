"""
engines/capability_deduplication.py

Capability deduplication and merging layer.

This module prevents capability duplication when combining results from:
    - Behavior engine
    - CAPA engine
    - Function-level detections

CRITICAL FUNCTION: deduplicate_capabilities()
Called BEFORE MITRE mapping to ensure clean, merged capability list.

Merging strategy:
    1. Normalize all capability names
    2. Group by canonical name
    3. Merge confidence scores (take MAX)
    4. Preserve source attribution
    5. Return deduplicated list
"""

from typing import List, Dict, Any
from utils.normalization import normalize_behavior
from utils.debug import debug_log


def deduplicate_capabilities(
    behavior_capabilities: List[Dict[str, Any]],
    capa_capabilities: List[Dict[str, Any]],
    function_capabilities: List[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Merge and deduplicate capabilities from multiple sources.
    
    Expected input format for each capability:
        {
            "name": str,           # Raw or normalized capability name
            "source": str,         # "behavior", "capa", "function", etc.
            "confidence": float    # 0.0-1.0
        }
    
    Args:
        behavior_capabilities: Capabilities from behavior engine
        capa_capabilities: Capabilities from CAPA
        function_capabilities: Additional function-level capabilities (optional)
        
    Returns:
        Deduplicated list of capabilities with merged confidence scores
        
    Example:
        Input:
            behavior: [{"name": "process_injection", "source": "behavior", "confidence": 0.8}]
            capa:     [{"name": "process_injection", "source": "capa", "confidence": 0.9}]
        
        Output:
            [{"name": "process_injection", "sources": ["behavior", "capa"], "confidence": 0.9}]
    """
    
    # Initialize capability map: {canonical_name: {sources: set, max_confidence: float}}
    capability_map: Dict[str, Dict[str, Any]] = {}
    
    # Combine all capability sources
    all_capabilities = []
    
    if behavior_capabilities:
        all_capabilities.extend(behavior_capabilities)
    
    if capa_capabilities:
        all_capabilities.extend(capa_capabilities)
    
    if function_capabilities:
        all_capabilities.extend(function_capabilities)
    
    # Process each capability
    for cap in all_capabilities:
        if not isinstance(cap, dict):
            continue
        
        # Extract fields
        raw_name = cap.get("name", "")
        source = cap.get("source", "unknown")
        confidence = float(cap.get("confidence", 0.8))
        
        # Normalize capability name
        canonical = normalize_behavior(raw_name)
        
        if not canonical:
            debug_log("[DEDUP] Invalid capability name", raw_name)
            continue
        
        # Merge into capability map
        if canonical not in capability_map:
            capability_map[canonical] = {
                "sources": set(),
                "max_confidence": 0.0
            }
        
        capability_map[canonical]["sources"].add(source)
        capability_map[canonical]["max_confidence"] = max(
            capability_map[canonical]["max_confidence"],
            confidence
        )
    
    # Build deduplicated output
    deduplicated = []
    
    for canonical_name, data in capability_map.items():
        deduplicated.append({
            "name": canonical_name,
            "sources": sorted(list(data["sources"])),
            "confidence": round(data["max_confidence"], 2)
        })
    
    # Sort by confidence (descending), then alphabetically
    deduplicated.sort(key=lambda x: (-x["confidence"], x["name"]))
    
    debug_log("[DEDUP] Input count", {
        "behavior": len(behavior_capabilities or []),
        "capa": len(capa_capabilities or []),
        "function": len(function_capabilities or [])
    })
    
    debug_log("[DEDUP] Output count", len(deduplicated))
    debug_log("[DEDUP] Deduplicated capabilities", deduplicated)
    
    return deduplicated


def validate_global_capabilities(
    function_results: List[Dict[str, Any]],
    global_capabilities: List[str]
) -> Dict[str, Any]:
    """
    Validate that global_capabilities equals union of all function capabilities.
    
    This prevents drift between function-level and global-level capability lists.
    
    Args:
        function_results: List of function analysis results
        global_capabilities: Global capability list to validate
        
    Returns:
        {
            "valid": bool,
            "function_caps": set,
            "global_caps": set,
            "missing_in_global": list,
            "extra_in_global": list
        }
    """
    # Extract all capabilities from functions
    function_caps = set()
    
    for func in function_results:
        # Extract from capabilities field
        caps = func.get("capabilities", [])
        for cap in caps:
            if isinstance(cap, dict):
                name = cap.get("name")
                if name:
                    function_caps.add(name)
            elif isinstance(cap, str):
                function_caps.add(cap)
    
    # Convert global to set
    global_caps = set(global_capabilities)
    
    # Check consistency
    missing_in_global = function_caps - global_caps
    extra_in_global = global_caps - function_caps
    
    valid = len(missing_in_global) == 0 and len(extra_in_global) == 0
    
    result = {
        "valid": valid,
        "function_caps": function_caps,
        "global_caps": global_caps,
        "missing_in_global": sorted(list(missing_in_global)),
        "extra_in_global": sorted(list(extra_in_global))
    }
    
    if not valid:
        debug_log("[VALIDATION] Global capabilities drift detected", result)
    
    return result


def merge_function_capabilities_with_capa(
    function_results: List[Dict[str, Any]],
    capa_function_capabilities: Dict[str, List[str]]
) -> List[Dict[str, Any]]:
    """
    Merge CAPA function-level capabilities into function analysis results.
    
    Args:
        function_results: List of function dicts from function_analysis_engine
        capa_function_capabilities: Dict mapping function address -> capability list
        
    Returns:
        Updated function_results with CAPA capabilities merged
    """
    # Create address-to-function mapping
    function_map = {}
    
    for func in function_results:
        func_name = func.get("function_name", "")
        
        # Try to extract address from function name
        # Common formats: "fcn.00401000", "sub.00401000", "0x401000"
        addr = None
        
        if func_name.startswith("fcn."):
            addr = "0x" + func_name[4:]
        elif func_name.startswith("sub."):
            addr = "0x" + func_name[4:]
        elif func_name.startswith("0x"):
            addr = func_name
        
        if addr:
            function_map[addr] = func
    
    # Merge CAPA capabilities
    for addr, capa_caps in capa_function_capabilities.items():
        if addr not in function_map:
            continue
        
        func = function_map[addr]
        
        # Get existing capabilities
        existing = func.get("capabilities", [])
        existing_names = set()
        
        for cap in existing:
            if isinstance(cap, dict):
                existing_names.add(cap.get("name"))
        
        # Add new CAPA capabilities
        new_capabilities = []
        
        for capa_cap in capa_caps:
            canonical = normalize_behavior(capa_cap)
            if canonical and canonical not in existing_names:
                new_capabilities.append({
                    "name": canonical,
                    "mitre": None,  # Will be filled by MITRE engine
                    "source": "capa"
                })
                existing_names.add(canonical)
        
        # Extend capabilities list
        if new_capabilities:
            func["capabilities"] = existing + new_capabilities
            debug_log(f"[CAPA MERGE] Function {func['function_name']}", {
                "added": [c["name"] for c in new_capabilities]
            })
    
    return function_results
