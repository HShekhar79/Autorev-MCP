"""
test_capa_integration.py

Comprehensive test suite for CAPA integration and deduplication fixes.

Tests cover:
    1. CAPA engine functionality
    2. Capability deduplication
    3. MITRE fusion
    4. Backward compatibility
    5. Error handling
    6. Global consistency validation

Run with: python test_capa_integration.py
"""

import sys
import os
from typing import Dict, Any

# Test fixtures
MOCK_CAPA_JSON = {
    "rules": {
        "create process": {
            "meta": {
                "att&ck": [
                    {
                        "id": "T1059",
                        "tactic": "execution",
                        "technique": "Command and Scripting Interpreter"
                    }
                ]
            },
            "matches": {
                "0x401000": {"type": "match"}
            }
        },
        "process injection": {
            "meta": {
                "att&ck": [
                    {
                        "id": "T1055",
                        "tactic": "defense-evasion",
                        "technique": "Process Injection"
                    }
                ]
            },
            "matches": {
                "0x401500": {"type": "match"}
            }
        }
    }
}


def test_capa_parsing():
    """Test CAPA JSON parsing and normalization."""
    print("\n" + "="*80)
    print("TEST 1: CAPA JSON Parsing")
    print("="*80)
    
    # Import here to avoid errors if modules not in path
    sys.path.insert(0, '/home/claude')
    from capa_engine import parse_capa_results
    
    result = parse_capa_results(MOCK_CAPA_JSON)
    
    # Validate structure
    assert "capabilities" in result
    assert "normalized_capabilities" in result
    assert "function_capabilities" in result
    assert "capability_to_mitre" in result
    
    # Validate normalization
    assert len(result["normalized_capabilities"]) > 0
    
    for cap in result["normalized_capabilities"]:
        assert "name" in cap
        assert "source" in cap
        assert "confidence" in cap
        assert cap["source"] == "capa"
        assert 0.0 <= cap["confidence"] <= 1.0
    
    # Validate function mapping
    assert "0x401000" in result["function_capabilities"]
    assert "0x401500" in result["function_capabilities"]
    
    # Validate MITRE mapping
    assert "T1059" in result["mitre_techniques"]
    assert "T1055" in result["mitre_techniques"]
    
    print("✅ CAPA parsing successful")
    print(f"   Capabilities detected: {result['capabilities_detected']}")
    print(f"   MITRE techniques: {len(result['mitre_techniques'])}")
    print(f"   Function mappings: {len(result['function_capabilities'])}")
    
    return result


def test_capability_deduplication():
    """Test capability deduplication logic."""
    print("\n" + "="*80)
    print("TEST 2: Capability Deduplication")
    print("="*80)
    
    from capability_deduplication import deduplicate_capabilities
    
    # Test case: same capability from different sources
    behavior_caps = [
        {"name": "process_injection", "source": "behavior", "confidence": 0.7},
        {"name": "network_activity", "source": "behavior", "confidence": 0.8}
    ]
    
    capa_caps = [
        {"name": "process_injection", "source": "capa", "confidence": 0.9},
        {"name": "command_execution", "source": "capa", "confidence": 0.85}
    ]
    
    deduplicated = deduplicate_capabilities(behavior_caps, capa_caps)
    
    # Validate deduplication
    cap_names = [c["name"] for c in deduplicated]
    
    assert len(set(cap_names)) == len(cap_names), "Duplicate capabilities found!"
    assert "process_injection" in cap_names
    assert "network_activity" in cap_names
    assert "command_execution" in cap_names
    
    # Validate confidence merging (should take MAX)
    process_injection_cap = next(c for c in deduplicated if c["name"] == "process_injection")
    assert process_injection_cap["confidence"] == 0.9, "Should use MAX confidence"
    
    # Validate source tracking
    assert "behavior" in process_injection_cap["sources"]
    assert "capa" in process_injection_cap["sources"]
    
    print("✅ Deduplication successful")
    print(f"   Input: {len(behavior_caps) + len(capa_caps)} capabilities")
    print(f"   Output: {len(deduplicated)} capabilities (deduplicated)")
    print(f"   Merged: process_injection from multiple sources")
    
    return deduplicated


def test_mitre_fusion():
    """Test MITRE technique fusion and deduplication."""
    print("\n" + "="*80)
    print("TEST 3: MITRE Fusion")
    print("="*80)
    
    from fusion_engine import merge_mitre_results, validate_mitre_deduplication
    
    # Mock behavior MITRE
    behavior_mitre = {
        "mitre_techniques": ["T1059", "T1071"],
        "tactics": {
            "execution": ["T1059"],
            "command_and_control": ["T1071"]
        }
    }
    
    # Mock capability MITRE
    capability_mitre = {
        "mitre_techniques": ["T1059", "T1055"],  # T1059 is duplicate
        "scores": {
            "T1059": 2.5,
            "T1055": 3.0
        }
    }
    
    # Merge
    fusion = merge_mitre_results(behavior_mitre, capability_mitre)
    
    # Validate structure
    assert "mitre_techniques" in fusion
    assert "scores" in fusion
    assert "sources" in fusion
    
    # Validate deduplication
    techniques = fusion["mitre_techniques"]
    assert len(set(techniques)) == len(techniques), "Duplicate MITRE IDs found!"
    
    # Validate that T1059 appears only once
    assert techniques.count("T1059") == 1
    
    # Validate score merging (should use MAX, not SUM)
    assert fusion["scores"]["T1059"] == 2.5  # MAX(1.5 from behavior, 2.5 from capability)
    assert fusion["scores"]["T1055"] == 3.0
    assert fusion["scores"]["T1071"] == 1.5  # Only from behavior
    
    # Validate source tracking
    assert "behavior" in fusion["sources"]["T1059"]
    assert "capability" in fusion["sources"]["T1059"]
    assert "behavior" in fusion["sources"]["T1071"]
    assert "capability" in fusion["sources"]["T1055"]
    
    # Run validation
    validation = validate_mitre_deduplication(fusion)
    assert validation["valid"], "MITRE deduplication failed!"
    assert validation["duplicate_count"] == 0
    
    print("✅ MITRE fusion successful")
    print(f"   Total techniques: {fusion['total_techniques']}")
    print(f"   No duplicates: {validation['valid']}")
    print(f"   Score merging: MAX strategy (no inflation)")
    
    return fusion


def test_empty_cases():
    """Test handling of empty inputs."""
    print("\n" + "="*80)
    print("TEST 4: Empty Case Handling")
    print("="*80)
    
    from capability_deduplication import deduplicate_capabilities
    from fusion_engine import merge_mitre_results
    
    # Test empty deduplication
    empty_dedup = deduplicate_capabilities([], [])
    assert isinstance(empty_dedup, list)
    assert len(empty_dedup) == 0
    print("✅ Empty deduplication handled")
    
    # Test empty fusion
    empty_fusion = merge_mitre_results({}, {})
    assert isinstance(empty_fusion, dict)
    assert empty_fusion["total_techniques"] == 0
    assert len(empty_fusion["mitre_techniques"]) == 0
    print("✅ Empty fusion handled")
    
    # Test None inputs
    none_fusion = merge_mitre_results(None, None)
    assert isinstance(none_fusion, dict)
    assert none_fusion["total_techniques"] == 0
    print("✅ None inputs handled")
    
    return True


def test_backward_compatibility():
    """Test backward compatibility with existing output formats."""
    print("\n" + "="*80)
    print("TEST 5: Backward Compatibility")
    print("="*80)
    
    from capa_engine import parse_capa_results
    from fusion_engine import merge_mitre_results
    
    # Parse CAPA results
    capa_result = parse_capa_results(MOCK_CAPA_JSON)
    
    # Check legacy fields are present
    assert "behaviour_to_mitre" in capa_result, "Legacy field missing!"
    assert "capability_to_mitre" in capa_result, "New field missing!"
    
    # Check that both contain same data
    assert capa_result["behaviour_to_mitre"] == capa_result["capability_to_mitre"]
    
    print("✅ Legacy 'behaviour_to_mitre' field preserved")
    print("✅ New 'capability_to_mitre' field added")
    
    # Check fusion backward compatibility
    fusion = merge_mitre_results(
        {"mitre_techniques": ["T1059"]},
        {"scores": {"T1055": 2.0}}
    )
    
    assert "mitre_techniques" in fusion
    assert "final_mitre" in fusion  # alias
    assert "tactics" in fusion
    assert "scores" in fusion
    
    print("✅ Fusion output structure preserved")
    
    return True


def test_global_consistency_validation():
    """Test global capability consistency validation."""
    print("\n" + "="*80)
    print("TEST 6: Global Consistency Validation")
    print("="*80)
    
    from capability_deduplication import validate_global_capabilities
    
    # Mock function results
    functions = [
        {
            "function_name": "fcn.00401000",
            "capabilities": [
                {"name": "process_injection"},
                {"name": "network_activity"}
            ]
        },
        {
            "function_name": "fcn.00401500",
            "capabilities": [
                {"name": "command_execution"}
            ]
        }
    ]
    
    # Test valid case
    global_caps = ["process_injection", "network_activity", "command_execution"]
    validation = validate_global_capabilities(functions, global_caps)
    
    assert validation["valid"], "Valid case marked as invalid!"
    assert len(validation["missing_in_global"]) == 0
    assert len(validation["extra_in_global"]) == 0
    
    print("✅ Valid consistency detected")
    
    # Test drift case
    global_caps_drift = ["process_injection", "network_activity"]  # missing command_execution
    validation_drift = validate_global_capabilities(functions, global_caps_drift)
    
    assert not validation_drift["valid"], "Drift not detected!"
    assert "command_execution" in validation_drift["missing_in_global"]
    
    print("✅ Drift detection working")
    print(f"   Missing in global: {validation_drift['missing_in_global']}")
    
    return True


def test_capa_status_degraded():
    """Test degraded mode when CAPA rules not found."""
    print("\n" + "="*80)
    print("TEST 7: CAPA Degraded Mode")
    print("="*80)
    
    from capa_engine import get_capa_status_summary
    
    # Mock degraded result
    degraded_result = {
        "status": "degraded",
        "reason": "rules_not_found",
        "detail": "CAPA rules not found at ./capa-rules",
        "capabilities_detected": 0,
        "capabilities": [],
        "normalized_capabilities": []
    }
    
    status = get_capa_status_summary(degraded_result)
    
    assert status["enabled"] == True  # Degraded still counts as "enabled" attempt
    assert status["status"] == "degraded"
    assert status["capabilities_found"] == 0
    
    print("✅ Degraded mode handled correctly")
    print(f"   Status: {status['status']}")
    print(f"   Message: {status['message']}")
    
    return True


def run_all_tests():
    """Run complete test suite."""
    print("\n" + "#"*80)
    print("# CAPA INTEGRATION TEST SUITE")
    print("#"*80)
    
    tests = [
        ("CAPA Parsing", test_capa_parsing),
        ("Capability Deduplication", test_capability_deduplication),
        ("MITRE Fusion", test_mitre_fusion),
        ("Empty Cases", test_empty_cases),
        ("Backward Compatibility", test_backward_compatibility),
        ("Global Consistency", test_global_consistency_validation),
        ("Degraded Mode", test_capa_status_degraded)
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"\n❌ TEST FAILED: {test_name}")
            print(f"   Error: {str(e)}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "#"*80)
    print(f"# TEST RESULTS: {passed} passed, {failed} failed")
    print("#"*80)
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED! CAPA integration is working correctly.")
    else:
        print(f"\n⚠️  {failed} tests failed. Please review errors above.")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
