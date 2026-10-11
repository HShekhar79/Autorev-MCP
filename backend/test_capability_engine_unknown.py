from capability_engine import CapabilityEngine

def test_unknown_external_activity_not_mapped():
    e = CapabilityEngine()
    assert "unknown_external_activity" not in e.mapping
    for inp in (["unknown_external_activity"],
                [{"name": "unknown_external_activity", "confidence": 0.9}],
                {"behaviors": ["unknown_external_activity"], "_detail": []}):
        assert e.run(inp) == {"capabilities": [], "scores": {}}

def test_known_behavior_still_maps():
    out = CapabilityEngine().run(["command_execution"])
    assert out == {"capabilities": ["execution"], "scores": {"execution": 1.6}}

def test_unknown_alongside_known_adds_nothing():
    out = CapabilityEngine().run(["unknown_external_activity", "command_execution"])
    assert out == CapabilityEngine().run(["command_execution"])
