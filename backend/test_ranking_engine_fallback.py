from engines.ranking_engine.ranking_engine import rank_suspicious_functions as r

def test_empty_fallback():
    for bad in ([], None, "x", {}):
        out = r(bad)
        assert len(out) == 1
        assert out[0] == {"rank": 0, "function_name": "no_suspicious_function",
                          "risk_score": 0, "behaviour": [], "calls": [],
                          "note": "No suspicious functions detected"}

def test_normal_ranking_preserved():
    data = [
        {"function_name": "a", "risk_score": 10, "behaviors": ["x"], "calls": ["c1", "c2"]},   # 10+5+2=17
        {"function_name": "b", "risk_score": 5, "behaviour": ["x", "y"], "calls": []},         # 5+10+0=15
        {"function_name": "c", "risk_score": 1, "behavior": ["x", "y", "z"], "calls": ["q"]},  # 1+15+1=17
        {"function_name": "d", "risk_score": 30},                                              # 30
    ]
    out = r(data)
    assert [f["function_name"] for f in out] == ["d", "a", "c", "b"]  # stable tie a before c
    assert [f["rank"] for f in out] == [1, 2, 3, 4]
    assert out[1]["behaviour"] == ["x"] and out[2]["behaviour"] == ["x", "y", "z"]
    assert "note" not in out[0] and "ranking_score" not in out[0]
    assert len(r(data, top_n=2)) == 2
