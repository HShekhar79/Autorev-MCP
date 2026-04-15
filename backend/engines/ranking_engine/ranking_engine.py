def rank_suspicious_functions(function_results, top_n=10):

    if not function_results or not isinstance(function_results, list):
        if not results:
            return [{
                "rank": 0,
                "function_name": "no_suspicious_function",
                "risk_score": 0,
                "behaviour": [],
                "calls": [],
                "note": "No suspicious functions detected"
            }]

    ranked_candidates = []

    for func in function_results:

        if not isinstance(func, dict):
            continue

        risk = func.get("risk_score", 0)

        behaviours = (
            func.get("behaviors")
            or func.get("behaviour")
            or func.get("behavior")
            or []
        )

        calls = func.get("calls", [])

        behaviour_count = len(behaviours) if behaviours else 0
        call_count = len(calls) if calls else 0

        ranking_score = risk + (behaviour_count * 5) + (call_count * 1)

        fname = func.get("function_name") or "unknown_function"

        ranked_candidates.append({
            "function_name": fname,
            "risk_score": risk,
            "behaviour": behaviours,
            "calls": calls,
            "ranking_score": ranking_score
        })

    ranked_candidates.sort(
        key=lambda x: x["ranking_score"],
        reverse=True
    )

    results = []

    for i, func in enumerate(ranked_candidates[:top_n]):

        results.append({
            "rank": i + 1,
            "function_name": func["function_name"],
            "risk_score": func["risk_score"],
            "behaviour": func["behaviour"],
            "calls": func["calls"]
        })

    return results