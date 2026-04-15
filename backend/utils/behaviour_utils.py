from utils.normalization import normalize_behavior


def normalize_behaviours(behaviours, source="unknown"):
    normalized = []

    for b in behaviours:

        # Case 1: string
        if isinstance(b, str):
            name = normalize_behavior(b)

            if not name:
                continue

            normalized.append({
                "name": name,
                "source": source.lower(),
                "confidence": 0.6
            })

        # Case 2: dict
        elif isinstance(b, dict):
            raw_name = b.get("name") or b.get("behavior") or b.get("behaviour")

            name = normalize_behavior(raw_name)

            if not name:
                continue

            try:
                confidence = float(b.get("confidence", 0.6))
            except Exception:
                confidence = 0.6

            normalized.append({
                "name": name,
                "source": str(b.get("source", source)).lower(),
                "confidence": confidence
            })

    return normalized


def deduplicate_behaviours(behaviours):
    unique = {}

    for b in behaviours:
        name = normalize_behavior(b.get("name"))

        if not name:
            continue

        if name not in unique or b.get("confidence", 0) > unique[name].get("confidence", 0):
            unique[name] = b

    return list(unique.values())


def deduplicate_behaviours(behaviours):
    unique = {}

    for b in behaviours:
        name = b.get("name")

        if not name:
            continue

        if name not in unique or b.get("confidence", 0) > unique[name].get("confidence", 0):
            unique[name] = b

    return list(unique.values())