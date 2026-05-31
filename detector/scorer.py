from .features import extract_features

WEIGHTS = {
    "url_length":          {"threshold": 75, "score": 10},
    "has_ip":              {"score": 25},
    "has_https":           {"score": -10},   # 음수 = 안전 신호
    "dot_count":           {"threshold": 4,  "score": 8},
    "hyphen_count":        {"threshold": 2,  "score": 8},
    "at_symbol":           {"score": 20},
    "double_slash":        {"score": 15},
    "subdomain_count":     {"threshold": 2,  "score": 10},
    "suspicious_keywords": {"threshold": 1,  "score": 15},
    "is_shortened":        {"score": 12},
    "special_char_count":  {"threshold": 3,  "score": 8},
    "digit_in_domain":     {"threshold": 2,  "score": 5},
}


def calculate_score(url: str) -> tuple[int, dict, dict]:
    features = extract_features(url)
    total = 0
    breakdown = {}

    for key, rule in WEIGHTS.items():
        value = features.get(key, 0)
        threshold = rule.get("threshold")
        weight = rule["score"]

        if threshold is not None:
            triggered = value >= threshold
        else:
            triggered = bool(value)

        if triggered:
            total += weight
            breakdown[key] = weight
        else:
            breakdown[key] = 0

    score = max(0, min(100, total))
    return score, breakdown, features


def get_risk_level(score: int) -> tuple[str, str]:
    if score >= 70:
        return "위험", "#e74c3c"
    elif score >= 40:
        return "주의", "#f39c12"
    else:
        return "안전", "#27ae60"
