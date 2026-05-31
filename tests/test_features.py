import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detector.features import extract_features, _is_ip
from detector.scorer import calculate_score, get_risk_level


def test_ip_detection():
    assert _is_ip("192.168.0.1") is True
    assert _is_ip("google.com") is False


def test_safe_url():
    score, _, _ = calculate_score("https://www.google.com")
    assert score < 40, f"안전한 URL 점수가 너무 높음: {score}"


def test_phishing_url():
    score, _, _ = calculate_score("http://192.168.1.1/login/verify/account?update=true")
    assert score >= 40, f"피싱 URL 점수가 너무 낮음: {score}"


def test_risk_levels():
    assert get_risk_level(80)[0] == "위험"
    assert get_risk_level(50)[0] == "주의"
    assert get_risk_level(20)[0] == "안전"


def test_https_bonus():
    score_http, _, _ = calculate_score("http://example.com")
    score_https, _, _ = calculate_score("https://example.com")
    assert score_https <= score_http


if __name__ == "__main__":
    test_ip_detection()
    test_safe_url()
    test_phishing_url()
    test_risk_levels()
    test_https_bonus()
    print("모든 테스트 통과")
