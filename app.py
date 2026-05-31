import streamlit as st
from detector.scorer import calculate_score, get_risk_level

st.set_page_config(page_title="Phishing URL Detector", page_icon="🔍", layout="centered")

st.title("🔍 Phishing URL Detector")
st.markdown("URL을 입력하면 피싱 위험도를 분석합니다.")

url_input = st.text_input("분석할 URL을 입력하세요", placeholder="https://example.com")

if st.button("분석하기", type="primary"):
    if not url_input.strip():
        st.warning("URL을 입력해주세요.")
    else:
        url = url_input.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        score, breakdown, features = calculate_score(url)
        risk_level, color = get_risk_level(score)

        st.markdown("---")

        col1, col2 = st.columns([1, 2])
        with col1:
            st.metric("위험도 점수", f"{score} / 100")
            st.markdown(f"### <span style='color:{color}'>{risk_level}</span>", unsafe_allow_html=True)
        with col2:
            st.progress(score / 100)

        st.markdown("#### 탐지된 위험 요소")
        risk_items = {k: v for k, v in breakdown.items() if v > 0}

        LABEL = {
            "url_length":          "URL 길이 과다 (75자 이상)",
            "has_ip":              "IP 주소 직접 사용",
            "has_https":           "HTTPS 미사용",
            "dot_count":           "점(.) 과다 사용",
            "hyphen_count":        "하이픈(-) 과다 사용",
            "at_symbol":           "@ 기호 포함",
            "double_slash":        "이중 슬래시(//) 포함",
            "subdomain_count":     "서브도메인 과다",
            "suspicious_keywords": "의심 키워드 포함",
            "is_shortened":        "URL 단축 서비스 사용",
            "special_char_count":  "특수문자 과다",
            "digit_in_domain":     "도메인에 숫자 포함",
        }

        if risk_items:
            for key, pts in risk_items.items():
                st.markdown(f"- ⚠️ **{LABEL.get(key, key)}** (+{pts}점)")
        else:
            st.success("위험 요소가 탐지되지 않았습니다.")

        with st.expander("상세 특징값 보기"):
            st.json(features)
